# Architecture specific utility functions
import os
import gtirb
import logging
from typing import Optional

from .utils import run_cmd, check_executables_exist
from . import DUMMY_LIB_NAME

log = logging.getLogger(__name__)

class ArchUtils:
    @staticmethod
    def backup_registers(label: str) -> str:
        '''
        Generate asm for backing up registers to given label
        :param label: Label to backup registers to.
        :return: Intel-formatted assembly
        '''
        raise NotImplementedError

    @staticmethod
    def restore_registers(label: str) -> str:
        '''
        Generate asm for restoring registers to given label
        :param label: Label to backup registers to.
        :return: Intel-formatted assembly
        '''
        raise NotImplementedError

    @staticmethod
    def call_function(func: str,
                      save_stack: Optional[int]=0,
                      pre_call: Optional[str]='',
                      post_call: Optional[str]='') -> str:
        '''
        Generate asm calling function
        :param func: Name of function to call.
        :param save_stack: Number of bytes of stack above the stack pointer to
            save before running function call (some ISAs require this)
        :param pre_call: assembly to insert immediately prior to call
        :param post_call: assembly to insert immediately post to call
        :return: Intel-formatted assembly
        '''
        raise NotImplementedError

    @staticmethod
    def generate(ir_file: str, output: str, working_dir: str, *args,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False, 
                 obj_link: Optional[list[str]]=None, **kwargs):
        """
        Generate binary or assembly from instrumented IR.

        :param ir_file: File location of GTIRB IR to generate from
        :param output: File location of output assembly and/or binary. '.exe'
            will be added for output binary and '.S' for assembly.
        :param working_dir: Local working directory to generate intermediary
            files
        :param gen_assembly: True if generating assembly
        :param gen_binary: True if generating binary
        :param obj_link: paths of additional objects / libraries to link
        """
        # The following is a stub that calls gtirb-pprinter on the IR directly.
        # No support for linking in static objects or any changes to default
        # gtirb-pprinter binary generation.
        assert gen_assembly or gen_binary, \
            "One of gen_assembly or gen_binary must be true"

        if obj_link != None:
            raise NotImplementedError

        basename = os.path.basename(output)
        asm_path = os.path.join(working_dir, f'{basename}.S')
        bin_path = os.path.join(working_dir, f'{basename}.exe')

        assert check_executables_exist(['gtirb-pprinter']), "gtirb-pprinter not found"

        gen_args = []
        if gen_assembly:
            gen_args += ['--asm', asm_path]
        if gen_binary:
            gen_args += ['--binary', bin_path]

        cmd = ["gtirb-pprinter", ir_file] + gen_args
        run_cmd(cmd)

        if gen_assembly:
            log.info(f'Generated assembly saved to: {asm_path}')
        if gen_binary:
            log.info(f'Generated binary saved to: {bin_path}')

class WindowsUtils(ArchUtils):
    @staticmethod
    def generate_def_file(ir: gtirb.IR, out_folder: str,
                        ignore_dlls: Optional[list[str]]=None) -> dict[str, str]:
        """
        Generate '.def' file for lib.exe to use to generate a '.lib' file declaring
        functions from external dlls used in IR. The generated lib file is used
        when linking the pretty printed assembly to these dlls.

        Output files will be generated to: {out_folder}/{dllname}.def
            e.g. for KERNEL32.dll: {out_folder}/KERNEL32.dll.def

        :param ir: GTIRB IR being def file being generated for
        :param out_folder: Path of output folder.
        :param filter_dlls: Names of dlls to ignore generating def files for
        :returns: mapping of dll names to their generated def files
        """
        if not ignore_dlls:
            ignore_dlls = []

        exports = {}
        for module in ir.modules:
            for _, _, func_name, lib in module.aux_data['peImportEntries'].data:
                if lib not in ignore_dlls:
                    if lib not in exports:
                        exports[lib] = []
                    exports[lib].append(func_name)

        def_file_mappings = {}

        for lib in exports:
            out_fname = f'{os.path.join(out_folder, lib)}.def'
            def_file_mappings[lib] = out_fname

            with open(out_fname, 'w') as f:
                f.write(f'LIBRARY "{lib}"\n\nEXPORTS\n')
                for func in exports[lib]:
                    f.write(f'    {func}\n')

            log.info(f"Generated DEF file for {lib} at: {out_fname}")

        return def_file_mappings

    @staticmethod
    def generate(ir_file: str, output: str, working_dir: str, ir: gtirb.IR,
                    gen_assembly: Optional[bool]=False,
                    gen_binary: Optional[bool]=False,
                    obj_link: Optional[list[str]]=None):
        """
        Generate assembly code or binary using gtirb-pprinter locally. At least one
        of gen_assembly or gen_binary must be true. MSVC must be installed and
        accessible and targeting right architecture.
        
        We use our own build process as gtirb-pprinter's PE binary printing doesn't
        allow us to link our own static libraries into the generated binary.

        :param ir_file: File location of GTIRB IR to generate from
        :param ir: GTIRB IR being printed (loaded version of ir_file)
        :param output: File location of output assembly and/or binary. '.exe' will
            be added for output binary and '.S' for assembly.
        :param working_dir: Local working directory to generate intermediary files
        :param gen_assembly: True if generating assembly
        :param gen_binary: True if generating binary
        :param obj_link: Path of object to link into instrumented binary.
        """
        assert gen_assembly or gen_binary, \
            "At least one of gen_assembly or gen_binary must be true"

        basename = os.path.basename(output)

        # Generate assembly (required for binary generation as well)
        assert check_executables_exist(['gtirb-pprinter']), "gtirb-pprinter not found"
        asm_fname = f'{output}.S' if gen_assembly else os.path.join(working_dir, f'{basename}.S')
        cmd = ["gtirb-pprinter", ir_file, '--asm', asm_fname]
        run_cmd(cmd)
        log.info(f'Generated assembly saved to: {asm_fname}')

        # Generate def files to use for linking dlls in final binary
        def_files = WindowsUtils.generate_def_file(ir, working_dir, ignore_dlls=[DUMMY_LIB_NAME])

        # Modify ASM to link to our lib files.
        # The default name gtirb-pprinter for the lib files is the dll name + lib,
        # which is encoded in the generated assembly.
        # e.g. for Kernel32.dll the gtirb-generated generated lib file would be
        # KERNEL32.LIB.
        # This causes conflicts with the actual Kernel32.lib which we need to use
        # to link most static libraries. So we name our lib files something
        # different (e.g. we rename Kernel32.dll to Kernel32.dll.lib) to avoid this. 
        # Below, we modify the gtirb-generated assembly to use our naming scheme.
        asm = None
        with open(asm_fname, 'r') as f:
            asm = f.read()
        for dll in def_files:
            #  generate gtirb-pprinter's name for a lib
            gtirb_lib_name = dll
            if dll.endswith('.dll'):
                gtirb_lib_name = dll[:-4]+'.lib'
            #  generate our own name
            new_lib_name = f'{dll}.lib'
            new_includelib_line= f'INCLUDELIB {new_lib_name}'
            old_includelib_line = f'INCLUDELIB {gtirb_lib_name}'
            #  replace reference in asm with our new name.
            asm = asm.replace(old_includelib_line, new_includelib_line)
        # Remove dummy library include. Symbols 'used' by dummy library will be
        # fullfilled by static library we later link. Dummy library included as
        # gtirb doesn't allow referencing symbols unless we define the dll they
        # come from, which it attempts to import while binary pretty printing.
        dummy_lib_include = f'INCLUDELIB {DUMMY_LIB_NAME}\n'
        asm = asm.replace(dummy_lib_include, '')
        # Write back modified ASM
        with open(asm_fname, 'w') as f:
            f.write(asm)

        if gen_assembly:
            return

        # Check MSVC build tools accessible and right architecture
        is_64bit = ir.modules[0] == gtirb.Module.ISA.X64
        assert check_executables_exist(['cl']), \
            "MSVC build tools not found, are you running in a developer command prompt?"
        cl_out, _ = run_cmd(["cl"], print=False)
        if is_64bit:
            assert b"for x64" in cl_out, \
                "64-bit MSVC build tools must be used to generate 64-bit instrumented binary"
        else:
            assert b"for x86" in cl_out, \
                "32-bit MSVC build tools must be used to generate 32-bit instrumented binary"
        log.info(f"{'64-bit' if is_64bit else '32-bit'} MSVC build tools found.")

        # Generate lib files from def files
        for dll in def_files:
            def_file = def_files[dll]
            lib_file = os.path.join(working_dir, f'{dll}.lib')
            cmd = ['lib', r'/nologo', fr'/def:{def_file}', fr'/out:{lib_file}',
                r'/MACHINE:X86']
            run_cmd(cmd)

        # Generate object from instrumented assembly
        obj_name = f'{basename}.obj'
        obj_path = os.path.join(working_dir, obj_name)
        cmd = ["ml", r'/nologo', r'/c', fr'/Fo{obj_path}', f'{asm_fname}']
        run_cmd(cmd)

        # Generate executable, linking in files if needed
        binary_name = f'{basename}.exe'
        binary_path = os.path.join(working_dir, f'{basename}.exe')
        cmd = ["cl", r'/nologo', f'{obj_name}', fr'/Fe{binary_name}', r'/link'] + obj_link + [r'/ENTRY:_EntryPoint', r'/SUBSYSTEM:console']
        run_cmd(cmd, working_dir=working_dir)

        log.info(f'Generated binary saved to: {binary_path}')

class WindowsX86Utils(WindowsUtils):
    @staticmethod
    def backup_registers(label: str) -> str:
        return f'''
            mov    DWORD PTR [{label}], eax
            mov    DWORD PTR [{label} + 0x4], ebx
            mov    DWORD PTR [{label} + 0x8], ecx
            mov    DWORD PTR [{label} + 0xC], edx
            mov    DWORD PTR [{label} + 0x10], edi
            mov    DWORD PTR [{label} + 0x14], esi
            movaps XMMWORD PTR [{label} + 0x20], xmm0
            movaps XMMWORD PTR [{label} + 0x30], xmm1
            movaps XMMWORD PTR [{label} + 0x40], xmm2
            movaps XMMWORD PTR [{label} + 0x50], xmm3
            movaps XMMWORD PTR [{label} + 0x60], xmm4
            movaps XMMWORD PTR [{label} + 0x70], xmm5
            movaps XMMWORD PTR [{label} + 0x80], xmm6
            movaps XMMWORD PTR [{label} + 0x90], xmm7
        '''

    @staticmethod
    def restore_registers(label: str) -> str:
        return f'''
            mov    eax,  DWORD PTR [{label}]
            mov    ebx,  DWORD PTR [{label} + 0x4]
            mov    ecx,  DWORD PTR [{label} + 0x8]
            mov    edx,  DWORD PTR [{label} + 0xC]
            mov    edi,  DWORD PTR [{label} + 0x10]
            mov    esi,  DWORD PTR [{label} + 0x14]
            movaps xmm0, XMMWORD PTR [{label} + 0x20]
            movaps xmm1, XMMWORD PTR [{label} + 0x30]
            movaps xmm2, XMMWORD PTR [{label} + 0x40]
            movaps xmm3, XMMWORD PTR [{label} + 0x50]
            movaps xmm4, XMMWORD PTR [{label} + 0x60]
            movaps xmm5, XMMWORD PTR [{label} + 0x70]
            movaps xmm6, XMMWORD PTR [{label} + 0x80]
            movaps xmm7, XMMWORD PTR [{label} + 0x90]
        '''

    @staticmethod
    def call_function(func: str,
                      save_stack: Optional[int]=0,
                      pre_call: Optional[str]='',
                      post_call: Optional[str]='') -> str:

        return f'''
            sub     esp, {hex(save_stack)}
            pushfd 
            push    eax
            push    ecx
            push    edx
            push    ebx
            push    ebp
            push    esi
            push    edi

            {pre_call}
            call    {func}
            {post_call}

            pop     edi
            pop     esi
            pop     ebp
            pop     ebx
            pop     edx
            pop     ecx
            pop     eax
            popfd
            add     esp, {hex(save_stack)}
        '''