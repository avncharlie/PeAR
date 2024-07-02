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

    def asm_fix_lib_names(asm: str, def_files: dict[str, str]) -> str:
        '''
        Modify GTIRB generated assembly to link to our lib files.
        The default name gtirb-pprinter for the lib files is the dll name + lib,
        which is encoded in the generated assembly.
        e.g. for Kernel32.dll the gtirb-generated generated lib file would be
        KERNEL32.LIB.
        This causes conflicts with the actual Kernel32.lib which we need to use
        to link most static libraries. So we name our lib files something
        different (e.g. we rename Kernel32.dll to Kernel32.dll.lib) to avoid
        this.  Below, we modify the gtirb-generated assembly to use our naming
        scheme.

        :param asm: assembly to fix
        :param def_files: mapping of dll names to their generated def files
        :returns: fixed assembly
        '''
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
        return asm

    def asm_fix_func_name_collisions(asm: str, names: list[str]) -> str:
        '''
        Ignore keywords that conflict with names of functions.
        Unfortunately the only way I see to do this is disabling the keyword.
        So programs that have name collisions and also use the keyword won't
        assemble.
        
        :param asm: assembly to fix
        :param names: names of conflicting functions
        :returns: fixed assembly
        '''
        ignore_keywords = ''
        for name in names:
            if f"call {name}" in asm or f"EXTERN {name}:PROC" in asm :
                ignore_keywords += f"option nokeyword: <{name}>\n"
        return ignore_keywords + asm

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

        is_64bit = ir.modules[0].isa == gtirb.Module.ISA.X64
        basename = os.path.basename(output)

        # Generate assembly (required for binary generation as well)
        assert check_executables_exist(['gtirb-pprinter']), "gtirb-pprinter not found"
        asm_fname = f'{output}.S' if gen_assembly else os.path.join(working_dir, f'{basename}.S')
        cmd = ["gtirb-pprinter", ir_file, '--asm', asm_fname]
        run_cmd(cmd)
        log.info(f'Generated assembly saved to: {asm_fname}')

        # Apply modifications to assembly
        asm = None
        with open(asm_fname, 'r') as f:
            asm = f.read()
        assert asm != None

        # Generate def files to use for linking dlls in final binary and link 
        # into assembly
        def_files = WindowsUtils.generate_def_file(ir, working_dir,
                                                   ignore_dlls=[DUMMY_LIB_NAME])
        asm = WindowsUtils.asm_fix_lib_names(asm, def_files)

        # Some functions share the name of assembly keywords. Fix these
        # collisions in the generated assembly
        asm = WindowsUtils.asm_fix_func_name_collisions(asm, ['fabs'])

        # Write back modified ASM
        with open(asm_fname, 'w') as f:
            f.write(asm)

        if not gen_binary:
            return

        # Generate lib files from def files
        for dll in def_files:
            def_file = def_files[dll]
            lib_file = os.path.join(working_dir, f'{dll}.lib')
            machine = r'/MACHINE:X64' if is_64bit else r'/MACHINE:X86'
            cmd = ['lib', r'/nologo', fr'/def:{def_file}', fr'/out:{lib_file}',
                   machine]
            run_cmd(cmd)

        # Generate object from instrumented assembly
        obj_name = f'{basename}.obj'
        obj_path = os.path.join(working_dir, obj_name)
        ml = "ml64" if is_64bit else "ml"
        cmd = [ml, r'/nologo', r'/c', fr'/Fo{obj_path}', f'{asm_fname}']
        run_cmd(cmd)

        # Generate executable, linking in files if needed
        binary_name = f'{basename}.exe'
        binary_path = os.path.join(working_dir, f'{basename}.exe')
        if obj_link == None:
            obj_link = []
        entrypoint = r'/ENTRY:__EntryPoint' if is_64bit else r'/ENTRY:_EntryPoint'
        cmd = ["cl", r'/nologo', f'{obj_name}', fr'/Fe{binary_name}', r'/link'] + obj_link + [entrypoint, r'/SUBSYSTEM:console']
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

            # sub stack right before call. may not be needed.
            sub esp, 0x40

            {pre_call}
            call    {func}
            {post_call}

            add esp, 0x40

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

class WindowsX64Utils(WindowsUtils):
    @staticmethod
    def backup_registers(label: str) -> str:
        return f'''
            mov    QWORD PTR [rip+{label}],        rax
            mov    QWORD PTR [rip+{label} + 0x8],  rbx
            mov    QWORD PTR [rip+{label} + 0x10], rcx
            mov    QWORD PTR [rip+{label} + 0x18], rdx
            mov    QWORD PTR [rip+{label} + 0x20], rdi
            mov    QWORD PTR [rip+{label} + 0x28], rsi
            mov    QWORD PTR [rip+{label} + 0x30], r8
            mov    QWORD PTR [rip+{label} + 0x38], r9
            mov    QWORD PTR [rip+{label} + 0x40], r10
            mov    QWORD PTR [rip+{label} + 0x48], r11
            mov    QWORD PTR [rip+{label} + 0x50], r12
            mov    QWORD PTR [rip+{label} + 0x58], r13
            mov    QWORD PTR [rip+{label} + 0x60], r14
            mov    QWORD PTR [rip+{label} + 0x68], r15
            movq   QWORD PTR [rip+{label} + 0x70], xmm0
            movq   QWORD PTR [rip+{label} + 0x80], xmm1
            movq   QWORD PTR [rip+{label} + 0x90], xmm2
            movq   QWORD PTR [rip+{label} + 0xa0], xmm3
            movq   QWORD PTR [rip+{label} + 0xb0], xmm4
            movq   QWORD PTR [rip+{label} + 0xc0], xmm5
            movq   QWORD PTR [rip+{label} + 0xd0], xmm6
            movq   QWORD PTR [rip+{label} + 0xe0], xmm7
            movq   QWORD PTR [rip+{label} + 0xf0], xmm8
            movq   QWORD PTR [rip+{label} + 0x100],xmm9
            movq   QWORD PTR [rip+{label} + 0x110],xmm10
            movq   QWORD PTR [rip+{label} + 0x120],xmm11
            movq   QWORD PTR [rip+{label} + 0x130],xmm12
            movq   QWORD PTR [rip+{label} + 0x140],xmm13
            movq   QWORD PTR [rip+{label} + 0x150],xmm14
            movq   QWORD PTR [rip+{label} + 0x160],xmm15
        '''

    @staticmethod
    def restore_registers(label: str) -> str:
        return f'''
            mov    rax,  QWORD PTR [rip+{label}]
            mov    rbx,  QWORD PTR [rip+{label} + 0x8]
            mov    rcx,  QWORD PTR [rip+{label} + 0x10]
            mov    rdx,  QWORD PTR [rip+{label} + 0x18]
            mov    rdi,  QWORD PTR [rip+{label} + 0x20]
            mov    rsi,  QWORD PTR [rip+{label} + 0x28]
            mov    r8,   QWORD PTR [rip+{label} + 0x30]
            mov    r9,   QWORD PTR [rip+{label} + 0x38]
            mov    r10,  QWORD PTR [rip+{label} + 0x40]
            mov    r11,  QWORD PTR [rip+{label} + 0x48]
            mov    r12,  QWORD PTR [rip+{label} + 0x50]
            mov    r13,  QWORD PTR [rip+{label} + 0x58]
            mov    r14,  QWORD PTR [rip+{label} + 0x60]
            mov    r15,  QWORD PTR [rip+{label} + 0x68]
            movq   xmm0, QWORD PTR [rip+{label} + 0x70]
            movq   xmm1, QWORD PTR [rip+{label} + 0x80]
            movq   xmm2, QWORD PTR [rip+{label} + 0x90]
            movq   xmm3, QWORD PTR [rip+{label} + 0xa0]
            movq   xmm4, QWORD PTR [rip+{label} + 0xb0]
            movq   xmm5, QWORD PTR [rip+{label} + 0xc0]
            movq   xmm6, QWORD PTR [rip+{label} + 0xd0]
            movq   xmm7, QWORD PTR [rip+{label} + 0xe0]
            movq   xmm8, QWORD PTR [rip+{label} + 0xf0]
            movq   xmm9, QWORD PTR [rip+{label} + 0x100]
            movq   xmm10,QWORD PTR [rip+{label} + 0x110]
            movq   xmm11,QWORD PTR [rip+{label} + 0x120]
            movq   xmm12,QWORD PTR [rip+{label} + 0x130]
            movq   xmm13,QWORD PTR [rip+{label} + 0x140]
            movq   xmm14,QWORD PTR [rip+{label} + 0x150]
            movq   xmm15,QWORD PTR [rip+{label} + 0x160]
        '''

    @staticmethod
    def call_function(func: str,
                      save_stack: Optional[int]=0,
                      pre_call: Optional[str]='',
                      post_call: Optional[str]='') -> str:

        return f'''
            sub     esp, {hex(save_stack)}
            pushfq
            push    rax
            push    rcx
            push    rdx
            push    rsi
            push    rdi
            push    r8
            push    r9
            push    r10
            push    r11
            push    rax

            # stack alignment
            mov     rdi, rsp
            lea     rsp, [rsp - 0x80]
            and     rsp, 0xfffffffffffffff0
            push    rdi
            push    rdi

            # sub stack right before call. may not be needed.
            sub     rsp, 0x100

            {pre_call}
            call {func}
            {post_call}

            add rsp, 0x100

            pop     rdi
            mov     rsp, rdi

            pop     rax
            pop     r11
            pop     r10
            pop     r9
            pop     r8
            pop     rdi
            pop     rsi
            pop     rdx
            pop     rcx
            pop     rax
            popfq
            add     esp, {hex(save_stack)}
        '''