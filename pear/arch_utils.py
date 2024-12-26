# Architecture specific utility functions
import os
import gtirb
import logging
from typing import Optional

from gtirb import Symbol, ProxyBlock
import gtirb_rewriting._auxdata as _auxdata

from .utils import run_cmd, check_executables_exist
from . import DUMMY_LIB_NAME

log = logging.getLogger(__name__)

class ArchUtils:
    @staticmethod
    def check_compiler_exists() -> bool:
        '''
        Assert compiler accessible for current architecture
        :return: if compiler found for current architecture
        '''
        raise NotImplementedError

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
    def generate(output: str, working_dir: str, ir: gtirb.IR, *args, 
                 asm_fname: Optional[str]=None,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False, 
                 obj_link: Optional[list[str]]=None, **kwargs):
        """
        Generate binary or assembly from instrumented IR or assembly.

        :param output: File location of output assembly and/or binary. '.exe'
            will be added for output binary, '.S' for assembly and '.gtirb' for 
            IR.
        :param working_dir: Local working directory to generate intermediary
            files
        :param ir: GTIRB IR to generate from
        :param asm_fname: If generating from instrumented assembly, file name of
          instrumented asm. We still need an IR to get info on how to generate
          the instrumented binary.
        :param gen_assembly: True if generating assembly
        :param gen_binary: True if generating binary
        :param obj_link: paths of additional objects / libraries to link
        """
        # The following is a stub that calls gtirb-pprinter on the IR directly.
        # No support for linking in static objects or any changes to default
        # gtirb-pprinter binary generation.
        basename = os.path.basename(output)
        asm_path = os.path.join(working_dir, f'{basename}.S')
        bin_path = os.path.join(working_dir, f'{basename}.exe')
        ir_file = os.path.join(working_dir, f'{basename}.gtirb')

        # Generate IR
        ir.save_protobuf(ir_file)
        log.info(f'Instrumented IR saved to: {ir_file}')

        assert gen_assembly or gen_binary, \
            "One of gen_assembly or gen_binary must be true"

        if asm_fname:
            raise NotImplementedError

        if not (obj_link == None or obj_link == []):
            raise NotImplementedError

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

class LinuxUtils(ArchUtils):
    @staticmethod
    def check_compiler_exists() -> bool:
        assert check_executables_exist(['gcc', 'ld']), \
            "GCC build tools not found"
        return True

    @staticmethod
    def backup_registers(label: str) -> str:
        raise NotImplementedError

    @staticmethod
    def restore_registers(label: str) -> str:
        raise NotImplementedError

    @staticmethod
    def call_function(func: str,
                      save_stack: Optional[int]=0,
                      pre_call: Optional[str]='',
                      post_call: Optional[str]='') -> str:
        raise NotImplementedError

    @staticmethod
    def generate_asm_external_symbol_stub(name: str, is_func: bool,
                                          version: Optional[str]=None,
                                          size: Optional[int] = 8) -> str:
        """
        Generate assembly stub for given function or data.

        :param name: Name of symbol
        :param is_func: True if function, False if data
        :param version: Version string, if versioned
        :returns: Assembly stub
        """
        ret = ''
        if version:
            ret += f'.symver {name},{name}@{version}\n'
        ret += f'.globl {name}\n'
        if is_func:
            ret += f'.type {name}, @function\n'
            ret += f'{name}:\nret\n\n'
        else:
            # If we don't specify the size, the linker won't generate a COPY
            # relocation within the final generated binary
            # (which is needed for data references)
            ret += f'.size {name}, {size}\n'
            ret += f'{name}:\n.byte {size}\n\n'
        return ret

    @staticmethod
    def generate_versioned_dummy_libs(versioned_syms: dict[str, dict[str, list[Symbol]]],
                                      elf_symbol_info: dict[Symbol, tuple[int, str, str, str, int]],
                                      out_folder) -> dict[str, tuple[str, str]]:
        """
        Generate assembly and version map for dummy libraries that define
        specific versioned symbols within those libraries
        Creates output files in the out_folder.
        e.g. for libc.so.6, generates:
            - {out_folder}/dummy_libc.so.6.S
            - {out_folder}/dummy_libc.so.6.version_map

        :param versioned_syms: Mapping of symbols of specific versions within
          libraries. e.g. {lib: {version: [symbol]}}
        :param elf_symbol_info: elfSymbolInfo AuxData table (used for symbol
                                                             type and size)
        :param out_folder: Path of output folder.
        :returns: {library: (generated asm, generated version map)}
        """
        ret = {}
        for lib, versions in versioned_syms.items():
            asm_p = os.path.join(out_folder, 'dummy_'+lib) + '.S'
            # generate version map
            version_map_p = os.path.join(out_folder, 'dummy_'+lib) + '.version_map'

            with open(asm_p, 'w') as f:
                text = '.section .text\n\n'
                data = '.section .data\n\n'
                
                for version, symlist in versions.items():
                    for sym in symlist:
                        name = sym.name
                        symsize, symtype, _, _, _ = elf_symbol_info[sym]
                        if symtype == 'FUNC':
                            text += LinuxUtils.generate_asm_external_symbol_stub(name, is_func=True, version=version)
                        elif symtype == 'OBJECT':
                            data += LinuxUtils.generate_asm_external_symbol_stub(name, is_func=False, version=version, size=symsize)
                f.write(text)
                f.write(data)
            log.info(f"Generated assembly for dummy {lib} at: {asm_p}")

            with open(version_map_p, 'w') as f:
                for version, symlist in versions.items():
                    f.write(version + " {\n  global:\n") #}
                    for sym in symlist:
                        f.write(f"    {sym.name};\n")
                    f.write("};\n\n")
            log.info(f"Generated version map for dummy {lib} at: {version_map_p}")
            ret[lib] = (asm_p, version_map_p)
        return ret

    @staticmethod
    def generate(output: str, working_dir: str, ir: gtirb.IR, *args, 
                 asm_fname: Optional[str]=None,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False, 
                 obj_link: Optional[list[str]]=None, **kwargs):
        basename = os.path.basename(output)
        ir_file = os.path.join(working_dir, f'{basename}.gtirb')

        # Generate IR
        ir.save_protobuf(ir_file)
        log.info(f'Instrumented IR saved to: {ir_file}')

        assert gen_assembly or gen_binary, \
            "At least one of gen_assembly or gen_binary must be true"

        # Generate assembly (required for binary generation as well)
        assert check_executables_exist(['gtirb-pprinter']), "gtirb-pprinter not found"

        if not asm_fname:
            asm_fname = f'{output}.S' if gen_assembly else os.path.join(working_dir, f'{basename}.S')
            cmd = ["gtirb-pprinter", ir_file, '--asm', asm_fname]
            run_cmd(cmd)
            log.info(f'Generated assembly saved to: {asm_fname}')

        if not gen_binary:
            return

        # Get version info:
        #  - store versioned symbols: lib: {version: [(sym, type)]}
        #  - keep track of non-versioned symbols: [sym, type]
        versioned_syms: dict[str, dict[str, list[Symbol]]] = {}
        nonversioned_syms: list[Symbol] = []
        external_libraries: list[str] = []
        library_paths: list[str] = []
        elf_symbol_info: dict[Symbol, tuple[int, str, str, str, int]] = {}
        exec_stack: bool = False
        stack_size: int = -1
        binary_type: list[str] = []
        has_ctors_dtors: bool = False

        assert len(ir.modules) == 1, "PeAR only supports one module GTIRB IRs"
        for module in ir.modules:
            # Get data from aux tables
            symbol_to_version_map: dict[Symbol, tuple[int, bool]] # {SYMBOL: (ID, is_hidden)}
            strong_versioned_syms: dict[Symbol, int] = {} # versioned sym:  ID
            lib_version_imports: dict[str, dict[int, str]] = {} # lib: {ID: version}
            exec_stack = module.aux_data['elfStackExec'].data
            stack_size = module.aux_data['elfStackSize'].data
            binary_type = _auxdata.binary_type.get_or_insert(module)
            library_paths = _auxdata.library_paths.get_or_insert(module)
            elf_symbol_info = _auxdata.elf_symbol_info.get_or_insert(module)
            external_libraries = _auxdata.libraries.get_or_insert(module)
            symbol_forwarding = _auxdata.symbol_forwarding.get_or_insert(module)
            elf_symbol_versions = module.aux_data['elfSymbolVersions'].data
            sym_version_defs, lib_version_imports, symbol_to_version_map = elf_symbol_versions

            # Get external versioned syms, ignoring hidden symbols
            for sym, (id, is_hidden) in symbol_to_version_map.items():
                strong_versioned_syms[sym] = id

            # Construct versioned_syms dict containing what symbols have what
            # version in what libraries
            id_to_lib_version: dict[int, tuple[str, str]] = {}
            for lib, id_to_version in lib_version_imports.items():
                versioned_syms[lib] = {}
                for id, version in id_to_version.items():
                    versioned_syms[lib][version] = []
                    id_to_lib_version[id] = (lib, version)
            for sym, id in strong_versioned_syms.items():
                lib, version = id_to_lib_version[id]
                versioned_syms[lib][version].append(sym)

            # To get non-versioned external symbols we collect all global,
            # non-hidden symbols that aren't versioned.
            for sym, (_, _, binding, visibility, _) in elf_symbol_info.items():
                if binding == 'GLOBAL' and visibility != 'HIDDEN' and sym not in strong_versioned_syms:
                    nonversioned_syms.append(sym)

            for section in module.sections:
                if '.ctors' in section.name:
                    has_ctors_dtors = True

        LinuxUtils.check_compiler_exists()

        if has_ctors_dtors:
            log.warning(f'The input binary has a .ctors or .dtors section. This could cause issues during regeneration, more details and a possible fix here: https://github.com/GrammaTech/gtirb-pprinter/issues/17')

        # We need to put unversioned symbol definitions somewhere...
        # We could weaken them, but I don't want to do that, as that would
        # require the objcopy tool from binutils, and I don't want extra
        # dependencies.
        # So we simply add them to the first library we generate, versioned or
        # non-versioned. As non-versioned symbols aren't tied to library name,
        # it doesn't matter what library we generate them under
        text = '.section .text\n\n'
        data = '.section .data\n\n'
        for sym in nonversioned_syms:
            name = sym.name
            symsize, symtype, _, _, _ = elf_symbol_info[sym]
            if symtype == 'FUNC':
                text += LinuxUtils.generate_asm_external_symbol_stub(name, is_func=True)
            elif symtype == 'OBJECT':
                data += LinuxUtils.generate_asm_external_symbol_stub(name, is_func=False, size=symsize)
        non_versioned_stubs = text + data
        added_non_versioned_stubs = False

        # Generate stub libraries 
        dummy_lib_to_asm_version_map: dict[str, tuple[str, str]] = \
                LinuxUtils.generate_versioned_dummy_libs(versioned_syms, elf_symbol_info, working_dir)
        dummy_libs = []
        for lib, (asm, version_map) in dummy_lib_to_asm_version_map.items():
            if not added_non_versioned_stubs:
                with open(asm, "a") as f:
                    f.write(non_versioned_stubs)
                    added_non_versioned_stubs = True
            dummy_lib = os.path.join(working_dir, lib)
            dummy_libs.append(lib)
            cmd = ['gcc', '-shared', '-fPIC', asm, f'-Wl,--version-script={version_map}', '-o', dummy_lib, '-nodefaultlibs']
            run_cmd(cmd)

        # Generate non-versioned stub libraries
        non_versioned_libs = []
        for lib in external_libraries:
            if lib not in dummy_libs:
                non_versioned_libs.append(lib)
        for lib in non_versioned_libs:
            libpath = os.path.join(working_dir, lib) + '.S'
            with open(libpath, 'w') as f:
                if not added_non_versioned_stubs:
                    f.write(non_versioned_stubs)
                    added_non_versioned_stubs = True
            dummy_lib = os.path.join(working_dir, lib)
            dummy_libs.append(lib)
            cmd = ['gcc', '-shared', '-fPIC', libpath, '-o', dummy_lib, '-nodefaultlibs']
            run_cmd(cmd)

        # Generate object from instrumented assembly
        obj_name = f'{basename}.o'
        obj_path = os.path.join(working_dir, obj_name)
        cmd = ['gcc', '-c', '-o', obj_path, asm_fname, '-nodefaultlibs', '-nostartfiles']
        run_cmd(cmd)

        # Collect rpaths
        rpath_cmd = []
        for rpath in library_paths:
            rpath_cmd += ['-rpath', rpath]

        # Set exec stack as in original binary
        exec_stack_cmd = ['-z', 'execstack' if exec_stack else 'noexecstack']

        # Set stack size (most binaries this is zero, meaning set to default stack size)
        stack_size_cmd = ['-z', f'stack-size={stack_size}']

        # Set pie or not
        pie_cmd = ['-pie' if 'PIE' in binary_type else '-no-pie']

        # Link it all together
        binary_path = f'{output}.exe'
        bin_name = f'{basename}.exe'
        cmd = ['ld', '-o', bin_name, obj_name] + dummy_libs + pie_cmd + exec_stack_cmd + ['-z', 'relro'] + stack_size_cmd + rpath_cmd
        run_cmd(cmd, working_dir=working_dir)

        log.info(f'Generated binary saved to: {binary_path}')

class WindowsUtils(ArchUtils):
    @staticmethod
    def check_compiler_exists() -> bool:
        assert check_executables_exist(['cl']), \
            "MSVC build tools not found, are you running in a developer command prompt?"
        return True

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
                    if func.split('@')[0] == lib[:-4]:
                        # Import by ordinal
                        ordinal = func.split('@')[1]
                        f.write(f'    {func} @ {ordinal} NONAME\n')
                    else:
                        # Import by name
                        f.write(f'    {func}\n')

            log.info(f"Generated DEF file for {lib} at: {out_fname}")

        return def_file_mappings

    @staticmethod
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

    @staticmethod
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
    def generate(output: str, working_dir: str, ir: gtirb.IR, *args, 
                 asm_fname: Optional[str]=None,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False, 
                 obj_link: Optional[list[str]]=None, **kwargs):
        """
        Generate assembly code or binary using gtirb-pprinter locally. At least one
        of gen_assembly or gen_binary must be true. MSVC must be installed and
        accessible and targeting right architecture.
        
        We use our own build process as gtirb-pprinter's PE binary printing doesn't
        allow us to link our own static libraries into the generated binary.

        :param output: File location of output assembly and/or binary. '.exe' will
            be added for output binary and '.S' for assembly.
        :param working_dir: Local working directory to generate intermediary files
        :param ir: GTIRB IR being printed 
        :param asm_fname: If generating from instrumented assembly, file name of
          instrumented asm. We still need an IR to get info on how to generate
          the instrumented binary.
        :param gen_assembly: True if generating assembly
        :param gen_binary: True if generating binary
        :param obj_link: Path of object to link into instrumented binary.
        """
        if asm_fname:
            raise NotImplementedError
        is_64bit = ir.modules[0].isa == gtirb.Module.ISA.X64
        basename = os.path.basename(output)
        ir_file = os.path.join(working_dir, f'{basename}.gtirb')

        # Generate IR
        ir.save_protobuf(ir_file)
        log.info(f'Instrumented IR saved to: {ir_file}')

        assert gen_assembly or gen_binary, \
            "At least one of gen_assembly or gen_binary must be true"

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
    def check_compiler_exists() -> bool:
        if WindowsUtils.check_compiler_exists():
            cl_out, _ = run_cmd(["cl"], print=False)
            assert b"for x86" in cl_out, \
                "32-bit MSVC build tools must be used to generate 32-bit instrumented binary"
            return True
        return False

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
    def check_compiler_exists() -> bool:
        if WindowsUtils.check_compiler_exists():
            cl_out, _ = run_cmd(["cl"], print=False)
            assert b"for x64" in cl_out, \
                "64-bit MSVC build tools must be used to generate 64-bit instrumented binary"
            return True
        return False

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
