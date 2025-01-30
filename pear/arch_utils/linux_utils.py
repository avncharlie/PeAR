import os
import re
import uuid
import gtirb
import random
import string
import logging
from typing import Optional, Union

from gtirb import Symbol, CodeBlock
from gtirb.block import DataBlock
from gtirb.cfg import Edge
from gtirb.module import Module
from gtirb.offset import Offset
from gtirb.symbolicexpression import SymAddrConst, SymAddrAddr, SymbolicExpression
import gtirb_rewriting._auxdata as _auxdata
from gtirb_capstone.instructions import GtirbInstructionDecoder
import gtirb_rewriting._auxdata as _auxdata

from .arch_utils import ArchUtils
from ..utils import run_cmd, check_executables_exist
from .. import DUMMY_LIB_NAME
from ..instruction_finder import find_asm_pattern, split_asm

log = logging.getLogger(__name__)

from dataclasses import dataclass

@dataclass
class SwitchData:
    jt_entry_size: int
    jt_load_instr_addr: int
    jt: DataBlock
    cases_start: CodeBlock
    matched_instructions: list[str]
    jt_label: str = ''
    cases_start_label: str = ''

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
    def generate_asm_external_symbol_stub(name: str, is_func: bool,
                                          version: Optional[str]=None,
                                          size: Optional[int] = 8) -> str:
        """
        Generate assembly stub for given function or data.

        :param name: Name of symbol
        :param is_func: True if function, False if data
        :param version: Version string, if versioned
        :param size: Size of symbol
        :returns: Assembly stub
        """
        ret = ''
        if version:
            ret += f'.symver {name},{name}@@@{version}\n'
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
                                      out_folder: str) -> dict[str, tuple[str, str]]:
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
                 obj_link: Optional[list[str]]=None, 
                 switch_data: Optional[list[SwitchData]]=None,
                 **kwargs):
        assert len(ir.modules) == 1, "PeAR only supports one module GTIRB IRs"

        is_x64 = ir.modules[0].isa == gtirb.Module.ISA.X64
        is_arm64 = ir.modules[0].isa == gtirb.Module.ISA.ARM64

        # GCC linker has a super weird behaviour where it blindly converts
        # legacy .ctors/.dtors sections to new .init_array/.fini_array sections,
        # despite their different semantics.
        #   .ctors/.dtors:
        #     Contains list of pointers terminated by -1. GCC inserts startup
        #     and teardown code in the binary (within the _init/_fini functions)
        #     that traverses these lists and executes the functions within them.
        #   .init_array/.fini_array:
        #     Contains list of pointers. libc executes these functions on
        #     startup/teardown. The size of this list is baked into the ELF
        #     file (in a dynamic tag), and it is not terminated by -1.
        # Upon converting .ctors/.dtors to .init_array/.fini_array, libc reads
        # the -1 as an item in the startup/teardown list and attempts to call
        # it, causing a segfault. 
        # To prevent this, we rename the .ctors/.dtors sections to prevent them
        # from being converted. The _init/_fini functions still operate as
        # normal and will execute the functions in these renamed sections. 
        # This is as the .ctor/.dtor sections are not special sections like
        # .init_array/.fini_array and the data they contain is only referenced
        # within the binary itself, so they can be renamed with no issues.
        # Read more:
        #  - https://maskray.me/blog/2021-11-07-init-ctors-init-array
        #  - https://github.com/GrammaTech/gtirb-pprinter/issues/17
        has_ctors_dtors = False
        for module in ir.modules:
            for section in module.sections:
                if '.ctors' in section.name:
                    has_ctors_dtors = True
                    section.name = '.old' + section.name
                if '.dtors' in section.name:
                    has_ctors_dtors = True
                    section.name = 'old' + section.name
        if has_ctors_dtors:
            log.warning(f'The input binary has a .ctors or .dtors section. This might cause issues during regeneration.')

        basename = os.path.basename(output)
        ir_file = os.path.join(working_dir, f'{basename}.gtirb')

        # Generate IR
        ir.save_protobuf(ir_file)
        log.info(f'Instrumented IR saved to: {ir_file}')

        assert gen_assembly or gen_binary, \
            "At least one of gen_assembly or gen_binary must be true"

        if not asm_fname:
            # Generate assembly (required for binary generation as well)
            assert check_executables_exist(['gtirb-pprinter']), "gtirb-pprinter not found"

            asm_fname = f'{output}.S' if gen_assembly else os.path.join(working_dir, f'{basename}.S')
            intel_syntax = ['--syntax', 'intel'] if is_x64 else []
            cmd = ["gtirb-pprinter", ir_file] + intel_syntax + ['--asm', asm_fname]
            run_cmd(cmd)
            if switch_data:
                expand_arm64_switches(asm_fname, switch_data)
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
            symbol_forwarding = _auxdata.symbol_forwarding.get_or_insert(module)
            elf_symbol_versions = module.aux_data['elfSymbolVersions'].data
            sym_version_defs, lib_version_imports, symbol_to_version_map = elf_symbol_versions
            _external_libraries = _auxdata.libraries.get_or_insert(module)
            # Filter out dummy lib, this would be introduced while adding a
            # call to an instrumentation library.
            for x in _external_libraries:
                if x != DUMMY_LIB_NAME:
                    external_libraries.append(x)

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
            # Ignore special _init and _fini functions
            for sym, (_, _, binding, visibility, _) in elf_symbol_info.items():
                ignore = ['_init', '_fini']
                if binding == 'GLOBAL' and visibility != 'HIDDEN' \
                        and sym not in strong_versioned_syms \
                        and sym.name not in ignore:
                    nonversioned_syms.append(sym)

        LinuxUtils.check_compiler_exists()

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
        extra_link = [] if not obj_link else obj_link
        cmd = ['ld', '-o', bin_name, obj_name] + extra_link + dummy_libs + pie_cmd + exec_stack_cmd + ['-z', 'relro'] + stack_size_cmd + rpath_cmd
        run_cmd(cmd, working_dir=working_dir)

        log.info(f'Generated binary saved to: {binary_path}')

class LinuxX64Utils(LinuxUtils):
    @staticmethod
    def call_function(func: str,
                      save_stack: Optional[int]=128,
                      pre_call: Optional[str]='',
                      post_call: Optional[str]='',
                      data: Optional[str]='') -> str:
        return f'''
            # Keep red zone safe.
            # use lea instead of add/sub so we don't stuff up flags before the pushfq
            lea rsp, [rsp - {save_stack}]
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
            push    rbx
            push    rbp
            push    r12
            push    r13
            push    r14
            push    r15

            # 16-byte align stack
            mov     rax, rsp
            lea     rsp, [rsp - 0x80]
            and     rsp, 0xfffffffffffffff0
            push    rax
            push    rax

            {pre_call}
            call {func}
            {post_call}

            pop     rax
            mov     rsp, rax

            pop     r15
            pop     r14
            pop     r13
            pop     r12
            pop     rbp
            pop     rbx
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
            lea rsp, [rsp + {save_stack}]

            {data}
        '''

class LinuxARM64Utils(LinuxUtils):
    @staticmethod
    def call_function(func: str,
                      save_stack: Optional[int]=128,
                      pre_call: Optional[str]='',
                      post_call: Optional[str]='',
                      data: Optional[str]='') -> str:
        return f'''
            sub sp, sp, {save_stack}
            stp x0, x1, [sp, #-16]!
            stp x2, x3, [sp, #-16]!
            stp x4, x5, [sp, #-16]!
            stp x6, x7, [sp, #-16]!
            stp x8, x9, [sp, #-16]!
            stp x10, x11, [sp, #-16]!
            stp x12, x13, [sp, #-16]!
            stp x14, x15, [sp, #-16]!
            stp x16, x17, [sp, #-16]!
            stp x18, x19, [sp, #-16]!
            stp x20, x21, [sp, #-16]!
            stp x22, x23, [sp, #-16]!
            stp x24, x25, [sp, #-16]!
            stp x26, x27, [sp, #-16]!
            stp x28, x29, [sp, #-16]!
            stp x30, xzr, [sp, #-16]!
            
            # Save flags
            mrs x20, nzcv
            stp x20, xzr, [sp, #-16]!

            # 16-byte align stack
            mov x10, sp
            mov x9, sp
            sub x9, x9, #128
            and x9, x9, #-16
            mov sp, x9
            stp x10, xzr, [sp, #-16]!

            {pre_call}
            bl {func}
            {post_call}

            ldp x10, xzr, [sp], #16
            mov sp, x10

            # Restore flags
            ldp x20, xzr, [sp], #16
            msr nzcv, x20

            ldp x30, xzr, [sp], #16
            ldp x28, x29, [sp], #16
            ldp x26, x27, [sp], #16
            ldp x24, x25, [sp], #16
            ldp x22, x23, [sp], #16
            ldp x20, x21, [sp], #16
            ldp x18, x19, [sp], #16
            ldp x16, x17, [sp], #16
            ldp x14, x15, [sp], #16
            ldp x12, x13, [sp], #16
            ldp x10, x11, [sp], #16
            ldp x8, x9, [sp], #16
            ldp x6, x7, [sp], #16
            ldp x4, x5, [sp], #16
            ldp x2, x3, [sp], #16
            ldp x0, x1, [sp], #16
            add sp, sp, {save_stack}

            {data}
        '''

def get_loaded_addr(module: Module, start: int, end: int) -> Union[tuple[DataBlock, str], None]:
    '''
    Get address loaded by adrp/add instruction pair
    :param module: GTIRB module
    :param start: start Address of adrp instruction
    :param end: End address of add instruction
    :returns: (DataBlock, name)
    '''
    e = list(module.symbolic_expressions_at(range(start, end)))
    # Check these instructions load one data address
    if len(e) != 2:
        return None
    interval, off, syme1 = e[0]
    _, _, syme2 = e[1]
    if type(syme1) != SymAddrConst or type(syme2) != SymAddrConst:
        return None
    if syme1.symbol != syme2.symbol or type(syme1.symbol._payload) != DataBlock:
        return None
    return (syme1.symbol._payload, syme1.symbol.name)

def get_switch_start(module: Module, start: int, end: int) -> Union[CodeBlock, None]:
    '''
    Get starting code address of switch loaded by ldrb/adr/add instruction set
    :param module: GTIRB module
    :param start: start Address of adrp instruction
    :param end: End address of add instruction
    '''
    e = list(module.symbolic_expressions_at(range(start, end)))
    # Check these instructions load one code address
    if len(e) != 1:
        return None
    _, _, syme1 = e[0]
    if type(syme1) != SymAddrConst:
        return None
    if type(syme1.symbol._payload) != CodeBlock:
        return None
    return syme1.symbol._payload

def find_switches(module: gtirb.Module) -> list[SwitchData]:
    '''
    Identify switches (very basic).
    Assumes no instrumentation has been applied!

    ID switches by:
        adrp <r1>, <jump_table>
        add <r1>, <r1>, :lo12:<jump_table>
        ldr* <r2>, [<r1>, *, uxtw*]
        adr <r3>, <code_base>
        add *, <r3>, <r2>, sxtw *

    :param module: Module to fix
    :returns: list of (Switch location, jump table location)
    '''
    decoder = GtirbInstructionDecoder(module.isa)

    asm = []
    ins_index: list[tuple[CodeBlock, int]] = []
    for cb in sorted(module.code_blocks, key=lambda e: e.address): # type: ignore
        cb: CodeBlock
        insns = list(decoder.get_instructions(cb))
        for i in insns:
            insns_str = f'{i.insn_name()} {i.op_str}'
            # Symbolise a few known instructions (TODO: add branches)
            if i.insn_name() in ['adrp', 'adr', 'add']:
                r = list(module.symbolic_expressions_at(range(i.address, i.address + i.size)))
                if len(r) > 0:
                    label = r[0][2].symbol.name
                    if SymbolicExpression.Attribute.LO12 in r[0][2].attributes:
                        label = ":lo12:" + label
                    # Replace literal with symbol
                    insns_str = re.sub(r'#\S+', label, insns_str)
            asm.append(insns_str)
            ins_index.append((cb, i.address))

    matches = find_asm_pattern(asm, [
        "adrp <r1>, <jump_table>", 
        "add <r1>, <r1>, :lo12:<jump_table>", 
        "ldr* <r2>, [<r1>, *, uxtw*]", 
        "adr <r3>, <code_base>", 
        "add *, <r3>, <r2>, sxtw *", 
    ])

    switches: list[SwitchData] = []

    # create SwitchData for each match
    for match in matches:
        jt_entry_size = -1
        jt_load_instr_addr = -1
        jt = None
        cases_start = None
        matched_instructions = []
        jt_label = '' 
        cases_start_label = ''

        for i in match:
            matched_instructions.append(asm[i])

        # Get load size based on load instruction
        load = (asm[match[2]]).split(' ')[0]
        if load == 'ldr':
            jt_entry_size = 4
        elif load == 'ldrh':
            jt_entry_size = 2
        elif load == 'ldrb':
            jt_entry_size = 1

        load_cb, load_addr = ins_index[match[2]]
        jt_load_instr_addr = load_addr

        jt_label = ((asm[match[0]]).split(',')[-1]).strip()
        jt = next(module.symbols_named(jt_label))._payload

        cases_start_label = ((asm[match[3]]).split(',')[-1]).strip()
        cases_start = next(module.symbols_named(cases_start_label))._payload
        switches.append(SwitchData(
                        jt_entry_size=jt_entry_size,
                        jt_load_instr_addr=jt_load_instr_addr,
                        jt=jt,
                        cases_start=cases_start,
                        matched_instructions=matched_instructions,
                        jt_label=jt_label,
                        cases_start_label=cases_start_label))
    return switches

def get_instructions(cb: CodeBlock):
    decoder = GtirbInstructionDecoder(Module.ISA.ARM64)
    l = decoder.get_instructions(cb)
    ret = []
    for x in l:
        ret.append( (x.address, f'{x.insn_name()} {x.op_str}') )
    return ret

def fix_arm64_switches(ir: gtirb.IR) -> list[SwitchData]:
    '''
    Find switches and ensure that their jump tables are constructed correctly.
    Assumes no instrumentation has been applied!
    Assumes that the incorrect switch jump table is just one big datablock (or
    consecutive DataBlocks)

    :param ir: IR to fix
    :returns: Switch information
    '''
    module = ir.modules[0]
    sym_expr_sizes: dict[gtirb.Offset, int] = _auxdata.symbolic_expression_sizes.get_or_insert(module)
    encodings: dict[gtirb.DataBlock, str] = _auxdata.encodings.get_or_insert(module)

    switches = find_switches(module)
    corrected = 0
    for s in switches:
        bi = s.jt.byte_interval
        entry_s = s.jt_entry_size
        if bi == None:
            continue

        # CodeBlock that jumps to different cases
        jump_to_case = next(module.code_blocks_on(s.jt_load_instr_addr))
        # CodeBlock that other cases are indexed from (and is probably case 1)
        code_start = s.cases_start
        code_start_sym = None
        for sym in module.symbols:
            if sym._payload == code_start:
                code_start_sym = sym
        assert code_start_sym != None, "Could not find code start sym?"
        s.cases_start_label = code_start_sym.name

        fixed = False

        curr = None
        # A jump table may be composed of multiple consecutive DataBlocks
        while True:
            if not curr:
                curr = s.jt
            else:
                # If the consecutive DataBlock has no references, we assume it
                # is part of the same jump table
                r = list(module.data_blocks_at(curr.address + curr.size))
                if len(r) > 0 and len(list(r[0].references)) == 0:
                    curr = r[0]
                else:
                    # Otherwise, we assume the jump table has ended
                    break

            r = list(module.symbolic_expressions_at(range(curr.address, curr.address + curr.size)))
            if len(r) > 0 and type(r[0][2]) == SymAddrAddr:
                # This part of the jump table already has symbolic expressions,
                continue
        
            fixed = True

            # Get raw bytes of jump table
            jt_content = curr.contents
            start_offset = curr.offset

            # If the jump table currently has a type (i.e string), remove it
            # As it interferes with gtirb-pprinter outputting symbolic expressions
            if curr in encodings:
                del encodings[curr]

            # Use jump table bytes to calculate offsets and find CodeBlocks for
            # other switch cases, and tell GTIRB this
            current_offset = start_offset
            for x in range(0, len(jt_content), entry_s):
                # Get index to case
                jt_offset = int.from_bytes(bytes(jt_content[x:x+entry_s]), 'little')
                case_addr = code_start.address + jt_offset*4

                # Generate label name for case
                sym_name = '.L' + ''.join(random.choices(string.ascii_lowercase, k=10))

                # Get case CodeBlock or create one
                case = None
                c = list(module.code_blocks_at(case_addr))
                if len(c) != 0:
                    case = c[0]
                else:
                    log.warning(f"Could not find CodeBlock at address {hex(case_addr)}! Attempting to insert one with label {sym_name} at this address.")
                    # No CodeBlock, we must create one. We will make it start at
                    # the case we want to jump to, and end at the start of the next
                    # CodeBlock after it.
                    new_case_bi = jump_to_case.byte_interval
                    new_case_offset = code_start.offset + jt_offset*4
                    new_case_size = 0
                    for cb in sorted(module.code_blocks, key=lambda e: e.address):
                        if cb.address > case_addr:
                            new_case_size = cb.address - case_addr
                            break
                    case = CodeBlock(byte_interval=new_case_bi, offset=new_case_offset, size=new_case_size)
                    new_case_bi.blocks.add(case)

                if case:
                    # Add incoming edge to case
                    ir.cfg.add(Edge(jump_to_case, case))

                # Create symbol and randomly generate name
                case_sym = Symbol(sym_name, uuid.uuid4(), case, False, module)
                module.symbols.add(case_sym)

                # Add symbolic expression to jump table (to reference distance from case instead of just storing bytes)
                bi.symbolic_expressions[current_offset] = SymAddrAddr(4, 0, case_sym, code_start_sym)

                # Add the size of the symbolic expression here
                sym_expr_sizes[Offset(element_id=bi, displacement=current_offset)] = entry_s
                current_offset += entry_s

        if fixed:
            corrected += 1

    if corrected > 1:
        log.info(f"Corrected {corrected} jump tables.")
    if corrected == 1:
        log.info(f"Corrected 1 jump table.")

    return switches

def find_asm_subsequence(sequence: list[str], sub: list[str]) -> list[int]:
    '''
    Find first asm subsequence and return list of indices matched
    
    :param sequence: List of asm to look through
    :param sub: Subsequence to find
    :returns: list of matched indices
    '''
    indices = []
    j = 0

    for i, element in enumerate(sequence):
        if split_asm(element) == split_asm(sub[j]):
            indices.append(i)
            j += 1
        if j == len(sub):
            break

    return indices if j == len(sub) else []


def expand_arm64_switches(asm_f: str, switches: list[SwitchData]):
    '''
    Switches with byte or short jump tables won't be able to deal
    with lots of extra code within the switch cases (as the entries won't be
    big enough enough to store the difference between the base and the case
    anymore). "Upgrade" these tables and switches to 4-byte entries.

    We perform this on the generated assembly as it is much easier than
    modifying the IR to do the same, as we would have to increase the size of
    the switch jump table Datablock, offset DataBlocks below it, and update
    offsets of symbolic expressions / symbols / whatever referencing the shifted 
    DataBlocks. Whereas in asm we can simply switch the .byte to .word and
    update

    :param asm_f: Assembly file to modify.
    :param switches: Information about the switches within the assembly
    '''

    asm = []
    strip_asm = []
    with open(asm_f) as f:
        for l in f:
            strip_asm.append(l.strip())
            asm.append(l)

    # First upgrade LDR instructions. 
    # This could be more efficient, as we we traverse the asm len(switches)
    # times to find the LDR instructions, when we could maybe just traverse it
    # once
    num_expanded = 0
    for switch in switches:
        # Skip if jump table entries already 4 bytes
        if switch.jt_entry_size == 4:
            continue

        # Find and upgrade switch instructions
        match = find_asm_subsequence(strip_asm, switch.matched_instructions)
        if len(match) == 0:
            log.warning(f"Could not find ldr instruction for switch {switch.jt_label} to expand!")
            continue

        # Upgrade ldr to 4 byte load
        ldr = ''
        shift = ''
        if switch.jt_entry_size == 1:
            ldr = 'ldrb'
            shift = 'uxtw'
        elif switch.jt_entry_size == 2:
            ldr = 'ldrh'
            shift = 'uxtw #1'
        ldr_index = match[2]
        asm[ldr_index] = asm[ldr_index].replace(ldr, 'ldr').replace(shift, 'uxtw #2')
        num_expanded += 1

    # Now upgrade jump table entries (in one run)
    switch_map = {}
    for switch in switches:
        switch_map[switch.jt_label] = switch

    # Find jump table entries and upgrade them
    num_jump_tables_expanded = 0
    i = 0
    while i < len(asm):
        x = asm[i]
        if x.strip()[:-1] in switch_map:
            switch = switch_map[x.strip()[:-1]]
            curr = ''
            if switch.jt_entry_size == 1:
                curr = '.byte'
            elif switch.jt_entry_size == 2:
                curr = '.short'
            else:
                i += 1
                continue

            i += 1
            while i < len(strip_asm):
                entry = strip_asm[i]
                if entry.startswith(curr):
                    asm[i] = asm[i].replace(curr, '.long')
                elif entry.startswith('.L_') or entry.startswith("#="):
                    i -= 1
                    break
                else:
                    log.warning(f'Jump table {switch.jt_label} terminated with unexpected entry "{entry}"')
                    i -= 1
                    break
                i += 1
            num_jump_tables_expanded += 1
        i += 1

    if num_expanded != num_jump_tables_expanded:
        log.warning(f"Expanded {num_expanded} ldr instructions and {num_jump_tables_expanded} jump tables ... these numbers should be equal")

    if num_expanded > 1:
        log.info(f"Expanded {num_expanded} jump tables.")
    if num_expanded == 1:
        log.info(f"Expanded 1 jump table.")

    # Write back switch-expanded asm
    with open(asm_f, 'w') as f:
        for l in asm:
            f.write(l)
