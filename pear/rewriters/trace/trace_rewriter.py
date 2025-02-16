# pyright: reportAttributeAccessIssue=false

import os
import json
import uuid
import shutil
import logging
import argparse
import textwrap
import importlib
import dataclasses

from collections import OrderedDict
from dataclasses import dataclass
from functools import partial
from typing import Optional

import gtirb
import gtirb_functions

from capstone_gt import CsInsn
from gtirb import CodeBlock
from gtirb_functions import Function
from gtirb_rewriting import (
    Pass,
    Patch,
    X86Syntax,
    Constraints,
    PassManager,
    BlockPosition,
    SingleBlockScope
)
from gtirb_capstone.instructions import GtirbInstructionDecoder

import gtirb_rewriting._auxdata as _auxdata

from ... import DUMMY_LIB_NAME
from ... import utils
from ...utils import run_cmd, get_codeblock_to_address_mappings, align_section
from ...arch_utils.linux_utils import LinuxUtils, LinuxX64Utils, LinuxARM64Utils, SwitchData
from ..rewriter import Rewriter

COV_FILE_PREFIX_LABEL = 'cov_file_prefix'

log = logging.getLogger(__name__)

@dataclass
class BasicBlockInfo:
    id: int                   # numerical ID
    start_address: int        # start execution address of block
    inst_offset: int          # offset from start of block to instrument
    size: int                 # size of block
    str_repr: str             # string disassembly of block

class TraceRewriter(Rewriter):
    """
    This class implements tracing instrumentation on Linux binaries.
    """
    @staticmethod
    def build_parser(parser: argparse._SubParsersAction):
        parser = parser.add_parser(TraceRewriter.name(),
                                   description= "Add tracing instrumentation to Linux binaries.",
                                   help='Add coverage instrumentation')
        parser.add_argument(
            '--print-execution', action='store_true', required=False,
            help=textwrap.dedent('''\
                Instrument binary to print the instructions it is executing.
                (Use --add-coverage instead, which provides this and more)
             ''')
        )

        parser.add_argument(
            '--add-coverage', action='store_true', required=False,
            help=textwrap.dedent('''\
                Instrument binary with tracing instrumentation to generate
                coverage output on runs.
             ''')
        )

        parser.add_argument(
            '--fast', action='store_true', required=False,
            help=textwrap.dedent('''\
                Use fast tracing instrumentation, but may have data loss if
                program abnormally terminates.
             ''')
        )

        parser.add_argument(
            '--slow', action='store_true', required=False,
            help=textwrap.dedent('''\
                Use slow tracing instrumentation which may log more information
                if the program abnormally terminates.
             ''')
        )

    @staticmethod
    def name():
        return 'Trace'

    def __init__(self, ir: gtirb.IR, args: argparse.Namespace,
                 mappings: OrderedDict[int, uuid.UUID], dry_run: bool):
        assert len(mappings) < (1 << 32), "Too many basic blocks!"
        assert len(ir.modules) == 1, "Only support 1 module"

        assert (args.add_coverage or args.print_execution) and not (args.add_coverage and args.print_execution), \
            "Select either --add-coverage or --print-execution, but not both."

        self.add_coverage = args.add_coverage
        self.print_execution = args.print_execution

        if self.add_coverage:
            assert (args.fast or args.slow) and not (args.fast and args.slow),\
                    "Select either fast or slow tracing instrumentation."

        self.fast = args.fast
        self.slow = args.slow

        self.ir = ir
        self.dry_run = dry_run
        self.module = ir.modules[0]
        self.isa = self.module.isa
        self.addr_to_codeblock = mappings
        self.codeblock_to_addr: OrderedDict[uuid.UUID, int] = get_codeblock_to_address_mappings(ir)
        self.decoder = GtirbInstructionDecoder(ir.modules[0].isa)

    def get_block_asm(self, 
                      func_map: dict[CodeBlock, str],
                      multi_entry_func_map: list[tuple[list[CodeBlock], str]],
                      start_addr: int, ins: list[CsInsn], cb: CodeBlock) -> str:
        """ Return dissasembly string of a CodeBlock """

        func_name = ''
        if cb in func_map:
            func_name = func_map[cb]
        else:
            for entries, name in multi_entry_func_map:
                if cb in entries:
                    func_name = name
                    break
        if func_name != '':
            func_name += ':\n'

        str_ins = func_name
        addr = start_addr
        for i in ins:
            str_ins += f"{hex(addr)}: {i.insn_name()} {i.op_str}\n"
            addr += i.size
        return str_ins

    def rewrite(self) -> gtirb.IR:
        # get functions
        functions: list[Function] = []
        has_functions = _auxdata.function_entries.exists(self.module) \
            and _auxdata.function_blocks.exists(self.module)
        if has_functions:
            functions = gtirb_functions.Function.build_functions(self.module)

        func_map: dict[CodeBlock, str] = {}
        multi_entry_func_map: list[tuple[list[CodeBlock], str]] = []
        for func in functions:
            if len(func.get_entry_blocks()) > 1:
                multi_entry_func_map.append((list(func.get_entry_blocks()), func.get_name()))
            else:
                func_map[func.get_entry_blocks().pop()] = func.get_name()

        # create mapping between codeblock and block info
        cov_mapping: dict[CodeBlock, BasicBlockInfo] = {}
        curr_id = 0
        for cb in self.ir.modules[0].code_blocks:
            if cb.size == 0:
                continue
            ins = list(self.decoder.get_instructions(cb))

            start_address = self.codeblock_to_addr[cb.uuid]
            # We add our instrumentation before the last instruction of the block
            inst_offset = 0
            for x in ins[:-1]:
                inst_offset += x.size

            block = BasicBlockInfo(
                id = curr_id,
                start_address = start_address,
                inst_offset = inst_offset,
                size = cb.size,
                str_repr = self.get_block_asm(func_map, multi_entry_func_map, start_address, ins, cb)
            )
            cov_mapping[cb] = block
            curr_id += 1

        self.cov_mapping = cov_mapping

        passes = []
        if self.print_execution:
            passes = [AddExecutionPrinting(cov_mapping)]
        if self.add_coverage:
            passes = [AddCoverageData(cov_mapping), AddCoverage(cov_mapping, self.fast, self.slow)]

        for p in passes:
            manager = PassManager()
            manager.add(p)
            manager.run(self.ir)

        return self.ir

    def generate(self, output: str, working_dir: str, *args,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False,
                 switch_data: Optional[list[SwitchData]]=None,
                 **kwargs):
        if self.print_execution:
            LinuxUtils.generate(output, working_dir, self.ir,
                                gen_assembly=gen_assembly,
                                gen_binary=gen_binary, obj_link=None,
                                switch_data=switch_data)
            return

        # Build the instrumentation object
        folder_name = 'instrumentation'
        orig_src = importlib.resources.files(__package__) / folder_name
        build_dir = os.path.join(working_dir, folder_name)
        shutil.copytree(orig_src, build_dir, dirs_exist_ok=True)
        obj_src_path = os.path.join(build_dir, 'coverage.c')
        static_obj_fname = 'coverage.o'
        static_obj_path = os.path.join(working_dir, static_obj_fname)
        cmd = ['gcc', '-c', '-o', static_obj_path, obj_src_path]
        run_cmd(cmd)

        # Get external symbols from this object
        symbols = []
        if not self.dry_run:
            symbols = utils.get_symbols_from_file(static_obj_path, working_dir)
        else:
            symbols = ['close', 'track_cov_fast', COV_FILE_PREFIX_LABEL, 'exit',
                       'snprintf', 'track_cov_slow', 'fd', 'write', 'getpid',
                       'printf', 'cov_file', 'open', 'is_setup']
            log.warning('Using cached symbols from coverage object as we are doing dry run')

        # Add symbols to the IR
        utils.add_symbols_to_ir(symbols, self.ir)

        # Build binary, linking instrumentation object
        to_link = [static_obj_fname]
        # if self.isa == gtirb.Module.ISA.X64:
        LinuxUtils.generate(output, working_dir, self.ir,
                            gen_assembly=gen_assembly,
                            gen_binary=gen_binary, obj_link=to_link,
                            switch_data=switch_data)

        # Dump basic block info (inefficient!)
        out = []
        for x in self.cov_mapping.values():
            out.append(dataclasses.asdict(x))
        bbinfo_dump = f'{output}.basicblockinfo.json'
        with open(bbinfo_dump, 'w') as f:
            json.dump(out, f)
        log.info(f'Auxillary information saved to: {bbinfo_dump}')

class AddExecutionPrinting(Pass):
    '''
    Instrument binary to print the disassembly of the instructions it executes
    as it executes them.
    '''
    def __init__(self, cov_mapping: dict[CodeBlock, BasicBlockInfo]):
        super().__init__()
        self.cov_mapping = cov_mapping

    def begin_module(self, module, functions, rewriting_ctx):
        # insert printf as dependent symbol
        rewriting_ctx.get_or_insert_extern_symbol('printf', 'libc.so.6')
        log.info(f"Instrumenting {len(self.cov_mapping)} blocks ..")

        is_x64 = module.isa == gtirb.Module.ISA.X64
        is_arm64 = module.isa == gtirb.Module.ISA.ARM64

        for cb, bbinfo in self.cov_mapping.items():
            to_print = bbinfo.str_repr + "\n"
            padding = 16 - (len(to_print) % 16)
            patch = None

            if is_x64:
                patch = Patch.from_function(
                    partial(
                        lambda p_str, padding, _:
                            LinuxX64Utils.call_function('printf', 
                                 pre_call='lea rdi,[rip + .Linsns]',
                                 data=f'''
                                     .rodata
                                     .align 2
                                     .Linsns:
                                         .string "{p_str}"
                                     .space {padding}
                            '''),
                    to_print, padding),
                    Constraints(x86_syntax=X86Syntax.INTEL)
                )
            if is_arm64:
                patch = Patch.from_function(
                    partial(
                        lambda p_str, padding, _:
                            LinuxARM64Utils.call_function('printf', 
                                 pre_call=f'''
                                     # far-away load into x0
                                     adrp x0, .Linsns
                                     add x0, x0, :lo12:.Linsns
                                     ''',
                                 data=f'''
                                     .rodata
                                     .align 2
                                     .Linsns:
                                         .string "{p_str}"
                                     .space {padding}
                            '''),
                    to_print, padding),
                    Constraints(x86_syntax=X86Syntax.INTEL)
                )
            assert patch != None, "unknown ISA"
            rewriting_ctx.insert_at(
                cb,
                bbinfo.inst_offset,
                patch
            )

        # Make sure original program data is aligned
        align_section(module, '.rodata', balign=16)

class AddCoverageData(Pass):
    '''
    Add id in program data for ARM64 programs as the id may be too big to load
    as an immediate.
    '''
    def __init__(self, cov_mapping: dict[CodeBlock, BasicBlockInfo]):
        self.cov_mapping = cov_mapping

    def begin_module(self, module, functions, rewriting_ctx):
        if module.isa != gtirb.Module.ISA.ARM64:
            return

        # gtirb patches must have at least one instruction in them
        id_insert = 'nop\n.section .data\n'
        for bbi in self.cov_mapping.values():
            id = bbi.id
            id_insert += f'.align 2\nbbinfo_id_{id}: .long {id}\n'
        rewriting_ctx.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(lambda _: id_insert, Constraints())
        )

        align_section(module, '.data', balign=16)


class AddCoverage(Pass):
    def __init__(self, cov_mapping: dict[CodeBlock, BasicBlockInfo],
                 fast: bool, slow: bool):
        super().__init__()
        self.cov_mapping = cov_mapping
        self.fast = fast
        self.slow = slow

    def begin_module(self, module, functions, rewriting_ctx):
        # This function will be in an object we create
        rewriting_ctx.get_or_insert_extern_symbol('track_cov_fast', DUMMY_LIB_NAME)
        rewriting_ctx.get_or_insert_extern_symbol('track_cov_slow', DUMMY_LIB_NAME)
        
        is_x64 = module.isa == gtirb.Module.ISA.X64
        is_arm64 = module.isa == gtirb.Module.ISA.ARM64

        trace_func = ''
        if self.fast:
            trace_func = 'track_cov_fast'
        elif self.slow:
            trace_func = 'track_cov_slow'
        assert trace_func != '', "Must choose fast or slow tracing"

        # Add coverage tracers
        log.info(f"Instrumenting {len(self.cov_mapping)} blocks ...")
        for cb, bbinfo in self.cov_mapping.items():
            patch = None
            if is_x64:
                patch = Patch.from_function(
                    partial(
                        lambda id, _:
                            LinuxX64Utils.call_function(trace_func,
                                                     pre_call=f'mov rdi, {id}'),
                    bbinfo.id),
                    Constraints(x86_syntax=X86Syntax.INTEL)
                )
            elif is_arm64:
                patch = Patch.from_function(
                    partial(
                        lambda id, _:
                            LinuxARM64Utils.call_function(trace_func,
                                                     pre_call=f'''
                                                     # far-away load into x0
                                                     adrp x0, bbinfo_id_{id}
                                                     add x0, x0, :lo12:bbinfo_id_{id}
                                                     ldr x0, [x0]
                                                     '''),
                    bbinfo.id),
                    Constraints(x86_syntax=X86Syntax.INTEL)
                )
            assert patch != None, "unknown ISA"
            rewriting_ctx.insert_at(
                cb,
                bbinfo.inst_offset,
                patch
            )

        # Add coverage file prefix (we add after coverage, as otherwise it
        # screws up the CodeBlock alignment somehow and gtirb refuses to let us
        # at the tracing calls, claiming we are trying to insert inside an
        # existing instruction.
        cov_file_prefix = module.name
        padding = 16 - (len(cov_file_prefix) % 16)
        assert module.entry_point != None, "Cannot find entrypoint!"
        rewriting_ctx.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(lambda _:f'''
                nop

                .section .data
                .globl {COV_FILE_PREFIX_LABEL}
                {COV_FILE_PREFIX_LABEL}:
                    .string "{cov_file_prefix}"
                .space {padding}
            ''', Constraints())
        )

        # Make sure original program data is aligned
        align_section(module, '.data', balign=16)
