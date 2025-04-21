# pyright: reportAttributeAccessIssue=false

import os
import json
import uuid
import random
import shutil
import pathlib
import logging
import argparse
import textwrap
import tempfile
import importlib

from collections import OrderedDict
from functools import partial
from typing import Optional

import gtirb
from gtirb_rewriting import (
    Pass,
    Patch,
    X86Syntax,
    Constraints,
    PassManager,
    BlockPosition,
    SingleBlockScope
)
import gtirb_rewriting._auxdata as _auxdata
from gtirb_capstone.instructions import GtirbInstructionDecoder

from ... import utils 
from ... import DUMMY_LIB_NAME
from ...utils import run_cmd, get_codeblock_to_address_mappings, align_section
from ...arch_utils.linux_utils import LinuxUtils, LinuxX64Utils, LinuxARM64Utils, SwitchData
from ...arch_utils.windows_utils import (WindowsUtils, WindowsX64Utils, WindowsX86Utils)

from ..rewriter import Rewriter

log = logging.getLogger(__name__)

AFL_TRACE_FUNC = '__afl_trace'
REG_BACKUP_LABEL = '__reg_backup'
PERS_FUNC_BACKUP_LABEL = '__persistent_ret_backup'
PERS_FIRST_PASS_LABEL = '__first_pass'

class AFLPlusPlusRewriter(Rewriter):
    """
    This class implements AFL++ instrumentation on x64 Linux binaries.
    """
    @staticmethod
    def get_description():
        return textwrap.dedent('''\
            Add AFL++ instrumentation to 64-bit Linux binaries.
            By default, starts fuzzing at binary entrypoint. To select a better location,
            use --deferred-fuzz-address/--deferred-fuzz-function.

            By default, a new binary will be spun up for every test. To repeatedly call one
            function for each fuzzing test, see the persistent mode flags. 

            By default, AFL++ relies on file IO to send testcases. To use shared memory to
            send testcases instead, use the sharedmem flags. In most cases, the sharedmem
            call location should be the same as the deferred fuzz / persistent mode
            location.

            See the tests within PeAR for AFL++ rewriter for example usage.
        ''')

    @staticmethod
    def build_parser(parser: argparse._SubParsersAction):
        parser = parser.add_parser(AFLPlusPlusRewriter.name(),
                                   description=AFLPlusPlusRewriter.get_description(),
                                   formatter_class=argparse.RawTextHelpFormatter,
                                   help='Add AFL++ instrumentation')

        def is_hex_address(loc):
            try:
                return int(loc, 16)
            except ValueError:
                parser.error(f'Can\'t parse "{loc}" as address, please provide hex address (e.g. 0x75a0)')

        def path_exists(f):
            if not pathlib.Path(f).exists():
                parser.error(f'File "{f}" not found')
            else:
                return f

        # Inlined tracing (no point in allowing the option, it is slower)
        # parser.add_argument(
        #     '--inlined-tracing', default=False, action='store_true', required=False,
        #     help=textwrap.dedent('''\
        #         Use inline tracing. Makes binary bigger and a bit slower. Don't
        #         use this. Default: false
        #     ''')
        # )

        # never zero counters
        parser.add_argument(
            '--never-zero', default=False, action='store_true', required=False,
            help=textwrap.dedent('''\
                If set, counters will be set to 1 when overflowed (instead of 
                zero, which AFL sees as no coverage has been achieved on that
                tuple). Default: False
            ''')
        )

        # Deferred initialisation 
        parser.add_argument(
            '--deferred-fuzz-address', required=False, type=is_hex_address,
            help="Address to start fuzzing test runs (i.e initialise forkserver)"
        )
        parser.add_argument(
            '--deferred-fuzz-function', required=False,
            help="Function to start fuzzing test runs (i.e initialise forkserver)"
        )

        # Persistent mode
        parser.add_argument(
            '--persistent-mode-address', required=False, type=is_hex_address,
            help='Address of function for persistent mode (repeatedly called for each fuzzing test).'
        )
        parser.add_argument(
            '--persistent-mode-function', required=False,
            help='Function for persistent mode (repeatedly called for each fuzzing test)'
        )
        parser.add_argument(
            '--persistent-mode-count', type=int, default=10000, required=False,
            help="Number of times to call function before forking a new test binary. Default: 10000"
        )

        # Sharedmem fuzzing
        parser.add_argument(
            '--sharedmem-call-address', required=False, type=is_hex_address,
            help="Address to insert a call to the sharedmem hook"
        )
        parser.add_argument(
            '--sharedmem-call-function', required=False,
            help="Function to insert a call to the sharedmem hook (at func start)"
        )
        parser.add_argument(
            '--sharedmem-obj', required=False, type=path_exists,
            help="Object containing sharedmem hook. Should be output of: gcc -c custom_hook.c"
        )
        parser.add_argument(
            '--sharedmem-hook-func-name', required=False,
            default='__pear_sharedmem_hook',
            help="Name of function to be called as sharedmem hook. Default: '__pear_sharedmem_hook'"
        )

    @staticmethod
    def name():
        return 'AFL++'

    def __init__(self, ir: gtirb.IR, args: argparse.Namespace,
                 mappings: OrderedDict[int, uuid.UUID], dry_run: bool):
        assert len(ir.modules) == 1, "Only support 1 module"

        self.ir = ir
        self.dry_run = dry_run
        self.module = ir.modules[0]
        self.addr_cb_map = mappings

        # self.inline: bool = args.inlined_tracing
        self.inline: bool = False
        self.never_zero: bool = args.never_zero

        self.pers_mode_cnt: int | None = args.persistent_mode_count
        self.shmem_hook_name: str | None = args.sharedmem_hook_func_name
        self.shmem_hook_obj: str | None = args.sharedmem_obj
        if self.shmem_hook_obj:
            with tempfile.TemporaryDirectory() as tmp:
                symbols = utils.get_symbols_from_file(self.shmem_hook_obj, tmp)
            assert self.shmem_hook_name in symbols, f"Could not find symbol {self.shmem_hook_name} in object {self.shmem_hook_obj}!"

        self.def_fuzz_addr: int | None = args.deferred_fuzz_address
        self.pers_mode_addr: int | None = args.persistent_mode_address
        self.shmem_call_addr: int | None  = args.sharedmem_call_address
        # Convert given function names to addresses
        for f_id, entryBlocks in self.module.aux_data["functionEntries"].data.items():
            name_sym: gtirb.Symbol = self.module.aux_data["functionNames"].data[f_id]
            e = entryBlocks.pop()
            if name_sym.name == args.deferred_fuzz_function:
                self.def_fuzz_addr = e.address
            if name_sym.name == args.persistent_mode_function:
                self.pers_mode_addr = e.address
            if name_sym.name == args.sharedmem_call_function:
                self.shmem_call_addr = e.address

    def rewrite(self) -> gtirb.IR:
        if self.shmem_hook_name:
            utils.add_symbols_to_ir([self.shmem_hook_name], self.ir)
        passes = [
            # Data must be added in a seperate pass before it can be referenced
            # in other passes.
            AddAFLPlusPlusDataPass(
                is_persistent=True if self.pers_mode_addr else False,
                is_deferred=True if self.def_fuzz_addr else False,
                is_sharedmem_fuzzing=True if self.shmem_call_addr else False),
            AddAFLPlusPlusPass(
                self.inline,
                self.never_zero,
                self.addr_cb_map,
                self.def_fuzz_addr,
                self.pers_mode_addr,
                self.pers_mode_cnt,
                self.shmem_call_addr,
                self.shmem_hook_name)
        ]
        # gtirb-rewriting's pass manager is bugged and can only handle running
        # one pass at a time.
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
        # build instrumentation object
        folder_name = 'instrumentation'
        orig_src = importlib.resources.files(__package__) / folder_name
        build_dir = os.path.join(working_dir, folder_name)
        shutil.copytree(orig_src, build_dir, dirs_exist_ok=True)
        obj_src_path = os.path.join(build_dir, 'afl-instrumentation.c')
        static_obj_fname = 'instrumentation.o'
        static_obj_path = os.path.join(working_dir, static_obj_fname)
        cmd = ['gcc', '-c', '-o', static_obj_path, obj_src_path]
        run_cmd(cmd)

        if self.dry_run:
            raise NotImplementedError
        symbols = utils.get_symbols_from_file(static_obj_path, working_dir)
        if self.shmem_hook_obj:
            symbols += utils.get_symbols_from_file(self.shmem_hook_obj, working_dir)
        utils.add_symbols_to_ir(symbols, self.ir)

        to_link = [static_obj_fname]
        if self.shmem_hook_obj:
            hook = os.path.basename(self.shmem_hook_obj)
            shutil.copyfile(self.shmem_hook_obj, os.path.join(working_dir, hook))
            to_link.append(hook)

        LinuxUtils.generate(output, working_dir, self.ir,
                            gen_assembly=gen_assembly,
                            gen_binary=gen_binary, obj_link=to_link,
                            switch_data=switch_data)

class AddAFLPlusPlusDataPass(Pass):
    """
    Add data (global variables) needed for AFL instrumentation to binary
    """
    def __init__(self, is_persistent=False, is_deferred=False, is_sharedmem_fuzzing=False):
        super().__init__()
        self.is_persistent = is_persistent
        self.is_deferred = is_deferred
        self.is_sharedmem_fuzzing = is_sharedmem_fuzzing

    def begin_module(self, module, functions, rewriting_ctx):
        # AFL searches the binaries for these signatures
        persistent_mode_sig = ""
        if self.is_persistent:
            persistent_mode_sig = """
                .PERSISTENT_MODE_SIGNATURE:
                    .string "##SIG_AFL_PERSISTENT##"
                    .space 9
            """

        deferred_initialisation_sig = ""
        if self.is_deferred:
            deferred_initialisation_sig = """
                .DEFERRED_INITIALISATION_SIGNATURE:
                    .string "##SIG_AFL_DEFER_FORKSRV##"
                    .space 6
            """

        rewriting_ctx.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(lambda _:f'''
                # GTIRB patches must have at least one basic block
                nop

                .data
                # Globals used by instrumentation object and patches
                #   tracing
                .globl __afl_area_ptr
                __afl_area_ptr:   .quad 0
                .globl __afl_prev_loc
                __afl_prev_loc:   .quad 0

                #   shared memory fuzzing
                .globl __afl_sharedmem_fuzzing
                __afl_sharedmem_fuzzing: .quad {1 if self.is_sharedmem_fuzzing else 0}
                .globl __afl_fuzz_len
                __afl_fuzz_len: .quad 0
                .globl __afl_fuzz_ptr
                __afl_fuzz_ptr: .quad 0

                .globl __afl_is_persistent
                __afl_is_persistent: .byte {1 if self.is_persistent else 0}
                .space 7

                # Data used by persistent mode patch / sharedmem hook
                {REG_BACKUP_LABEL}: .space 0x170
                {PERS_FUNC_BACKUP_LABEL}: .quad 0
                {PERS_FIRST_PASS_LABEL}: .byte 1
                .space 7

                .rodata
                .space 16
                # Signatures used by afl-fuzz to detect features
                {persistent_mode_sig}
                {deferred_initialisation_sig}
            ''', Constraints(x86_syntax=X86Syntax.INTEL))
        )

        align_section(module, '.data', balign=16)
        align_section(module, '.rodata', balign=16)

class AddAFLPlusPlusPass(Pass):
    """
    Add AFL++ instrumentation to x64 binaries.
    """
    def __init__(self, inline_tracing: bool, never_zero: bool,
                 addr_cb_map: OrderedDict[int, uuid.UUID],
                 def_fuzz_addr: Optional[int],
                 pers_mode_addr: Optional[int],
                 pers_mode_cnt: Optional[int],
                 shmem_call_addr: Optional[int],
                 shmem_hook_name: Optional[str]
                 ):
        super().__init__()
        self.inline_tracing = inline_tracing
        self.never_zero = never_zero
        self.addr_cb_map: OrderedDict[int, uuid.UUID] = addr_cb_map
        self.init_forkserver: int = def_fuzz_addr
        self.pers_mode: int = pers_mode_addr
        self.pers_mode_cnt: int = pers_mode_cnt
        self.shmem_call_addr: int = shmem_call_addr
        self.shmem_hook_name: str = shmem_hook_name
        if not def_fuzz_addr:
            log.warning("No deferred fuzzing location; initialising at program entrypoint."
                        " For faster fuzzing, specify an initialisation point.")

    @staticmethod
    def trace_asm(block_id: int, inline: bool, never_zero: bool = False) -> str:
        '''
        Tracing asm.
        :param inline: should the trace be inlined
        :param never_zero: if inlined, should counter wrap to 1 instead of 0
        :param block_id: unique ID of block patch is being generated for
        '''
        trace = f'call {AFL_TRACE_FUNC}'
        if inline:
            trace = AddAFLPlusPlusPass.tracing_asm(inline=True, never_zero=never_zero)
        return f'''
            # Using lea + mov as it might be faster than consecutive pushes
            # Subtract stack past red-zone (keep it unmodified)
            # red zone = 128 = 0x80. we push two registers, so sub 0x90
            lea rsp,[rsp-0x90]
            mov qword ptr [rsp], rcx
            mov qword ptr [rsp+0x8], rax # rax clobbered by lahf inside func

            mov rcx, {hex(block_id)}
            {trace}

            mov rax, qword ptr [rsp+0x8]
            mov rcx, qword ptr [rsp]
            lea rsp, [rsp+0x90]
        '''

    @staticmethod
    def trace_func_asm(never_zero: bool = False) -> str:
        return AddAFLPlusPlusPass.tracing_asm(inline=False, never_zero=never_zero)

    @staticmethod
    def tracing_asm(inline: bool = False, never_zero: bool = False) -> str:
        '''
        Tracing code
        Heavily inspired via afl-as assembly patches. 
        Small tweak to remove rdx dependency (makes it very slightly faster)
        See insp here: https://github.com/mirrorer/afl/blob/master/afl-as.h
        :param inline: if not inline, will add ret at end
        :param never_zero: if counters should wrap to 1 instead of 0
        '''
        inc_counter = 'inc byte ptr [rcx]'
        if never_zero:
            inc_counter = textwrap.dedent('''\
                add byte ptr [rcx], 0x1
                adc byte ptr [rcx], 0x0 # map[index] = 1 on overflow
            ''')
        ret = '' if inline else 'ret' 
        return f'''
            # Store flags on stack (faster than pushf)
            lahf
            seto al
            
            xor rcx, qword ptr [rip + __afl_prev_loc]       # rcx = curr_loc ^ prev_loc 
            xor qword ptr [rip + __afl_prev_loc], rcx       # prev_loc = curr_loc
            shr qword ptr [rip + __afl_prev_loc], 1         # prev_loc = curr_loc >> 1
            add rcx, qword ptr [rip + __afl_area_ptr]       # rcx = __afl_area_ptr[curr_loc ^ prev_loc]
            {inc_counter}                                   # __afl_area_ptr[curr_loc ^ prev_loc]++
            
            # Return
            add al,0x7f
            sahf
            {ret}
        '''

    def call_sharedmem_hook(self):
        '''
        Call sharedmem hook after stack alignment
        '''
        return f'''
            # stack align
            mov     rcx, rsp
            lea     rsp, [rsp - 0x80]
            and     rsp, 0xfffffffffffffff0
            push    rcx
            push    rcx

            # arg 1: saved registers
            lea rdi, [rip+{REG_BACKUP_LABEL}]

            # arg 2: testcase pointer
            mov rsi, [rip+__afl_fuzz_ptr]

            # arg 3: testcase length
            mov rax, [rip+__afl_fuzz_len]
            mov edx, [rax]
            call {self.shmem_hook_name}

            pop     rcx
            mov     rsp, rcx
        '''

    def persistent_patch(self, call_shmem_hook: bool=False) -> Patch:
        '''
        Patch to insert in front of a function to repeatedly fuzz it.
        '''
        backup_regs = LinuxX64Utils.backup_registers(REG_BACKUP_LABEL)
        restore_regs = LinuxX64Utils.restore_registers(REG_BACKUP_LABEL)
        sharedmem_hook_call = ''
        if call_shmem_hook:
            sharedmem_hook_call = self.call_sharedmem_hook()

        persistent_mode_patch = Patch.from_function(lambda _: f'''
            # Backup all original registers
            {backup_regs}

            # Start of persistent loop
            .Lsetup_loop:

            movzx eax, BYTE PTR {PERS_FIRST_PASS_LABEL}[rip]
            test al, al
            je .Lnot_first_pass
            # On first pass, save and overwrite legitimate return address
            pop rax
            mov QWORD PTR [rip+{PERS_FUNC_BACKUP_LABEL}], rax
            mov BYTE PTR [rip+{PERS_FIRST_PASS_LABEL}], 0

            .Lnot_first_pass:
            # On subsequent passes, we push return address on stack to
            # emulate function call
            lea rax, [rip+.Lsetup_loop]
            push rax

            # Check whether to continue loop or not
            mov     rcx, rsp
            lea     rsp, [rsp - 0x80]
            and     rsp, 0xfffffffffffffff0
            push    rcx
            push    rcx

            mov edi, {hex(self.pers_mode_cnt)}
            call __afl_persistent_loop

            pop     rcx
            mov     rsp, rcx
           
            test eax,eax
            jne .Lstart_func

            # To break loop, restore original return address, restore registers and ret
            mov rax, QWORD PTR [rip+{PERS_FUNC_BACKUP_LABEL}]
            lea rsp,[rsp+0x8]
            push rax

            {restore_regs}
            ret

            .Lstart_func:
            # Before starting loop, call sharedmem hook if needed and restore registers
            {sharedmem_hook_call}
            {restore_regs}
        ''', Constraints(x86_syntax=X86Syntax.INTEL))
        return persistent_mode_patch

    def begin_module(self, module, functions, rewriting_ctx):
        assert module.entry_point != None, "cannot find entrypoint"

        if not self.init_forkserver:
            self.init_forkserver = module.entry_point.address

        rewriting_ctx.get_or_insert_extern_symbol('__afl_setup', DUMMY_LIB_NAME)
        rewriting_ctx.get_or_insert_extern_symbol('__afl_start_forkserver', DUMMY_LIB_NAME)
        rewriting_ctx.get_or_insert_extern_symbol('__afl_persistent_loop', DUMMY_LIB_NAME)

        # Call AFL setup at entrypoint
        # This attaches to AFL shared memory and does other init stuff
        rewriting_ctx.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(
                lambda _: LinuxX64Utils.call_function('__afl_setup'),
                Constraints(x86_syntax=X86Syntax.INTEL)
            )
        )

        # Init forkserver
        utils.insert_patch_at_address(
            self.init_forkserver,
            Patch.from_function(
                lambda _: LinuxX64Utils.call_function('__afl_start_forkserver'),
                Constraints(x86_syntax=X86Syntax.INTEL)
            ),
            self.addr_cb_map,
            rewriting_ctx
        )

        # Insert trace function
        if not self.inline_tracing:
            rewriting_ctx.register_insert_function(
                AFL_TRACE_FUNC,
                Patch.from_function(
                    partial (
                        lambda nz, _: AddAFLPlusPlusPass.trace_func_asm(nz),
                    self.never_zero),
                    Constraints(x86_syntax=X86Syntax.INTEL)
                )
            )

        # Insert tracing at each each basic block
        instr_count = 0
        for func in functions:
            blocks = utils.get_basic_blocks(func)
            for blocklist in blocks:
                block_id = random.getrandbits(16)
                # create trace patch
                rewriting_ctx.register_insert(
                    SingleBlockScope(blocklist[0], BlockPosition.ENTRY),
                    Patch.from_function(
                        partial(
                            lambda id, it, nz, _: AddAFLPlusPlusPass.trace_asm(id, it, nz),
                        block_id, self.inline_tracing, self.never_zero),
                        Constraints(x86_syntax=X86Syntax.INTEL)
                    )
                )
                instr_count += 1

        call_shm_hook_in_pers = self.shmem_call_addr and self.shmem_call_addr == self.pers_mode

        # Add persistent mode patch + sharedmem hook if required
        if self.pers_mode:
            utils.insert_patch_at_address(
                self.pers_mode,
                self.persistent_patch(call_shmem_hook=call_shm_hook_in_pers),
                self.addr_cb_map,
                rewriting_ctx
            )

        if self.shmem_call_addr and not call_shm_hook_in_pers:
            # sharedmem hook is not being used with persistent mode
            # insert it seperately
            utils.insert_patch_at_address(
                self.shmem_call_addr,
                Patch.from_function(lambda _: f'''
                    {LinuxX64Utils.backup_registers(REG_BACKUP_LABEL)}
                    {self.call_sharedmem_hook()}
                    {LinuxX64Utils.restore_registers(REG_BACKUP_LABEL)}
                ''', Constraints(x86_syntax=X86Syntax.INTEL)),
                self.addr_cb_map,
                rewriting_ctx
            )

        in_info = ' inline ' if self.inline_tracing else ' '
        log.info(f"Adding{in_info}tracing code to {instr_count} locations ...")
