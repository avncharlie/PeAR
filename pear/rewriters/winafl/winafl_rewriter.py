import os
import uuid
import random
import shutil
import logging
import argparse
import importlib

from collections import OrderedDict
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
from gtirb_capstone.instructions import GtirbInstructionDecoder

from ... import DUMMY_LIB_NAME
from ... import utils
from ...utils import run_cmd, check_executables_exist
from ...arch_utils import WindowsX86Utils

from ..rewriter import Rewriter

log = logging.getLogger(__name__)

class WinAFLRewriter(Rewriter):
    """
    This class implements WinAFL instrumentation on x86 and x64 binaries.
    """
    @staticmethod
    def build_parser(parser: argparse.ArgumentParser):
        parser.description = "Add WinAFL instrumentation to 32-bit or 64-bit Windows binaries."
        def is_hex_address(loc):
            try:
                return int(loc, 16)
            except ValueError:
                parser.error(f'Can\'t parse "{loc}" as address, please provide hex address (e.g. 0x75a0)')
        parser.add_argument(
            '--target-func', required=True, type=is_hex_address,
            help="Address of target function that will be interrogated during fuzzing"
        )

    @staticmethod
    def get_info() -> tuple[str, str]:
        return ("WinAFL", "Add WinAFL instrumentation")

    def __init__(self, ir: gtirb.IR, args: argparse.Namespace):
        self.ir = ir
        self.target_func: int = args.target_func
        self.mappings: OrderedDict[int, uuid.UUID] = utils.get_address_to_codeblock_mappings(ir)

    def rewrite(self) -> gtirb.IR:
        passes = [
            # Data must be added in a seperate pass before it can be referenced
            # in other passes.
            AddWinAFLDataPass(), 
            AddWinAFLPass(self.mappings, self.target_func)
        ]
        # gtirb-rewriting's pass manager is bugged and can only handle running
        # one pass at a time.
        for p in passes:
            manager = PassManager()
            manager.add(p)
            manager.run(self.ir)
        return self.ir

    def generate(self,
                 ir_file: str, output: str, working_dir: str, *args,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False,
                 **kwargs):
        if not gen_binary:
            WindowsX86Utils.generate(ir_file, output, working_dir, self.ir,
                                     gen_assembly=gen_assembly)
            return
        # As we are generating binary, we need to build the instrumentation
        # object.
        # Copy object source to working dir
        folder_name = "instrumentation_obj"
        orig_obj_folder = importlib.resources.files(__package__) / folder_name
        obj_src_folder = os.path.join(working_dir, folder_name)
        shutil.copytree(orig_obj_folder, obj_src_folder, dirs_exist_ok=True)
        # Build object
        obj_src_path = os.path.join(obj_src_folder, "afl-staticinstr.c")
        static_obj_fname = "afl-staticinstr.obj"
        static_obj_path = os.path.join(working_dir, static_obj_fname)
        cmd = ["cl", r"/nologo", r"/c", obj_src_path, fr'/Fo{static_obj_path}']
        run_cmd(cmd)

        # Now build binary, linking static object and its dependencies.
        to_link = ["vcruntime.lib", "ucrt.lib", "kernel32.lib", "user32.lib",
                   static_obj_fname]
        WindowsX86Utils.generate(ir_file, output, working_dir, self.ir,
                                 gen_binary=gen_binary, obj_link=to_link)
        

class WinAFLTrampolinePatch(Patch):
    '''
    WinAFL basic block tracing instrumentation
    '''
    def __init__(self, block_id: int):
        self.block_id = block_id 
        super().__init__(Constraints(x86_syntax=X86Syntax.INTEL))

    def get_asm(self, insertion_context):
        return f'''
            push   eax
            push   ebx
            lahf
            seto   al
            mov    ebx, {hex(self.block_id)}
            xor    ebx, dword ptr [__afl_prev_loc]
            add    ebx, dword ptr [__afl_area_ptr]
            inc    byte ptr [ebx]
            mov    dword ptr [__afl_prev_loc], {hex(self.block_id >> 1)}
            add    al, 127
            sahf
            pop ebx
            pop eax
        '''

class AddWinAFLDataPass(Pass):
    """
    Add global variables needed for AFL instrumentation to binary.
    """
    def begin_module(self, module, functions, rewriting_ctx):
        rewriting_ctx.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(lambda _:f'''
                # GTIRB patches must have at least one basic block
                nop

                .section SYZYAFL
                __tls_index: .space 4
                __tls_slot_offset: .space 4
                __afl_prev_loc: .space 4
                __afl_area_ptr: .long __afl_area
                __afl_area: .space 0x10000

                .section .data
                p_mode_reg_backup: .space 0x100
                p_mode_ret_addr_backup: .space 4

                __first_pass: .byte 1
                .space 3
            ''', Constraints(x86_syntax=X86Syntax.INTEL))
        )

class AddWinAFLPass(Pass):
    def __init__(self, mappings: OrderedDict[int, uuid.UUID], target_func: int):
        """
        Insert AFL instrumentation.
        Adds block tracing code to all functions, and persistent fuzzing loop to
        specified target function.
        
        :param mappings: dictionary of addresses to codeblock UUIDs
        :param target_func: address of function to add main fuzzer loop to
        """
        super().__init__()
        self.mappings = mappings
        self.target_func = target_func

    def begin_module(self, module, functions, rewriting_ctx):
        rewriting_ctx.get_or_insert_extern_symbol('__afl_persistent_loop', DUMMY_LIB_NAME)
        rewriting_ctx.get_or_insert_extern_symbol('__afl_display_banner', DUMMY_LIB_NAME)

        decoder = GtirbInstructionDecoder(module.isa)

        backup_regs = WindowsX86Utils.backup_registers('p_mode_reg_backup')
        restore_regs = WindowsX86Utils.restore_registers('p_mode_reg_backup')

        sharedmem_hook_call = ''
        persistent_mode_patch = Patch.from_function(lambda _: f'''
            # Backup all original registers
            {backup_regs}

            # Start of persistent loop
            .Lsetup_loop:

            movzx eax, BYTE PTR __first_pass
            test al, al
            je .Lnot_first_pass
            # On first pass, save and overwrite legitimate return address
            pop eax
            mov DWORD PTR [p_mode_ret_addr_backup], eax
            mov BYTE PTR [__first_pass], 0

            .Lnot_first_pass:
            # On subsequent passes, we push return address on stack to
            # emulate function call
            lea eax, [.Lsetup_loop]
            push eax

            # Check whether to continue loop or not
            call __afl_persistent_loop
           
            test eax, eax
            jne .Lstart_func

            # To break loop, restore original return address, restore registers and ret
            mov eax, DWORD PTR [p_mode_ret_addr_backup]
            add esp, 0x4
            push eax

            {restore_regs}
            ret

            .Lstart_func:
            # Before starting loop, call sharedmem hook if needed and restore registers
            {sharedmem_hook_call}
            {restore_regs}
        ''', Constraints(x86_syntax=X86Syntax.INTEL))

        # Add persistent mode handler to target function
        utils.insert_patch_at_address(
            self.target_func,
            persistent_mode_patch,
            self.mappings,
            rewriting_ctx
        )

        # Add tracing code everywhere
        instr_count = 0
        for func in functions:
            blocks = utils.get_basic_blocks(func)
            for blocklist in blocks:
                rewriting_ctx.register_insert(
                    SingleBlockScope(blocklist[0], BlockPosition.ENTRY),
                    WinAFLTrampolinePatch(block_id=random.getrandbits(16))
                )
                instr_count += 1

        # Actual rewrite occurs when pass is run, not when we inserted 
        # instrumentation above
        log.info(f"Adding tracing code to {instr_count} locations ...")

class AddHelloPrintPass(Pass):
    def begin_module(self, module, functions, rewriting_ctx):
        rewriting_ctx.get_or_insert_extern_symbol('printf', 'MSVCRT.dll')
        rewriting_ctx.register_insert_function(
            '__testing',
            Patch.from_function(lambda _: '''

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

                mov     rdi, rsp
                lea     rsp, [rsp - 0x80]
                and     rsp, 0xfffffffffffffff0
                push    rdi
                push    rdi

                sub     rsp, 0x100

                lea rcx,[rip + .Linsns] 
                call printf

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

                ret

                .section .rdata
                .Linsns:
                    .string "HELLO WORLD\n"
                    .space 3
            ''', Constraints(x86_syntax=X86Syntax.INTEL))
        )
        
        decoder = GtirbInstructionDecoder(module.isa)
        
        for function in functions:
            e = function.get_entry_blocks().pop()
        
            insns = ''
            for ins in decoder.get_instructions(e):
                insns += f"{ins.insn_name()} {ins.op_str}\n"
            insns = insns[:-1]
        
            main = '\n'.join(['sub rsp, 0x28', 'lea rcx, [rip + 0x8ee65]', 'call 0x140002513'])
        
            if insns == main:
                rewriting_ctx.register_insert(
                    SingleBlockScope(e, BlockPosition.ENTRY),
                    Call64bitFunctionPatch('__testing')
                )

class Call64bitFunctionPatch(Patch):
    '''
    Call function with 16 byte stack alignment while preserving registers
    '''
    def __init__(self, func, save_stack=0x100):
        self._func = func
        self._save_stack= save_stack
        super().__init__(Constraints(x86_syntax=X86Syntax.INTEL))

    def get_asm(self, insertion_context) -> str: # pyright: ignore
        return f'''

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

            mov     rdi, rsp
            lea     rsp, [rsp - 0x80]
            and     rsp, 0xfffffffffffffff0
            push    rdi
            push    rdi

            sub  rsp, {hex(self._save_stack)}

            call {self._func}

            add rsp, {hex(self._save_stack)}

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

        '''