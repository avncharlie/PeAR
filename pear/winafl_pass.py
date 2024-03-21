import random
import logging
import uuid
from collections import OrderedDict

from gtirb_rewriting import (
    Pass,
    Patch,
    Constraints,
    X86Syntax,
    SingleBlockScope,
    BlockPosition,
    InsertionContext,
)

from gtirb_capstone.instructions import GtirbInstructionDecoder

from . import DUMMY_LIB_NAME
from . import utils

log = logging.getLogger(__name__)

class Call32bitFunctionPatch(Patch):
    '''
    Call 32-bit function
    '''
    def __init__(self, func, save_stack=0x40):
        self._func = func
        self._save_stack = save_stack
        super().__init__(Constraints(x86_syntax=X86Syntax.INTEL))

    def get_asm(self, insertion_context: InsertionContext) -> str:  # pyright: ignore
        return f'''
            pushfd 
            push    eax
            push    ecx
            push    edx
            push    ebx
            push    ebp
            push    esi
            push    edi

            sub     esp, {hex(self._save_stack)}

            call    {self._func}

            add     esp, {hex(self._save_stack)}

            pop     edi
            pop     esi
            pop     ebp
            pop     ebx
            pop     edx
            pop     ecx
            pop     eax
            popfd
        '''

class Call64bitFunctionPatch(Patch):
    '''
    Call function with 16 byte stack alignment while preserving registers
    '''
    def __init__(self, func, save_stack=0x100):
        self._func = func
        self._save_stack= save_stack
        super().__init__(Constraints(x86_syntax=X86Syntax.INTEL))

    def get_asm(self, insertion_context: InsertionContext) -> str: # pyright: ignore
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

class AddWinAFLDataPass(Pass):
    """
    Add global variables needed for AFL instrumentation to binary
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

class AddWinAFLPass(Pass):
    def __init__(self, mappings: OrderedDict[int, uuid.UUID], target_func: int):
        """
        gtirb-rewriting pass to insert AFL instrumentation.

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

        sharedmem_hook_call = ''
        persistent_mode_patch = Patch.from_function(lambda _: f'''
            # Backup all original registers
            {utils.backup_regs_x86('p_mode_reg_backup')}

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

            {utils.restore_regs_x86('p_mode_reg_backup')}
            ret

            .Lstart_func:
            # Before starting loop, call sharedmem hook if needed and restore registers
            {sharedmem_hook_call}
            {utils.restore_regs_x86('p_mode_reg_backup')}
        ''', Constraints(x86_syntax=X86Syntax.INTEL))

        # Add persistent mode handler to target function
        utils.insert_patch_at_address(
            self.target_func,
            persistent_mode_patch,
            self.mappings,
            rewriting_ctx
        )

        # Add tracing code everywhere
        for func in functions:
            blocks = utils.get_basic_blocks(func)
            for blocklist in blocks:
                rewriting_ctx.register_insert(
                    SingleBlockScope(blocklist[0], BlockPosition.ENTRY),
                    WinAFLTrampolinePatch(block_id=random.getrandbits(16))
                )

        # for func in functions:
        #     e = func.get_entry_blocks().pop()

        #     if e.address == 0x004075a0:
        #         print("Adding persistent patch")
        #         rewriting_ctx.register_insert(
        #             SingleBlockScope(e, BlockPosition.ENTRY),
        #             persistent_mode_patch
        #         )

        #     # read_and_test file and test are instrumented in simple32
        #     # todo: try instrument funcs and see what happens
        #     if e.address in [0x004075a0, 0x004074a0]:
        #         print(f"Adding tracing code to {hex(e.address)}")
        #         blocks = utils.get_basic_blocks(func)
        #         for blocklist in blocks:
        #             rewriting_ctx.register_insert(
        #                 SingleBlockScope(blocklist[0], BlockPosition.ENTRY),
        #                 WinAFLTrampolinePatch(block_id=random.getrandbits(16))
        #             )

class AddHelloPrintPass(Pass):
    def begin_module(self, module, functions, rewriting_ctx):

        # instr_count = 0
        # for function in functions:
        #     entry_blocks = function.get_entry_blocks()
        #     for block in entry_blocks:
        #         rewriting_ctx.register_insert(
        #             SingleBlockScope(block, BlockPosition.ENTRY),
        #             Patch.from_function(lambda _: f'''
        #                 nop
        #             ''', Constraints(x86_syntax=X86Syntax.INTEL))
        #         )
        #         instr_count += 1
        # log.info(f'Instrumenting {instr_count} locations ...')

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
