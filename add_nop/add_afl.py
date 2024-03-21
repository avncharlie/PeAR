import gtirb
import gtirb_functions
from gtirb_rewriting import *
import gtirb_rewriting.driver
from gtirb_rewriting.driver import PassDriver
from gtirb_capstone.instructions import GtirbInstructionDecoder

import time
import json
import uuid
import random
import sys
import os
import collections
import typing
import argparse
import textwrap

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class CallFunctionPatch(Patch):
    '''
    Call function with 16 byte stack alignment while preserving registers
    DOES NOT PRESERVE FLOAT REGISTERS
    '''
    def __init__(self, func, save_stack=0x100):
        self._func = func
        self._save_stack= save_stack
        super().__init__(Constraints(x86_syntax=X86Syntax.INTEL))

    def get_asm(self, insertion_context: InsertionContext) -> str: # pyright: ignore
        return f'''
            sub     rsp, {hex(self._save_stack)}
           
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

            mov     rax, rsp
            lea     rsp, [rsp - 0x80]
            and     rsp, 0xfffffffffffffff0
            push    rax
            push    rax

            call {self._func}

            pop     rax
            mov     rsp, rax

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

            add rsp, {hex(self._save_stack)}
        '''

class FilePatch(Patch):
    '''
    Add contents of file as patch
    '''
    def __init__(self, path):
        with open(path) as f:
            self.asm = f.read()
        super().__init__(Constraints(x86_syntax=X86Syntax.INTEL))

    def get_asm(self, insertion_context: InsertionContext) -> str: # pyright: ignore
        return self.asm

class AFLTrampolinePatch(Patch):
    '''
    AFL basic block tracing instrumentation
    '''
    def __init__(self, block_id: int):
        self.block_id = block_id 
        super().__init__(Constraints(x86_syntax=X86Syntax.INTEL))

    def get_asm(self, insertion_context): # pyright: ignore
        return f'''
            lea    rsp,[rsp-0x98]
            mov    QWORD PTR [rsp],rdx
            mov    QWORD PTR [rsp+0x8],rcx
            mov    QWORD PTR [rsp+0x10],rax
            mov    rcx,{hex(self.block_id)}
            call   __afl_trace
            mov    rax,QWORD PTR [rsp+0x10]
            mov    rcx,QWORD PTR [rsp+0x8]
            mov    rdx,QWORD PTR [rsp]
            lea    rsp,[rsp+0x98]
        '''

class CreateAddressMapPass(Pass):
    """
    Create a mapping between addresses and Codeblock UUIDs and store in file
    """
    def __init__(self, out_file):
        super().__init__()
        self.out_file = out_file

    def begin_module(self,
                     module: gtirb.module.Module,
                     functions: list[gtirb_functions.function.Function],
                     context: RewritingContext):

        print('----------------------------------------')
        print('Generating address to CodeBlock map...')

        f = collections.OrderedDict()
        for block in sorted(module.code_blocks, key=lambda e: e.address):
            f[block.address] = block.uuid.hex

        with open(self.out_file, 'w') as out:
            json.dump(f, out)

        print(f'Map generated and saved to {self.out_file}')
        print('----------------------------------------')

class CreateAddressMap(PassDriver):
    def add_options(self, group):
        group.add_argument("--output", required=True)

    def create_pass(self, args, ir):
        return CreateAddressMapPass(args.output)

    def description(self):
        return "Creates a mapping between CodeBlocks and addresses and stores in file"

class AddAFLGlobalDataPass(Pass):
    """
    Add data (global variables) needed for AFL instrumentation to binary
    """
    def __init__(self, is_persistent=False, is_deferred=False, is_sharedmem_fuzzing=False):
        super().__init__()
        self.is_persistent = is_persistent
        self.is_deferred = is_deferred
        self.is_sharedmem_fuzzing = is_sharedmem_fuzzing

    def begin_module(self,
                     module: gtirb.module.Module,
                     functions: list[gtirb_functions.function.Function],
                     context: RewritingContext):

        print('----------------------------------------')
        print('Adding AFL data...')

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

        # create required variables
        context.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(lambda _:f'''
                # GTIRB patches must have at least one basic block
                nop

                .data
                __afl_area_ptr_dummy: .quad 0
                __afl_area_ptr:   .quad 0
                __afl_debug:   .quad 0

                __afl_already_initialized_shm: .quad 0 
                __afl_prev_loc:   .quad   0

                __afl_already_initialized_forkserver: .quad 0 
                __afl_map_size: .quad 0x10000
                child_pid: .quad 0
                old_sigterm_handler: .space 8
                __afl_connected: .quad 0

                __afl_sharedmem_fuzzing: .quad {1 if self.is_sharedmem_fuzzing else 0}
                is_persistent: .byte {1 if self.is_persistent else 0}

                cycle_cnt: .quad 0
                first_pass: .byte 1

                p_mode_reg_backup: .space 0x170
                p_mode_ret_addr_backup: .space 8

                __afl_fuzz_len: .space 8
                __afl_fuzz_ptr: .space 8

                __document_mutation_counter: .space 4

                .rodata
                .space 16
                {persistent_mode_sig}
                {deferred_initialisation_sig}
            ''', Constraints(x86_syntax=X86Syntax.INTEL))
        )
        print(f'AFL data added')
        print('----------------------------------------')

class AddAFLGlobalData(PassDriver):
    def add_options(self, group):
        group.add_argument("--is-persistent", required=False)
        group.add_argument("--is-deferred", required=False)

    def create_pass(self, args, ir):
        persistent = False
        deferred = False

        if args.is_persistent:
            persistent = True

        if args.is_deferred:
            deferred = True

        return AddAFLGlobalDataPass(is_deferred=deferred, is_persistent=persistent)

    def description(self):
        return """ Add data (global variables) needed for AFL instrumentation to binary """

class AddAFLPass(Pass):
    """
    Add AFL instrumentation to binary
    AddAFLGlobalData must be called before this is run
    """
    def __init__(self, patch_dir, mappings_file, init_func=None,
            init_addr=None, persistent_mode_init_func=None,
            persistent_mode_init_addr=None, persistent_mode_count=10000,
            sharedmem_hook_name=None, sharedmem_loc_address=None,
            sharedmem_loc_is_persistent=None, sharedmem_loc_is_init=None):
        super().__init__()

        self.init_func = init_func
        self.init_addr = init_addr 
        self.instrumented_locations = 0
        self.patch_dir = patch_dir

        self.persistent_mode_func = persistent_mode_init_func
        self.persistent_mode_addr = persistent_mode_init_addr
        self.persistent_mode_count = persistent_mode_count
        self.persistent_mode = False
        if persistent_mode_init_addr or persistent_mode_init_func:
            self.persistent_mode = True

        self.sharedmem_hook_name = sharedmem_hook_name
        self.sharedmem_loc_address = sharedmem_loc_address
        self.sharedmem_loc_is_persistent = sharedmem_loc_is_persistent
        self.sharedmem_loc_is_init = sharedmem_loc_is_init
        self.sharedmem_fuzzing = False
        if self.sharedmem_hook_name:
            self.sharedmem_fuzzing = True

        self.mappings_file = mappings_file

    def get_basic_blocks(self, function: gtirb_functions.Function) -> list[list[gtirb.CodeBlock]]:
        blocks: list[list[gtirb.CodeBlock]] = []
        for block in sorted(function.get_all_blocks(), key=lambda e: e.address):
            incoming = list(block.incoming_edges)
            outgoing = list(block.outgoing_edges)

            # Ignore 'detached' blocks that have  no path to or from them.
            if len(incoming) == 0 and len(outgoing) == 0 and not block in function.get_entry_blocks():
                continue

            '''
            Gtirb builds basic blocks across an entire program and not just
            functions. This means that calls are considered to end a basic
            block. However, in the context of AFL instrumentation, we do not
            consider a call to end a basic block. 
            As such, we group blocks that satisfy all these conditions:
              - Do not have an incoming edge from a jump instruction 
              - Have a incoming edge that is a fallthrough and ...
                  - The source block of the fallthrough edge has two outgoing 
                    edges, being: {Call, Fallthrough}.
            
            i.e consider this block:
              <ASM1>
              call <func>
              <ASM2>
              call <another_func>
            Gtirb would turn this into two basic blocks:
              block 1 (outgoing edges = [CALL, Fallthrough to block 2]:
                <ASM1>
                call <func>
              block 2 (incoming edges = [Fallthrough from block 1]:
                <ASM2>
                call <another_func>
            We consider this one block. As such, we store blocks as lists, and
            the above block would be stored as [block1, block2] in the
            `blocks` array.
            Blocks that don't have calls in them would be stored as singleton
            lists in the `blocks` array.
            '''

            # Check block is fallthrough and doesn't come from branch.
            incoming_edge_types = [x.label.type for x in incoming]
            if gtirb.Edge.Type.Fallthrough in incoming_edge_types and not gtirb.Edge.Type.Branch in incoming_edge_types:
                skip = False
                for incoming_edge in incoming:

                    # Retrieve source block that falls through to current block.
                    if incoming_edge.label.type == gtirb.Edge.Type.Fallthrough:
                        outgoing_source_edge_types = [x.label.type for x in list(incoming_edge.source.outgoing_edges)]

                        # Check source block has {Call, Fallthrough} as its
                        # outoing edges.
                        if set(outgoing_source_edge_types) == set([gtirb.Edge.Type.Call, gtirb.Edge.Type.Fallthrough]):

                            # Find parent block in blocklist and append self.
                            for blocklist in blocks:
                                for b in blocklist:
                                    if b.address == incoming_edge.source.address:
                                        blocklist.append(block)
                                        break

                            skip = True
                            break
                if skip:
                    continue

            blocks.append([block])

        return blocks

    def add_afl_block_tracing(self, function: gtirb_functions.Function,
            context: RewritingContext):
        '''
        Add AFL basic block tracing instrumentation
        '''

        blocks: list[list[gtirb.CodeBlock]] = self.get_basic_blocks(function)

        for blocklist in blocks:
            # insert AFL Trampoline at start of block
            context.register_insert(
                SingleBlockScope(blocklist[0], BlockPosition.ENTRY),
                AFLTrampolinePatch(block_id=random.getrandbits(16))
            )

            self.instrumented_locations += 1

    def insert_patch_at_address(self, patch_address: int, patch: Patch,
            blocks: typing.Iterator[gtirb.CodeBlock], context: RewritingContext):
        '''
        Insert patch at specific address
        Use precomputed address to CodeBlock mappings.
        These mappings were computed before the binary had any patches applied
        so we use them to add patches to the blocks corresponding to the given
        address in the unpatched binary.
        '''
        mappings = list(self.address_mappings.items())

        # find block to instrument
        i = 0
        while patch_address >= mappings[i][0]:
            i += 1
        block_addr, block_uuid = mappings[i-1]

        patch_block: gtirb.CodeBlock = None # pyright: ignore
        for block in blocks:
            if block_uuid == block.uuid:
                patch_block = block
                break

        block_offset = patch_address - block_addr
        context.insert_at(
            patch_block,
            block_offset,
            patch
        )

    def backup_register_asm(self):
        '''
        Backup registers to p_mode_reg_backup 
        '''
        return '''
            mov    QWORD PTR [rip+p_mode_reg_backup],        rax
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x8],  rbx
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x10], rcx
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x18], rdx
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x20], rdi
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x28], rsi
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x30], r8
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x38], r9
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x40], r10
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x48], r11
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x50], r12
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x58], r13
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x60], r14
            mov    QWORD PTR [rip+p_mode_reg_backup + 0x68], r15
            movq   QWORD PTR [rip+p_mode_reg_backup + 0x70], xmm0
            movq   QWORD PTR [rip+p_mode_reg_backup + 0x80], xmm1
            movq   QWORD PTR [rip+p_mode_reg_backup + 0x90], xmm2
            movq   QWORD PTR [rip+p_mode_reg_backup + 0xa0], xmm3
            movq   QWORD PTR [rip+p_mode_reg_backup + 0xb0], xmm4
            movq   QWORD PTR [rip+p_mode_reg_backup + 0xc0], xmm5
            movq   QWORD PTR [rip+p_mode_reg_backup + 0xd0], xmm6
            movq   QWORD PTR [rip+p_mode_reg_backup + 0xe0], xmm7
            movq   QWORD PTR [rip+p_mode_reg_backup + 0xf0], xmm8
            movq   QWORD PTR [rip+p_mode_reg_backup + 0x100],xmm9
            movq   QWORD PTR [rip+p_mode_reg_backup + 0x110],xmm10
            movq   QWORD PTR [rip+p_mode_reg_backup + 0x120],xmm11
            movq   QWORD PTR [rip+p_mode_reg_backup + 0x130],xmm12
            movq   QWORD PTR [rip+p_mode_reg_backup + 0x140],xmm13
            movq   QWORD PTR [rip+p_mode_reg_backup + 0x150],xmm14
            movq   QWORD PTR [rip+p_mode_reg_backup + 0x160],xmm15
        '''

    def restore_register_asm(self):
        '''
        Restore registers from p_mode_reg_backup 
        '''
        return '''
            mov    rax,  QWORD PTR [rip+p_mode_reg_backup]
            mov    rbx,  QWORD PTR [rip+p_mode_reg_backup + 0x8]
            mov    rcx,  QWORD PTR [rip+p_mode_reg_backup + 0x10]
            mov    rdx,  QWORD PTR [rip+p_mode_reg_backup + 0x18]
            mov    rdi,  QWORD PTR [rip+p_mode_reg_backup + 0x20]
            mov    rsi,  QWORD PTR [rip+p_mode_reg_backup + 0x28]
            mov    r8,   QWORD PTR [rip+p_mode_reg_backup + 0x30]
            mov    r9,   QWORD PTR [rip+p_mode_reg_backup + 0x38]
            mov    r10,  QWORD PTR [rip+p_mode_reg_backup + 0x40]
            mov    r11,  QWORD PTR [rip+p_mode_reg_backup + 0x48]
            mov    r12,  QWORD PTR [rip+p_mode_reg_backup + 0x50]
            mov    r13,  QWORD PTR [rip+p_mode_reg_backup + 0x58]
            mov    r14,  QWORD PTR [rip+p_mode_reg_backup + 0x60]
            mov    r15,  QWORD PTR [rip+p_mode_reg_backup + 0x68]
            movq   xmm0, QWORD PTR [rip+p_mode_reg_backup + 0x70]
            movq   xmm1, QWORD PTR [rip+p_mode_reg_backup + 0x80]
            movq   xmm2, QWORD PTR [rip+p_mode_reg_backup + 0x90]
            movq   xmm3, QWORD PTR [rip+p_mode_reg_backup + 0xa0]
            movq   xmm4, QWORD PTR [rip+p_mode_reg_backup + 0xb0]
            movq   xmm5, QWORD PTR [rip+p_mode_reg_backup + 0xc0]
            movq   xmm6, QWORD PTR [rip+p_mode_reg_backup + 0xd0]
            movq   xmm7, QWORD PTR [rip+p_mode_reg_backup + 0xe0]
            movq   xmm8, QWORD PTR [rip+p_mode_reg_backup + 0xf0]
            movq   xmm9, QWORD PTR [rip+p_mode_reg_backup + 0x100]
            movq   xmm10,QWORD PTR [rip+p_mode_reg_backup + 0x110]
            movq   xmm11,QWORD PTR [rip+p_mode_reg_backup + 0x120]
            movq   xmm12,QWORD PTR [rip+p_mode_reg_backup + 0x130]
            movq   xmm13,QWORD PTR [rip+p_mode_reg_backup + 0x140]
            movq   xmm14,QWORD PTR [rip+p_mode_reg_backup + 0x150]
            movq   xmm15,QWORD PTR [rip+p_mode_reg_backup + 0x160]
        '''

    def call_sharedmem_hook_asm(self):
        return f'''
            # stack align
            mov     rcx, rsp
            lea     rsp, [rsp - 0x80]
            and     rsp, 0xfffffffffffffff0
            push    rcx
            push    rcx

            # arg 1: saved registers
            lea rdi, [rip+p_mode_reg_backup]

            # arg 2: testcase
            mov rsi, [rip+__afl_fuzz_ptr]

            # arg 3: testcase length
            mov rax, [rip+__afl_fuzz_len]
            mov edx, [rax]
            call {self.sharedmem_hook_name}

            pop     rcx
            mov     rsp, rcx
        '''

    def setup_and_call_sharedmem_hook_asm(self):
        return f'''
        {self.backup_register_asm()}
        {self.call_sharedmem_hook_asm()}
        {self.restore_register_asm()}
        '''

    def apply_persistent_mode_handler(self,
            context: RewritingContext,
            function: typing.Optional[gtirb_functions.function.Function] = None,
            address: typing.Optional[int] = None,
            module_blocks: typing.Optional[typing.Iterator[gtirb.CodeBlock]] = None):

        # add persistent sharedmem call
        sharedmem_hook_call = ""
        if self.sharedmem_loc_is_persistent:
            sharedmem_hook_call = self.call_sharedmem_hook_asm()

        persistent_mode_patch = Patch.from_function(lambda _: f'''
            # Backup all original registers
            {self.backup_register_asm()}

            # Start of persistent loop
            .Lsetup_loop:

            movzx eax, BYTE PTR first_pass[rip]
            test al, al
            je .Lnot_first_pass
            # On first pass, save and overwrite legitimate return address
            # (first_pass var will be later set by __afl_persistent_loop function)
            pop rax
            mov QWORD PTR [rip+p_mode_ret_addr_backup], rax

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

            mov edi,{hex(self.persistent_mode_count)}
            call __afl_persistent_loop

            pop     rcx
            mov     rsp, rcx
           
            test eax,eax
            jne .Lstart_func

            # To break loop, restore original return address, restore registers and ret
            mov rax, QWORD PTR [rip+p_mode_ret_addr_backup]
            lea rsp,[rsp+0x8]
            push rax
            {self.restore_register_asm()}
            ret

            .Lstart_func:
            # Before starting loop, call sharedmem hook if needed and restore registers
            {sharedmem_hook_call}
            {self.restore_register_asm()}
        ''', Constraints(x86_syntax=X86Syntax.INTEL))

        if function: 
            entry_block: gtirb.CodeBlock 
            for b in function.get_entry_blocks():
                entry_block = b
            context.register_insert(
                SingleBlockScope(entry_block, BlockPosition.ENTRY),
                persistent_mode_patch
            )
        elif address and module_blocks:
            self.insert_patch_at_address(address, persistent_mode_patch,
                    module_blocks, context)
 
    def begin_module(self,
                     module: gtirb.module.Module,
                     functions: list[gtirb_functions.function.Function],
                     context: RewritingContext):


        print('----------------------------------------')
        # load address mappings
        self.address_mappings = collections.OrderedDict()
        d = None
        with open(self.mappings_file) as f:
            d = json.load(f, object_pairs_hook=collections.OrderedDict)
        for addr in d:
            self.address_mappings[int(addr)] = uuid.UUID(d[addr])

        # Make sure these external functions are available to use in our patch
        context.get_or_insert_extern_symbol('getenv', 'libc.so.6')
        context.get_or_insert_extern_symbol('atoi', 'libc.so.6')
        context.get_or_insert_extern_symbol('shmat', 'libc.so.6')
        context.get_or_insert_extern_symbol('write', 'libc.so.6')
        context.get_or_insert_extern_symbol('perror', 'libc.so.6')
        context.get_or_insert_extern_symbol('malloc', 'libc.so.6')
        context.get_or_insert_extern_symbol('free', 'libc.so.6')
        context.get_or_insert_extern_symbol('sprintf', 'libc.so.6')
        context.get_or_insert_extern_symbol('fprintf', 'libc.so.6')
        context.get_or_insert_extern_symbol('printf', 'libc.so.6')
        context.get_or_insert_extern_symbol('_exit', 'libc.so.6')
        context.get_or_insert_extern_symbol('exit', 'libc.so.6')
        context.get_or_insert_extern_symbol('kill', 'libc.so.6')
        context.get_or_insert_extern_symbol('waitpid', 'libc.so.6')
        context.get_or_insert_extern_symbol('sigaction', 'libc.so.6')
        context.get_or_insert_extern_symbol('signal', 'libc.so.6')
        context.get_or_insert_extern_symbol('read', 'libc.so.6')
        context.get_or_insert_extern_symbol('fork', 'libc.so.6')
        context.get_or_insert_extern_symbol('open', 'libc.so.6')
        context.get_or_insert_extern_symbol('unlink', 'libc.so.6')
        context.get_or_insert_extern_symbol('close', 'libc.so.6')
        context.get_or_insert_extern_symbol('stderr', 'libc.so.6')
        context.get_or_insert_extern_symbol('fwrite', 'libc.so.6')
        context.get_or_insert_extern_symbol('raise', 'libc.so.6')
        context.get_or_insert_extern_symbol('memset', 'libc.so.6')
        context.get_or_insert_extern_symbol('puts', 'libc.so.6')
        
        if self.sharedmem_hook_name:
            context.get_or_insert_extern_symbol(f'{self.sharedmem_hook_name}', 'not_real_lib.a')

        # Function to update AFL bitmap on codepaths
        print(f'Inserting function: __afl_trace')
        context.register_insert_function(
            '__afl_trace',
            Patch.from_function(lambda _: '''

                # Store flags on stack (apparently faster than pushf)
                lahf
                seto al

                # Store afl shared memory area in rdx
                mov rdx,[rip + __afl_area_ptr]

                # Record path in bitmap
                xor rcx,QWORD PTR [rip + __afl_prev_loc]
                xor QWORD PTR [rip + __afl_prev_loc],rcx
                shr QWORD PTR [rip + __afl_prev_loc],1
                inc BYTE PTR [rdx+rcx*1]
                adc BYTE PTR [rdx+rcx*1],0x0

                # Return
                add al,0x7f
                sahf
                ret
            ''', Constraints(x86_syntax=X86Syntax.INTEL))
        )

        # Get function patches from patch dir and insert into binary
        # patches are formatted as such: N-<func_name>.s
        # where N specifies the order in which the patches should be loaded
        patch_files = []
        for f in os.listdir(self.patch_dir):
            if f[0].isnumeric() and f[1] == '-' and f[-2:] == '.s':
                patch_files.append(f)
        patch_files.sort(key=lambda e: int(e.split('-')[0]))

        for patch_file in patch_files:
            func_name = patch_file[2:-2]
            print(f'Inserting function: {func_name}')
            context.register_insert_function(
                func_name,
                FilePatch(path=self.patch_dir+patch_file)
            )

        # setup AFL at start of program execution
        context.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            CallFunctionPatch('__afl_setup')
        )

        # if forkserver entrypoint unspecified, attempt to use main function
        is_deferred = True
        if not self.init_addr and not self.init_func:
            self.init_func = 'main'
            is_deferred = False

        added_entrypoint = False
        added_persistent_mode = False

        # add address based forkserver initialisation + sharedmem hook call if needed
        if self.init_addr:
            self.insert_patch_at_address(
                self.init_addr,
                CallFunctionPatch('__afl_start_forkserver'),
                module.code_blocks,
                context
            )
            if self.sharedmem_loc_is_init:
                self.insert_patch_at_address(
                    self.init_addr,
                    Patch.from_function(lambda _: f'''
                        {self.setup_and_call_sharedmem_hook_asm()}
                    ''', Constraints(x86_syntax=X86Syntax.INTEL)),
                    module.code_blocks,
                    context
                )
            added_entrypoint = True

        for function in functions:
            # make sure we do not modify _start function
            if module.entry_point not in function.get_all_blocks():

                # add function based forkserver initialisation + sharedmem hook call if needed
                if not added_entrypoint and function.get_name() == self.init_func:
                    func_entry_block = list(function.get_entry_blocks())[0]
                    context.register_insert(
                        SingleBlockScope(func_entry_block, BlockPosition.ENTRY),
                        CallFunctionPatch('__afl_start_forkserver')
                    )
                    if self.sharedmem_loc_is_init:
                        context.register_insert(
                            SingleBlockScope(func_entry_block, BlockPosition.ENTRY),
                            Patch.from_function(lambda _: f'''
                                {self.setup_and_call_sharedmem_hook_asm()}
                            ''', Constraints(x86_syntax=X86Syntax.INTEL)),
                        )
                    added_entrypoint = True

                # add persistent mode handler if needed
                if function.get_name() == self.persistent_mode_func:
                    self.apply_persistent_mode_handler(context, function=function)
                    added_persistent_mode = True

                # add block tracing instrumentation
                self.add_afl_block_tracing(function, context)

        # add address based persistent mode handler
        if not added_persistent_mode and self.persistent_mode_addr:
            self.apply_persistent_mode_handler(
                context,
                address=self.persistent_mode_addr,
                module_blocks=module.code_blocks
            )
            added_persistent_mode = True

        # add address based sharedmem hook call 
        if self.sharedmem_loc_address:
            self.insert_patch_at_address(
                self.sharedmem_loc_address,
                Patch.from_function(lambda _: f'''
                    {self.setup_and_call_sharedmem_hook_asm()}
                ''', Constraints(x86_syntax=X86Syntax.INTEL)),
                module.code_blocks,
                context
            )

        if not added_entrypoint:
            print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC} No main function found to add forkserver initialisation!"
                + " Please manually specify forkserver entrypoint using --forkserver-init-address or --forkserver-init-func")
            exit(1)

        print(f'{bcolors.OKGREEN}Instrumented {self.instrumented_locations} locations {bcolors.ENDC}')

        if added_persistent_mode:
            persistent_loc = f'function: {self.persistent_mode_func}' if self.persistent_mode_func else f'address: {hex(self.persistent_mode_addr)}'
            print(f'{bcolors.OKGREEN}Added persistent mode to {persistent_loc} (with loop count of {self.persistent_mode_count}) {bcolors.ENDC}')

        if is_deferred:
            deferred_loc = f'function: {self.init_func}' if self.init_func else f'address: {hex(self.init_addr)}'
            print(f'{bcolors.OKGREEN}Added deferred initialisation to {deferred_loc} {bcolors.ENDC}')

        if self.sharedmem_fuzzing:
            sharedmem_loc = ''
            if self.sharedmem_loc_address:
                sharedmem_loc = 'at ' + hex(self.sharedmem_loc_address)
            elif self.sharedmem_loc_is_init:
                sharedmem_loc = 'after forkserver initialsation'
            elif self.sharedmem_loc_is_persistent:
                sharedmem_loc = 'at start of persistent loop'
            print(f'{bcolors.OKGREEN}Added call to sharedmem hook "{self.sharedmem_hook_name}" {sharedmem_loc} {bcolors.ENDC}')

        print(f'----------------------------------------')


class AddAFLInstrumentation(PassDriver):
    def add_options(self, group):
        group.add_argument("--patch-dir", required=True)
        group.add_argument("--codeblock-mappings", required=True)
        group.add_argument("--forkserver-init-address", required=False)
        group.add_argument("--forkserver-init-func", required=False)
        group.add_argument("--persistent-mode-init-address", required=False)
        group.add_argument("--persistent-mode-init-func", required=False)
        group.add_argument("--persistent-mode-count", required=False)

    def create_pass(self, args, ir):
        if args.forkserver_init_func and args.forkserver_init_address:
            print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC} Must only specify one of either forkserver init function or address.")
            exit(1)

        if args.persistent_mode_init_address and args.persistent_mode_init_func:
            print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC} Must only specify one of either persistent init function or address.")
            exit(1)

        if not args.persistent_mode_count and (args.persistent_mode_init_address or args.persistent_mode_init_func):
            print(f"{bcolors.WARNING}WARNING:{bcolors.ENDC} Persistent mode count not specified. Setting to 10000")
            args.persistent_mode_count = 10000

        if args.persistent_mode_init_address:
            args.persistent_mode_init_address = int(args.persistent_mode_init_address, 16)

        if args.persistent_mode_count:
            args.persistent_mode_count = int(args.persistent_mode_count)

        return AddAFLPass(args.patch_dir, args.codeblock_mappings,
                init_func=args.forkserver_init_func,
                init_addr=args.forkserver_init_address,
                persistent_mode_init_addr=args.persistent_mode_init_address,
                persistent_mode_init_func=args.persistent_mode_init_func,
                persistent_mode_count=args.persistent_mode_count)

    def description(self):
        return "Adds AFL instrumentation to binaries. Can only be run after AddAFLGlobalData."

class ShiftRodataAlignmentPass(Pass):
    """
    Shift rodata alignment
    """
    def __init__(self, bytes_to_add, alignment):
        super().__init__()
        self.bytes_to_add = bytes_to_add
        self.alignment = alignment

    def begin_module(self,
                     module: gtirb.module.Module,
                     _: list[gtirb_functions.function.Function],
                     context: RewritingContext):

        print('----------------------------------------')

        print(f'Adding {self.bytes_to_add} bytes to .rodata to ensure {self.alignment} byte alignment')
        context.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(lambda _: f'''
                # GTIRB patches must have at least one basic block
                nop

                .rodata
                .space {self.bytes_to_add}
            ''', Constraints(x86_syntax=X86Syntax.INTEL))
        )
        print('----------------------------------------')

class ShiftRodataAlignment(PassDriver):
    def add_options(self, group):
        group.add_argument("--rodata-bytes-added", required=True)
        group.add_argument("--rodata-alignment-required", required=True)

    def create_pass(self, args, ir):
        align = int(args.rodata_alignment_required)
        calc_alignment = lambda nbytes: align * ((nbytes // align) + 1) - nbytes

        bytes_added = int(args.rodata_bytes_added)
        bytes_to_add = calc_alignment(bytes_added)

        return ShiftRodataAlignmentPass(bytes_to_add, align)

    def description(self):
        return "Ensures alignment of .rodata section"

def create_pass_entrypoints(passes):
    return [gtirb_rewriting.driver._PassEntryPointAdaptor(p.__name__, p) for p in passes]

def get_args():
    parser = argparse.ArgumentParser(
        description="Add AFL instrumentation to GTIRB IR",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('infile', help="Path to input GTIRB IR file")
    parser.add_argument('outfile', help="Path to output GTIRB IR file")

    parser.add_argument(
        '--patch-dir', required=True,
        help="Directory of asm support functions"
    )

    # deferred initialisation 
    parser.add_argument(
        '--forkserver-init-address', required=False,
        help="Address to initialise forkserver"
    )
    parser.add_argument(
        '--forkserver-init-func', required=False,
        help="Function in which to initialise forkserver"
    )

    # persistent mode args
    parser.add_argument(
        '--persistent-mode-address', required=False,
        help="Function address to start persistent mode"
    )
    parser.add_argument(
        '--persistent-mode-func', required=False,
        help="Function in which to apply persistent mode"
    )
    parser.add_argument(
        '--persistent-mode-count', required=False,
        help="Persistent mode count"
    )

    # sharedmem
    parser.add_argument(
        '--sharedmem-hook-location', required=False,
        help=textwrap.dedent('''\
        Location to insert sharedmem hook. Can be one of
          PERSISTENT_LOOP
            Calls the hook immediately prior to the start of the persistent loop
          FORKSERVER_INIT
            Calls the hook immediately after the forkserver initialisation
            (as the child process begins)
          <address>
            Calls the hook at specified address
        ''')
    )
    parser.add_argument(
        '--sharedmem-hook-func-name', required=False,
        help="Name of function to be called as sharedmem hook"
    )

    args =  parser.parse_args()

    args.is_hook_loc_persistent = False
    args.is_hook_loc_init = False
    args.is_hook_loc_address = False
    args.hook_loc_address = None
    
    args.is_deferred = False
    args.is_persistent = False
    args.is_sharedmem_fuzzing = False

    if args.sharedmem_hook_location:
        args.is_sharedmem_fuzzing = True

        if not args.sharedmem_hook_func_name:
            args.sharedmem_hook_func_name = "__afl_rewrite_sharedmem_hook"

        loc = args.sharedmem_hook_location

        if loc == 'PERSISTENT_LOOP':
            args.is_hook_loc_persistent = True
        elif loc == 'FORKSERVER_INIT':
            args.is_hook_loc_init = True
        elif loc.startswith('0x'):
            args.is_hook_loc_address = True
            args.hook_loc_address = int(loc, 16)
        else:
            print(f'{bcolors.FAIL}ERROR:{bcolors.ENDC} Unknown option "{loc}" for --shardemem-hook-location')
            exit(1)

    if args.forkserver_init_func and args.forkserver_init_address:
        print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC} Must only specify one of either forkserver init function or address.")
        exit(1)

    if args.persistent_mode_address and args.persistent_mode_func:
        print(f"{bcolors.FAIL}ERROR:{bcolors.ENDC} Must only specify one of either persistent init function or address.")
        exit(1)

    if args.persistent_mode_count:
        args.persistent_mode_count = int(args.persistent_mode_count)

    if not args.persistent_mode_count and (args.persistent_mode_address or args.persistent_mode_func):
        print(f"{bcolors.WARNING}WARNING:{bcolors.ENDC} Persistent mode count not specified. Setting to 10000")
        args.persistent_mode_count = 10000

    if args.persistent_mode_address:
        args.persistent_mode_address = int(args.persistent_mode_address, 16)

    if args.forkserver_init_address:
        args.forkserver_init_address = int(args.forkserver_init_address, 16)

    if args.forkserver_init_address or args.forkserver_init_func:
        args.is_deferred = True
    if args.persistent_mode_address or args.persistent_mode_func:
        args.is_persistent = True

    return args

def main():
    MAPPING_FNAME = ".rewrite_mappings.json"
    ADDED_BYTES_FNAME = "added_bytes_rodata"
    RODATA_ALIGNMENT = 16

    args = get_args()

    print("Loading IR ...")
    start_t = time.time()
    ir = gtirb.IR.load_protobuf(args.infile)
    diff = round(time.time()-start_t, 3)
    print(f'IR loaded in {diff} seconds')

    # calculate bytes needed to add to rodata to ensure 16 byte alignment
    rodata_added_bytes = 0
    with open(os.path.join(args.patch_dir, ADDED_BYTES_FNAME)) as f:
        rodata_added_bytes = int(f.read())
    calc_alignment = lambda nbytes: RODATA_ALIGNMENT * ((nbytes // RODATA_ALIGNMENT) + 1) - nbytes
    bytes_to_add = calc_alignment(rodata_added_bytes)

    passes = [
        CreateAddressMapPass(MAPPING_FNAME),
        AddAFLGlobalDataPass(
            is_deferred=args.is_deferred,
            is_persistent=args.is_persistent,
            is_sharedmem_fuzzing=args.is_sharedmem_fuzzing
        ),
        AddAFLPass(
            args.patch_dir,
            MAPPING_FNAME,
            init_func=args.forkserver_init_func,
            init_addr=args.forkserver_init_address, 
            persistent_mode_init_addr=args.persistent_mode_address,
            persistent_mode_init_func=args.persistent_mode_func,
            persistent_mode_count=args.persistent_mode_count,
            sharedmem_hook_name=args.sharedmem_hook_func_name,
            sharedmem_loc_address=args.hook_loc_address,
            sharedmem_loc_is_init=args.is_hook_loc_init,
            sharedmem_loc_is_persistent=args.is_hook_loc_persistent 
        ),
        ShiftRodataAlignmentPass(bytes_to_add, RODATA_ALIGNMENT)
    ]
            
    print("Modifying ...")
    start_t = time.time()

    for p in passes:
        manager = PassManager()
        manager.add(p)
        manager.run(ir)

    diff = round(time.time()-start_t, 3)
    print(f'Done in {diff} seconds')

    print("Saving ...")
    ir.save_protobuf(args.outfile)

    if args.is_sharedmem_fuzzing:
        print(f'{bcolors.OKCYAN}To use shared memory hook, add compile options "-L/folder/to/sharedmem/hook -lhook" when compiling instrumented program.{bcolors.ENDC}')

if __name__ == "__main__":
    main()
