import os
import json
import uuid
import random
import shutil
import pathlib
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
from ...arch_utils.windows_utils import WindowsUtils, WindowsX64Utils, WindowsX86Utils

from ..rewriter import Rewriter

log = logging.getLogger(__name__)

class WinAFLRewriter(Rewriter):
    """
    This class implements WinAFL instrumentation on x86 and x64 Windows binaries.
    """
    @staticmethod
    def build_parser(parser: argparse._SubParsersAction):
        parser = parser.add_parser(WinAFLRewriter.name(),
                                   description= "Add WinAFL instrumentation to 32-bit or 64-bit Windows binaries.",
                                   help='Add WinAFL instrumentation',
                                   add_help=False)

        def is_hex_address(loc):
            try:
                return int(loc, 16)
            except ValueError:
                parser.error(f'Can\'t parse "{loc}" as address, please provide hex address (e.g. 0x75a0)')

        required = parser.add_argument_group('required arguments')
        optional = parser.add_argument_group('optional arguments')
        required.add_argument(
            '--target-func', required=True, type=is_hex_address,
            help="Address of target function that will be interrogated during fuzzing"
        )

        optional.add_argument(
            '-h',
            '--help',
            action='help',
            default=argparse.SUPPRESS,
            help='Show this help message and exit'
        )

        optional.add_argument(
            '--ignore-functions', required=False, nargs='+',
            help="Addresses of functions to not instrument",
            metavar=("ADDR1", "ADDR2")
        )

        optional.add_argument(
            '--extra-link-libs', required=False, nargs='+',
            help="Extra libraries to link to final executable",
            metavar=("LIB1", "LIB2")
        )

    @staticmethod
    def name():
        return 'WinAFL'

    def __init__(self, ir: gtirb.IR, args: argparse.Namespace,
                 mappings: OrderedDict[int, uuid.UUID], dry_run: bool):
        self.ir = ir
        self.target_func: int = args.target_func
        self.mappings = mappings

        # convert relative library paths to absolute paths
        self.extra_link = args.extra_link_libs
        link = []
        if self.extra_link != None:
            for l in self.extra_link:
                p = pathlib.Path(l)
                if p.exists():
                    link.append(str(p.resolve()))
                else:
                    link.append(l)
        self.extra_link: list[str] = link
        self.is_64bit = ir.modules[0].isa == gtirb.Module.ISA.X64

        # convert ignorelist to hex addresses
        if args.ignore_functions == None:
            args.ignore_functions = []
        self.ignore_funcs: list[int] = []
        for func in args.ignore_functions:
            try:
                self.ignore_funcs.append(int(func, 16))
            except ValueError:
                assert False, (f'Can\'t parse "{func}" as address, please provide hex address')

        # check compiler right version
        if self.is_64bit:
            WindowsX64Utils.check_compiler_exists()
        else:
            WindowsX86Utils.check_compiler_exists()
        log.info(f"{'64-bit' if self.is_64bit else '32-bit'} MSVC build tools found.")

    def rewrite(self) -> gtirb.IR:
        passes = [
            # Data must be added in a seperate pass before it can be referenced
            # in other passes.
            AddWinAFLDataPass(self.is_64bit), 
            AddWinAFLPass(self.mappings, self.target_func, self.is_64bit,
                          self.ignore_funcs)
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
                 **kwargs):

        if not gen_binary:
            WindowsUtils.generate(output, working_dir, self.ir,
                                  gen_assembly=gen_assembly)
            return

        # As we are generating binary, we need to build the instrumentation
        # object.
        # Copy object source to working dir
        folder_name = "instrumentation"
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
                   static_obj_fname] + self.extra_link
        WindowsUtils.generate(output, working_dir, self.ir,
                              gen_binary=gen_binary, obj_link=to_link)

class AddWinAFLDataPass(Pass):
    def __init__(self, is_64bit: bool):
        """
        Add global variables needed for AFL instrumentation to binary.

        :param is_64bit: true if binary is 64 bit
        """
        super().__init__()
        self.is_64bit = is_64bit

    def begin_module(self, module, functions, rewriting_ctx):
        size = '4'
        r = 'eax'
        rel = ''
        p_mode_size = '0x100'
        if self.is_64bit:
            size = '8'
            r = 'rax'
            rel = 'rip + '
            p_mode_size = '0x170'

        rewriting_ctx.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(lambda _:f'''
                # Load address of __afl_area into __afl_area_ptr (idk how to do
                # this in its definition)
                push {r}
                lea {r}, [{rel}__afl_area]
                mov [{rel}__afl_area_ptr], {r}
                pop {r}

                .section SYZYAFL
                __tls_index: .space {size}
                __tls_slot_offset: .space {size}
                __afl_prev_loc: .space {size}
                __afl_area_ptr: .space {size}
                __afl_area: .space 0x10000

                .section .data
                p_mode_reg_backup: .space {p_mode_size}
                p_mode_ret_addr_backup: .space {size}

                __first_pass: .byte 1
                .space {'7' if self.is_64bit else '3'}
            ''', Constraints(x86_syntax=X86Syntax.INTEL))
        )

class WinAFL32TrampolinePatch(Patch):
    '''
    WinAFL basic block tracing instrumentation for 32-bit binaries
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
 
class WinAFL64TrampolinePatch(Patch):
    '''
    WinAFL basic block tracing instrumentation for 64-bit binaries
    '''
    def __init__(self, block_id: int):
        self.block_id = block_id 
        super().__init__(Constraints(x86_syntax=X86Syntax.INTEL))

    def get_asm(self, insertion_context):
        return f'''
            push   rax
            push   rbx
            lahf
            seto   al
            mov    rbx, {hex(self.block_id)}
            xor    rbx, qword ptr [rip + __afl_prev_loc]
            add    rbx, qword ptr [rip + __afl_area_ptr]
            inc    byte ptr [rbx]
            mov    qword ptr [rip + __afl_prev_loc], {hex(self.block_id >> 1)}
            add    al, 127
            sahf
            pop rbx
            pop rax
        '''

class AddWinAFLPass(Pass):
    def __init__(self, mappings: OrderedDict[int, uuid.UUID], target_func: int,
                 is_64bit: bool, ignore_funcs: list[int]):
        """
        Insert AFL instrumentation.
        Adds block tracing code to all functions, and persistent fuzzing loop to
        specified target function.
        
        :param mappings: dictionary of addresses to codeblock UUIDs
        :param target_func: address of function to add main fuzzer loop to
        :param is_64bit: true if binary is 64 bit
        """
        super().__init__()
        self.mappings = mappings
        self.target_func = target_func
        self.is_64bit = is_64bit
        self.ignore_funcs = ignore_funcs

    def persistent_patch_x32(self):
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
        return persistent_mode_patch

    def persistent_patch_x64(self):
        backup_regs = WindowsX64Utils.backup_registers('p_mode_reg_backup')
        restore_regs = WindowsX64Utils.restore_registers('p_mode_reg_backup')
        sharedmem_hook_call = ''
        persistent_mode_patch = Patch.from_function(lambda _: f'''
            # Backup all original registers
            {backup_regs}

            # Start of persistent loop
            .Lsetup_loop:

            movzx eax, BYTE PTR __first_pass[rip]
            test al, al
            je .Lnot_first_pass
            # On first pass, save and overwrite legitimate return address
            pop rax
            mov QWORD PTR [rip+p_mode_ret_addr_backup], rax
            mov BYTE PTR [__first_pass], 0

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

            call __afl_persistent_loop

            pop     rcx
            mov     rsp, rcx
           
            test eax,eax
            jne .Lstart_func

            # To break loop, restore original return address, restore registers and ret
            mov rax, QWORD PTR [rip+p_mode_ret_addr_backup]
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
        # Setup persistence patch (loops the target function)
        rewriting_ctx.get_or_insert_extern_symbol('__afl_persistent_loop', DUMMY_LIB_NAME)
        if self.is_64bit:
            persistent_patch = self.persistent_patch_x64()
        else:
            persistent_patch = self.persistent_patch_x32()

        # Add persistence handler to target function
        utils.insert_patch_at_address(
            self.target_func,
            persistent_patch,
            self.mappings,
            rewriting_ctx
        )

        # Add tracing code everywhere
        if self.is_64bit:
            WinAFLTrampolinePatch = WinAFL64TrampolinePatch
        else:
            WinAFLTrampolinePatch = WinAFL32TrampolinePatch

        instr_count = 0
        ignore = {self.mappings[f]: f for f in self.ignore_funcs} # uuid: address
        for func in functions:
            skip = False

            # don't instrument start function as that we won't have set up
            # __afl_area_ptr by then
            if module.entry_point in func.get_all_blocks():
                skip = True

            # ignore user-specified functions
            for b in func.get_entry_blocks():
                if b.uuid in ignore:
                    log.info(f"Skipping function {hex(ignore[b.uuid])}...")
                    skip = True

            if skip:
                continue

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
