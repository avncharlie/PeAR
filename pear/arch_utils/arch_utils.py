# Architecture specific utility functions
import os
import gtirb
import logging
from typing import Optional

from ..utils import run_cmd, check_executables_exist

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
                      post_call: Optional[str]='',
                      data: Optional[str]='') -> str:
        '''
        Generate asm calling function
        :param func: Name of function to call.
        :param save_stack: Number of bytes of stack above the stack pointer to
            save before running function call (some ISAs require this)
        :param pre_call: assembly to insert immediately prior to call
        :param post_call: assembly to insert immediately post to call
        :param data: data to insert at end
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
            gen_args += ['--syntax', 'intel', '--asm', asm_path]
        if gen_binary:
            gen_args += ['--binary', bin_path]

        cmd = ["gtirb-pprinter", ir_file] + gen_args
        run_cmd(cmd)

        if gen_assembly:
            log.info(f'Generated assembly saved to: {asm_path}')
        if gen_binary:
            log.info(f'Generated binary saved to: {bin_path}')
