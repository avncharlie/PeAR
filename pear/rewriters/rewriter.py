import logging
import argparse
from typing import Optional

import gtirb
from ..arch_utils import ArchUtils

log = logging.getLogger(__name__)

class Rewriter:
    """
    Base class that represents rewriters.
    The 'transform' method adds instrumentation to an IR, and the 'generate'
    method generates a binary or assembly from the instrumented IR.
    The 'get_info' and 'build_parser' methods setup argument parsing for the IR.
    """
    def __init__(self, ir: gtirb.IR, args: argparse.Namespace):
        """
        Create a rewriter.

        :param ir: ir to instrument.
        :param args: Parsed arguments for rewriter. Parser built using
            build_parser class method.
        """
        raise NotImplementedError
    
    def rewrite(self, *args, **kwargs) -> gtirb.IR:
        """
        Instrument IR given IR.

        :returns: Instrumented IR
        """
        raise NotImplementedError

    def generate(self,
                 ir_file: str, output: str, working_dir: str, *args,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False,
                 **kwargs):
        """
        Generate binary or assembly from instrumented IR.

        :param ir_file: File location of GTIRB IR to generate from
        :param output: File location of output assembly and/or binary. '.exe'
            will be added for output binary and '.S' for assembly.
        :param working_dir: Local working directory to generate intermediary
            files
        :param gen_assembly: True if generating assembly
        :param gen_binary: True if generating binary
        """
        # Calls generic generation method.
        # More advanced rewriters that need to do things like compiling and 
        # linking in their own compiled objects will need to override this.
        ArchUtils.generate(ir_file, output, working_dir,
                           gen_assembly=gen_assembly,
                           gen_binary=gen_binary)

    @staticmethod
    def get_info() -> tuple[str, str]:
        """
        Return name and description of rewriter.
        Used when listing rewriters on command line.

        :returns: A tuple containing: (rewriter name, brief summary).
        """
        raise NotImplementedError

    @staticmethod
    def build_parser(parser: argparse.ArgumentParser):
        """
        Set up arparse parser for rewriter-specific arguments.
        """
        raise NotImplementedError