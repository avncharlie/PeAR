import uuid
import logging
import argparse

from collections import OrderedDict
from typing import Optional

import gtirb
from ..arch_utils import ArchUtils

log = logging.getLogger(__name__)

class Rewriter:
    """
    Base class that represents rewriters.
    The 'transform' method adds instrumentation to an IR, and the 'generate'
    method generates a binary or assembly from the instrumented IR.
    The 'name' and 'build_parser' methods setup argument parsing for the IR.
    """
    def __init__(self, ir: gtirb.IR, args: argparse.Namespace,
                 mappings: OrderedDict[int, uuid.UUID]):
        """
        Create a rewriter.

        :param ir: ir to instrument.
        :param args: Parsed arguments for rewriter. Parser built using
            build_parser class method.
        :param mappings: Codeblocks to address mappings in original IR
        """
        raise NotImplementedError
    
    def rewrite(self, *args, **kwargs) -> gtirb.IR:
        """
        Instrument IR given IR.

        :returns: Instrumented IR
        """
        raise NotImplementedError

    def generate(self,
                 output: str, working_dir: str, *args,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False,
                 **kwargs):
        """
        Generate binary or assembly from instrumented IR.

        :param output: File location of output assembly and/or binary. '.exe'
            will be added for output binary, '.S' for assembly and '.gtirb' for 
            IR.
        :param working_dir: Local working directory to generate intermediary
            files
        :param gen_assembly: True if generating assembly
        :param gen_binary: True if generating binary
        """
        raise NotImplementedError

    @staticmethod
    def build_parser(parser: argparse._SubParsersAction):
        """
        Set up arparse parser for rewriter-specific arguments.
        Method should add subparser parser to given main parser.
        """
        raise NotImplementedError

    @staticmethod
    def name():
        """Returns name of rewriter"""
        raise NotImplementedError
