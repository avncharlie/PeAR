import os
import shutil
import pathlib
import logging
import argparse

from typing import Optional

import gtirb

from .rewriter import Rewriter
from ..utils import run_cmd
from ..arch_utils import WindowsUtils

log = logging.getLogger(__name__)

class IdentityRewriter(Rewriter):
    """
    Rewriter that doesn't apply any tranformation, just lifts the binary to IR
    before attempting to generate it.
    """
    @staticmethod
    def build_parser(parser: argparse._SubParsersAction):
        parser = parser.add_parser(IdentityRewriter.name(),
                                   help='Cycle binary through reassembly and disassembly')
        parser.description = """\
Lift binary to GTIRB IR then attempt to generate it.
If a binary can't go through this rewriter without breaking, GTIRB isn't
able to reassemble or disassemble it correctly and instrumentation will not
be possible."""

        parser.add_argument(
            '--link', required=False, nargs='+',
            help='Libraries to link',
            metavar=("LIB1", "LIB2")
        )

    @staticmethod
    def name():
        return 'Identity'

    def __init__(self, ir: gtirb.IR, args: argparse.Namespace):
        self.ir = ir
        self.link: list[str] = args.link

        # convert relative library paths to absolute paths
        link = []
        if self.link != None:
            for l in self.link:
                p = pathlib.Path(l)
                if p.exists():
                    link.append(str(p.resolve()))
                else:
                    link.append(l)
        self.link = link

    def rewrite(self) -> gtirb.IR:
        return self.ir

    def generate(self,
                 ir_file: str, output: str, working_dir: str, *args,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False,
                 **kwargs):
        WindowsUtils.generate(ir_file, output, working_dir, self.ir,
                                    gen_assembly=gen_assembly,
                                    gen_binary=gen_binary,
                                    obj_link=self.link)