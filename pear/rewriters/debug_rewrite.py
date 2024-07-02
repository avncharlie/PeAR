import uuid
import pathlib
import logging
import argparse

from collections import OrderedDict
from typing import Optional

import gtirb

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


from .rewriter import Rewriter
from ..utils import run_cmd
from ..arch_utils import WindowsUtils

log = logging.getLogger(__name__)

class DebugRewriter(Rewriter):
    """
    Rewriter that doesn't apply any tranformation, just lifts the binary to IR
    before attempting to generate it.
    """
    @staticmethod
    def build_parser(parser: argparse._SubParsersAction):
        parser = parser.add_parser(DebugRewriter.name(),
                                   help='dbg')

        parser.add_argument(
            '--link', required=False, nargs='+',
            help='Libraries to link',
            metavar=("LIB1", "LIB2")
        )

    @staticmethod
    def name():
        return 'Debug'

    def __init__(self, ir: gtirb.IR, args: argparse.Namespace,
                 mappings: OrderedDict[int, uuid.UUID]):
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
        passes = [
            BreakSwitchPass(),
        ]
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
        WindowsUtils.generate(ir_file, output, working_dir, self.ir,
                                    gen_assembly=gen_assembly,
                                    gen_binary=gen_binary,
                                    obj_link=self.link)

class BreakSwitchPass(Pass):
    def begin_module(self, module, functions, rewriting_ctx):
        for x in module.code_blocks:
            if x.address == 0x14000721c:
                rewriting_ctx.register_insert(
                    SingleBlockScope(x, BlockPosition.ENTRY),
                    Patch.from_function(lambda _:f'''
                    nop
                    nop
                    nop
                    nop
                    ''', Constraints(x86_syntax=X86Syntax.INTEL))
                )

