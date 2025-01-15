import uuid
import pathlib
import logging
import argparse

from collections import OrderedDict
from typing import Optional

import gtirb
from gtirb import Symbol, ProxyBlock
import gtirb_rewriting._auxdata as _auxdata

from .rewriter import Rewriter
from ..utils import run_cmd
from ..arch_utils.arch_utils import ArchUtils
from ..arch_utils.windows_utils import WindowsUtils, WindowsX64Utils, WindowsX86Utils
from ..arch_utils.linux_utils import LinuxUtils, SwitchData

log = logging.getLogger(__name__)

class IdentityRewriter(Rewriter):
    """
    Rewriter that doesn't apply any tranformation, just lifts the binary to IR
    before attempting to generate it.
    """
    @staticmethod
    def build_parser(parser: argparse._SubParsersAction):
        parser = parser.add_parser(IdentityRewriter.name(),
                                   help='Parse then regenerate binary')
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

    def __init__(self, ir: gtirb.IR, args: argparse.Namespace,
                 mappings: OrderedDict[int, uuid.UUID], dry_run: bool):
        self.ir = ir
        self.link: list[str] = args.link
        self.is_64bit = ir.modules[0].isa == gtirb.Module.ISA.X64
        self.is_windows = ir.modules[0].file_format == gtirb.Module.FileFormat.PE
        self.is_linux = ir.modules[0].file_format == gtirb.Module.FileFormat.ELF
        self.dry_run = dry_run

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

        # check we have compiler
        if self.is_windows and self.is_64bit:
            WindowsX64Utils.check_compiler_exists()
        if self.is_windows and not self.is_64bit:
            WindowsX86Utils.check_compiler_exists()
        if self.is_linux and self.is_64bit:
            LinuxUtils.check_compiler_exists()

    def rewrite(self) -> gtirb.IR:
        return self.ir

    def generate(self, output: str, working_dir: str, *args,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False,
                 switch_data: Optional[list[SwitchData]]=None,
                 **kwargs):
        if self.is_windows:
            WindowsUtils.generate(output, working_dir, self.ir,
                                  gen_assembly=gen_assembly,
                                  gen_binary=gen_binary, obj_link=self.link)
        elif self.is_linux:
            LinuxUtils.generate(output, working_dir, self.ir,
                               gen_assembly=gen_assembly,
                               gen_binary=gen_binary,obj_link=self.link,
                               switch_data=switch_data)
        else:
            ArchUtils.generate(output, working_dir, self.ir,
                               gen_assembly=gen_assembly,
                               gen_binary=gen_binary, obj_link=self.link)
