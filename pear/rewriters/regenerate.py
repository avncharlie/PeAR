import uuid
import pathlib
import logging
import argparse
import textwrap

from collections import OrderedDict
from typing import Optional

import gtirb
from gtirb import Symbol, ProxyBlock
import gtirb_rewriting._auxdata as _auxdata

from .rewriter import Rewriter
from ..utils import run_cmd
from ..arch_utils import ArchUtils, WindowsUtils, WindowsX64Utils, WindowsX86Utils, LinuxUtils

log = logging.getLogger(__name__)

class RegenerateRewriter(Rewriter):
    """
    Rewriter that regenerates a binary from instrumented assembly source.
    """
    @staticmethod
    def build_parser(parser: argparse._SubParsersAction):
        parser = parser.add_parser(RegenerateRewriter.name(),
                                   help='Regenerate binary from instrumented assembly source')
        parser.description = textwrap.dedent("""\
            Regenerate binary from assembly source. Will attempt to regenerate binary with
            the same properties of the given input binary (i.e shared libs, rpath, pie, etc)""")

        def path_exists(f):
            if not pathlib.Path(f).exists():
                parser.error(f'Assembly file "{f}" not found')
            else:
                return f

        parser.add_argument(
            '--from-asm', required=True, type=path_exists,
            help='Assembly source to generate from',
        )

        parser.add_argument(
            '--link', required=False, nargs='+',
            help='Libraries to link',
            metavar=("LIB1", "LIB2")
        )

    @staticmethod
    def name():
        return 'Regenerate'

    def __init__(self, ir: gtirb.IR, args: argparse.Namespace,
                 mappings: OrderedDict[int, uuid.UUID]):
        self.ir = ir
        self.link: list[str] = args.link
        self.asm: str = args.from_asm
        self.is_64bit = ir.modules[0].isa == gtirb.Module.ISA.X64
        self.is_windows = ir.modules[0].file_format == gtirb.Module.FileFormat.PE
        self.is_linux = ir.modules[0].file_format == gtirb.Module.FileFormat.ELF

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
                 **kwargs):
        if self.is_windows:
            WindowsUtils.generate(output, working_dir, self.ir,
                                  asm_fname=self.asm,
                                  gen_assembly=gen_assembly,
                                  gen_binary=gen_binary, obj_link=self.link)
        elif self.is_linux:
            LinuxUtils.generate(output, working_dir, self.ir,
                                asm_fname=self.asm,
                                gen_assembly=gen_assembly,
                                gen_binary=gen_binary, obj_link=self.link)
        else:
            ArchUtils.generate(output, working_dir, self.ir,
                               asm_fname=self.asm,
                               gen_assembly=gen_assembly,
                               gen_binary=gen_binary, obj_link=self.link)
