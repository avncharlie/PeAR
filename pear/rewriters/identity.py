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
from ..arch_utils import ArchUtils, WindowsUtils, WindowsX64Utils, WindowsX86Utils, LinuxUtils

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

    def __init__(self, ir: gtirb.IR, args: argparse.Namespace,
                 mappings: OrderedDict[int, uuid.UUID]):
        self.ir = ir
        self.link: list[str] = args.link
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
        # prepare for generation

        for module in self.ir.modules:
            # Get data from aux tables
            elf_symbol_info = _auxdata.elf_symbol_info.get_or_insert(module)
            elf_symbol_versions = module.aux_data['elfSymbolVersions'].data
            sym_version_defs,lib_version_imports, symbol_to_version_map = elf_symbol_versions
            lib_version_imports: dict[str, dict[int, str]] # {'libc.so.6': {2: 'GLIBC_2.2.5', 4: 'GLIBC_2.14'}}
            symbol_to_version_map: dict[Symbol, tuple[int, bool]] # {SYMBOL: (ID, is_hidden)}

            # Generate mapping from version ID -> (version string, lib)
            id_to_version: dict[int, tuple[str, str]] = {}
            for lib, versions in lib_version_imports.items():
                for version_id, version_string in versions.items():
                    id_to_version[version_id] = (version_string, lib)

            strong_versioned_syms: dict[Symbol, int] = {}

            # Get weak symbols
            weak_syms = []
            for symbol, (_, _, binding, _, _) in elf_symbol_info.items():
                if binding == "WEAK":
                    weak_syms.append(symbol)

            # Get external versioned syms, ignoring weak symbols
            for sym, (id, is_hidden) in symbol_to_version_map.items():
                if not is_hidden and sym not in weak_syms:
                    strong_versioned_syms[sym] = id

            # Convert remaining external non-versioned syms to weak symbols
            for symbol, (a, sym_type, binding, visibility, b) in elf_symbol_info.items():
                if binding == "GLOBAL" and isinstance(symbol._payload, ProxyBlock) and symbol not in strong_versioned_syms:
                    elf_symbol_info[symbol] = (a, sym_type, "WEAK", visibility, b)

        return self.ir

    def generate(self, output: str, working_dir: str, *args,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False,
                 **kwargs):
        if self.is_windows:
            WindowsUtils.generate(output, working_dir, self.ir,
                                  gen_assembly=gen_assembly,
                                  gen_binary=gen_binary, obj_link=self.link)
        if self.is_linux:
            # pass
            LinuxUtils.generate(output, working_dir, self.ir,
                               gen_assembly=gen_assembly,
                               gen_binary=gen_binary, obj_link=self.link)
        else:
            ArchUtils.generate(output, working_dir, self.ir,
                               gen_assembly=gen_assembly,
                               gen_binary=gen_binary, obj_link=self.link)
