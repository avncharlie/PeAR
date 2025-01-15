import os
import json
import uuid
import random
import shutil
import pathlib
import logging
import argparse
import textwrap
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
from ...arch_utils.windows_utils import (WindowsUtils, WindowsX64Utils, WindowsX86Utils)

from ..rewriter import Rewriter

log = logging.getLogger(__name__)

class AFLPlusPlusRewriter(Rewriter):
    """
    This class implements AFL++ instrumentation on x64 Linux binaries.
    """
    @staticmethod
    def build_parser(parser: argparse._SubParsersAction):
        parser = parser.add_parser(AFLPlusPlusRewriter.name(),
                                   description= "Add AFL++ instrumentation to 64-bit Linux binaries.",
                                   help='Add AFL++ instrumentation',
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


        required.add_argument(
            '--patch-dir', required=True,
            help="Directory of asm support functions"
        )

        # deferred initialisation 
        required.add_argument(
            '--forkserver-init-address', required=False,
            help="Address to initialise forkserver"
        )
        required.add_argument(
            '--forkserver-init-func', required=False,
            help="Function in which to initialise forkserver"
        )

        # persistent mode args
        required.add_argument(
            '--persistent-mode-address', required=False,
            help="Function address to start persistent mode"
        )
        required.add_argument(
            '--persistent-mode-func', required=False,
            help="Function in which to apply persistent mode"
        )
        required.add_argument(
            '--persistent-mode-count', required=False,
            help="Persistent mode count"
        )

        # sharedmem
        required.add_argument(
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
        required.add_argument(
            '--sharedmem-hook-func-name', required=False,
            help="Name of function to be called as sharedmem hook"
        )

    @staticmethod
    def name():
        return 'AFL++'

    def __init__(self, ir: gtirb.IR, args: argparse.Namespace,
                 mappings: OrderedDict[int, uuid.UUID], dry_run: bool):
        raise NotImplementedError

    def generate(self,
                 ir_file: str, output: str, working_dir: str, *args,
                 gen_assembly: Optional[bool]=False,
                 gen_binary: Optional[bool]=False,
                 **kwargs):
        raise NotImplementedError
