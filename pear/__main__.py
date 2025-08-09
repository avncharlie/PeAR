# pyright: reportAttributeAccessIssue=false

import os
import sys
import time
import stat
import json
import logging
import pathlib
import textwrap
import argparse
from types import CodeType
from gtirb import Symbol, CodeBlock
import gtirb_rewriting._auxdata as _auxdata

from collections import OrderedDict

import gtirb

from .utils import is_pie, get_address_to_byteblock_mappings
from .ddisasm import ddisasm
from . import REWRITERS, REWRITER_MAP, GEN_SCRIPT_OPTS
from .rewriters.rewriter import Rewriter
from .arch_utils.linux_utils import fix_arm64_switches

log = logging.getLogger(__package__)

def setup_logger(log):
    # TODO: remove this color stuff
    green = '\033[92m'
    blue = '\033[94m'
    yellow = '\033[93m'
    red = '\033[91m'
    magenta = '\033[95m'
    end = '\033[0m'

    class CustomFormatter(logging.Formatter):
        LEVEL_COLORS = {
            logging.INFO: blue,
            logging.WARNING: yellow,
            logging.ERROR: red,
            logging.CRITICAL: magenta,
        }
        def format(self, record):
            color = self.LEVEL_COLORS.get(record.levelno, '')
            log_msg = f"{color}{record.levelname} - {record.name} - {record.msg}{end}"
            return log_msg
    handler = logging.StreamHandler(sys.stdout)
    formatter = CustomFormatter("%(levelname)s - %(name)s - %(message)s")
    handler.setFormatter(formatter)
    log.setLevel(logging.INFO)
    log.addHandler(handler)

def main_descriptions():
    return '''\
Add static fuzzing instrumentation to binaries.

Producing an instrumented binary requires PeAR to be run on a platform that can
build the instrumented binary. E.g. to produce an instrumented 64-bit Windows
binary 64-bit MSVS compiler tools must be installed, and 32-bit tools for a
32-bit binary.

 example usage:
 - Instrument binary and produce new binary
   $ pear --ir-cache IR_CACHE_DIR --input-binary BINARY --output-dir OUT --gen-binary WinAFL --target-func ADDRESS

 - See help for a rewriter
   $ pear WinAFL -h
   $ pear Identity -h

 - Test if GTIRB can rewrite a binary
   $ pear --ir-cache IR_CACHE_DIR --input-binary BINARY --output-dir OUT --gen-binary Identity
'''

def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments for PeAR

    :returns: parsed arguments
    """
    # using hack here: https://stackoverflow.com/a/57582191
    # to display optional and required keyword arguments nicely
    parser = argparse.ArgumentParser(
        prog='PeAR',
        description=main_descriptions(),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    optional.add_argument(
        '-h',
        '--help',
        action='help',
        default=argparse.SUPPRESS,
        help='Show this help message and exit'
    )

    def path_exists(f):
        if not pathlib.Path(f).exists():
            parser.error(f'File "{f}" not found. \
Hint: running a docker container? Check volume mount location')
        else:
            return f

    input = required.add_mutually_exclusive_group(required=True)
    input.add_argument(
        '--input-ir', type=path_exists,
        help="Path to input GTIRB IR file."
    )
    input.add_argument(
        '--input-binary', type=path_exists,
        help="Path to input binary. Requires Ddisasm to be installed."
    )
    required.add_argument(
        '--output-dir', required=True, type=path_exists,
        help="Empty directory to store temporary files and instrumentation results."
    )
    optional.add_argument(
        '--ignore-nonempty', action='store_true', required=False,
        help="Ignore nonempty output directory."
    )
    optional.add_argument(
        '--hints', required=False, type=path_exists,
        help=textwrap.dedent('''\
            Hint file to use with ddisasm.
            See https://github.com/GrammaTech/ddisasm/blob/main/doc/source/GENERAL/5-AdvancedUsage.md
            for details.
        ''')
    )
    optional.add_argument(
        '--gen-binary', action='store_true', required=False,
        help=textwrap.dedent('''\
            Build instrumented binary. Requires gtirb-pprinter and build tools
            to be installed.
         ''')
    )
    optional.add_argument(
        '--gen-asm', action='store_true', required=False,
        help=textwrap.dedent('''\
            Generate instrumented assembly. Requires gtirb-pprinter to be
            installed.
        ''')
    )
    optional.add_argument(
        '--ir-cache', required=False, type=path_exists,
        help=textwrap.dedent('''\
            Dir to use to store generated IRs. Avoids repeatedly disassembling
            the same binary.
        ''')
    )
    optional.add_argument(
        '--func-names', required=False, type=path_exists,
        help=textwrap.dedent('''\
            Json files with object mapping address to function. Use Ghidra
            script pear/tools/ghidra_get_function_names.py to generate.
            schema: {'func_map': {<addr>: <name>}, 'base_addr': <load_addr>}
        ''')
    )
    optional.add_argument(
        '--gen-build-script', action='store_true', required=False,
        help=textwrap.dedent('''\
            Run tool, display commands that would be run without executing
            them, and create a build script to run on the target system to
            generate the instrumented binary.
        ''')
    )

    # Add rewriter subcommands
    rewriter_parsers = parser.add_subparsers(dest='tool',
                                             help='Available tools',
                                             required=True)
    for r in REWRITERS:
        r.build_parser(rewriter_parsers)

    args = parser.parse_args()

    # Set dry run global var
    if args.gen_build_script:
        GEN_SCRIPT_OPTS.is_dry_run = True

    # Get chosen rewriter class
    args.rewriter = REWRITER_MAP[args.tool]

    # Check output dir empty
    if not args.ignore_nonempty:
        if len(os.listdir(args.output_dir)) != 0:
            parser.error(f'Output dir "{args.output_dir}" not empty. To continue anyway, use --ignore-nonempty. This could break the rewriter.')

    return args

def preprocess_fixp_data_align(ir: gtirb.IR):
    '''
    Fix issue breaking data alignment in jump tables by manually setting all
    DataBlock's alignment to four.
    More info here: https://github.com/GrammaTech/gtirb-rewriting/issues/15
    :param ir: ir to fix
    '''
    module = ir.modules[0]
    alignment = _auxdata.alignment.get_or_insert(module)
    for db in module.data_blocks:
        alignment[db] = 1

def preprocess_add_function_names(ir: gtirb.IR, func_names: str):
    # Make sure func mappings are typed correctly
    # And subtract base address from func if PIE
    fn: dict[int, str] = {}
    with open(func_names) as f:
        _funcmap = json.load(f)
        b_addr = _funcmap['base_addr']
        b_addr = int(b_addr, 16) if b_addr.startswith('0x') else int(b_addr)
        for addr, name in _funcmap['func_map'].items():
            if type(addr) == str:
                addr = int(addr, 16) if addr.startswith('0x') else int(addr)
            if is_pie(ir.modules[0]):
                addr -= b_addr # subtract base address for PIE binaries
            fn[addr] = name
    # Rename functions
    names_set = 0
    module = ir.modules[0]
    for f_id, entryBlocks in module.aux_data["functionEntries"].data.items():
        for x in entryBlocks:
            if type(x) == CodeBlock and x.address != None and x.address in fn:
                name_sym = module.aux_data["functionNames"].data[f_id]
                name_sym.name = fn[x.address]
                names_set += 1
    log.info(f"Set {names_set} function names using function map")

# TODO make this a generic symbol renaming thing
def preprocess_rename_data_symbols(ir: gtirb.IR, orig: list[str], repl: list[str]):
    '''
    Replace symbol names in orig with repl. Case insentive search
    e.g. orig[X] -> repl[X]
    '''
    assert len(orig) == len(repl)
    orig = [x.lower() for x in orig]
    module = ir.modules[0]
    elf_symbol_info: dict[Symbol, tuple[int, str, str, str, int]]
    elf_symbol_info = _auxdata.elf_symbol_info.get_or_insert(module)
    for sym, (_, symtype, binding, visibility, _) in elf_symbol_info.items():
        name = sym.name
        if binding == 'LOCAL' and visibility != 'HIDDEN' \
                and symtype == 'OBJECT' and name.lower() in orig:
            sym.name = repl[orig.index(name.lower())]
            log.warning(f'Renaming data symbol "{name}" to "{sym.name}" to prevent issues on reassembly')

if __name__ == "__main__":
    setup_logger(log)
    args = parse_args()

    # Generate (and cache) IR if binary provided
    if args.input_binary: 
        basename = os.path.basename(args.input_binary)
        ir_file = f'{os.path.join(args.output_dir, basename)}.gtirb'
        ddisasm(
            args.input_binary,
            ir_file,
            ir_cache=args.ir_cache,
            hints=args.hints if args.hints else None
        )
        args.input_ir = ir_file

    # Try to get executable name from input filename
    basename = os.path.basename(args.input_ir)
    if basename.endswith('.gtirb'):
        basename = basename[:-len('.gtirb')]
    outname = (basename + '.' + args.rewriter.name()).replace('.exe', '')

    # load IR and generate mappings
    start_t = time.time()
    ir: gtirb.IR = gtirb.IR.load_protobuf(args.input_ir)
    mappings = get_address_to_byteblock_mappings(ir)
    diff = round(time.time()-start_t, 3)
    log.info(f'IR loaded in {diff} seconds')

    # Set build script output file if dry run
    build_script = ''
    if args.gen_build_script:
        build_script = os.path.join(args.output_dir, "build_" + outname)
        if ir.modules[0].file_format == gtirb.Module.FileFormat.PE:
            build_script += '.bat'
        elif ir.modules[0].file_format == gtirb.Module.FileFormat.ELF:
            build_script += '.sh'
            with open(build_script, 'w') as f:
                f.write('#!/bin/bash\nset -x\n')
            # make executable
            st = os.stat(build_script)
            os.chmod(build_script, st.st_mode | stat.S_IEXEC)
        GEN_SCRIPT_OPTS.gen_output = build_script

    # pre-process ARM64 binaries to fix switch identification
    switches = None
    if ir.modules[0].file_format == gtirb.Module.FileFormat.ELF \
            and ir.modules[0].isa == gtirb.Module.ISA.ARM64:
        switches = fix_arm64_switches(ir)
    # pre-process IR by recording given function names
    if args.func_names:
        preprocess_add_function_names(ir, args.func_names)
    # pre-process IR by renaming symbols with the same name as Intel AVX512
    #   opmask registers k0-k7 to kkX (e.g. k0 becomes kk0). To avoid issues
    #   when regenerating
    if ir.modules[0].file_format == gtirb.Module.FileFormat.ELF \
            and ir.modules[0].isa == gtirb.Module.ISA.X64:
        orig = [f'k{x}' for x in range(8)]
        repl = [f'kk{x}' for x in range(8)]
        preprocess_rename_data_symbols(ir, orig, repl)
        # offset is special keyword for gcc
        preprocess_rename_data_symbols(ir, ['offset'], ['_offset'])

    # Run chosen rewriter
    rewriter: Rewriter = args.rewriter(ir, args, mappings, args.gen_build_script)
    instrumented_ir = rewriter.rewrite()

    # Save instrumented IR to file and generate assembly or binary if needed
    if args.gen_asm or args.gen_binary:
        output_basename= os.path.join(args.output_dir, outname)
        rewriter.generate(output_basename, args.output_dir,
                          gen_assembly=args.gen_asm,
                          gen_binary=args.gen_binary,
                          switch_data=switches)

    if args.gen_build_script:
        log.info(f"Build script saved to: {build_script}")
