import os
import sys
import time
import json
import logging
import pathlib
import textwrap
import argparse

from collections import OrderedDict

import gtirb

from . import utils
from .ddisasm import ddisasm
from . import REWRITERS, REWRITER_MAP
from .rewriters.rewriter import Rewriter

#format="%(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)",

# TODO: remove this color stuff
green = '\033[92m'
blue = '\033[94m'
end = '\033[0m'
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format=blue + "%(levelname)s - %(name)s - %(message)s" + end
)
log = logging.getLogger(__package__)

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

    # Add rewriter subcommands
    rewriter_parsers = parser.add_subparsers(dest='rewriter',
                                             help='Available rewriters',
                                             required=True)
    for r in REWRITERS:
        r.build_parser(rewriter_parsers)

    args = parser.parse_args()

    # Get chosen rewriter class
    args.rewriter = REWRITER_MAP[args.rewriter]

    # Check output dir empty
    if not args.ignore_nonempty:
        if len(os.listdir(args.output_dir)) != 0:
            parser.error(f'Output dir "{args.output_dir}" not empty. To continue anyway, use --ignore-nonempty. This could break the rewriter.')

    return args

if __name__ == "__main__":
    args = parse_args()

    # Generate (and cache) IR if binary provided
    if args.input_binary: 
        basename = os.path.basename(args.input_binary)
        ir_file = f'{os.path.join(args.output_dir, basename)}.gtirb'
        ddisasm(
            args.input_binary,
            ir_file,
            ir_cache=args.ir_cache
        )
        args.input_ir = ir_file

    # Try to get executable name from input filename
    basename = os.path.basename(args.input_ir)
    if basename.endswith('.gtirb'):
        basename = basename[:-len('.gtirb')]

    # load IR and generate mappings
    start_t = time.time()
    ir = gtirb.IR.load_protobuf(args.input_ir)
    mappings = utils.get_address_to_byteblock_mappings(ir)
    diff = round(time.time()-start_t, 3)
    log.info(f'IR loaded in {diff} seconds')

    # Run chosen rewriter
    rewriter: Rewriter = args.rewriter(ir, args, mappings)
    instrumented_ir = rewriter.rewrite()

    # Save instrumented IR
    instrumented_ir_fname = f'{os.path.join(args.output_dir, basename)}.instrumented.gtirb'
    instrumented_ir.save_protobuf(instrumented_ir_fname)
    log.info(f'Instrumented IR saved to: {instrumented_ir_fname}')

    # Generate assembly or binary if needed
    if args.gen_asm or args.gen_binary:
        output_basename= f'{os.path.join(args.output_dir, basename)}.instrumented'.replace('.exe', '')
        rewriter.generate(instrumented_ir_fname,
                          output_basename, args.output_dir,
                          gen_assembly=args.gen_asm,
                          gen_binary=args.gen_binary)