import os
import sys
import time
import logging
import pathlib
import textwrap
import argparse

import gtirb

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

Producing instrumented assembly can be done on any environment with
gtirb-pprinter installed. 

Producing an instrumented binary requires PeAR to be run on a platform that can
build the instrumented binary. E.g. to produce an instrumented 64-bit Windows
binary 64-bit MSVS compiler tools must be installed and to produce a Linux
binary GCC must be installed.'''
# example usage:
# - Instrument binary and produce new binary
#   python3 -m pear --input-binary BINARY --output-dir OUTPUT_DIR --gen-binary --target-func ADDR
# - Instrument binary and cache IR and produce instrumented assembly
#   python3 -m pear --input-binary BINARY --output-dir OUTPUT_DIR --ir-cache CACHE_DIR --gen-asm --target-func ADDR
# - Instrument binary and cache IR and produce instrumented binary and assembly (recommended)
#   python3 -m pear --input-binary BINARY --output-dir OUTPUT_DIR --ir-cache CACHE_DIR --gen-asm --gen-binary --target-func ADDR
# - Instrument GTIRB IR and produce instrumented GTIRB IR
#   python3 -m pear --input-IR IR_FILE --output-dir OUTPUT_DIR --ir-cache CACHE_DIR --target-func ADDR'''

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
        help="Directory to store temporary files and instrumentation results."
    )
    optional.add_argument(
        '--gen-binary', action='store_true', required=False,
        help=textwrap.dedent('''\
            Build instrumented binary. Requires gtirb-pprinter to be installed,
            as well as either GCC for Linux binaries or Microsoft assembler for
            Windows binaries. See '--build-server' option for doing build on
            seperate machine.
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
        r_name, r_desc = r.get_info()
        r_parser = rewriter_parsers.add_parser(r_name, help=r_desc)
        r.build_parser(r_parser)

    args = parser.parse_args()
    args.rewriter = REWRITER_MAP[args.rewriter]

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

    # load IR
    start_t = time.time()
    ir = gtirb.IR.load_protobuf(args.input_ir)
    diff = round(time.time()-start_t, 3)
    log.info(f'IR loaded in {diff} seconds')

    # Run chosen rewriter
    rewriter: Rewriter = args.rewriter(ir, args)
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