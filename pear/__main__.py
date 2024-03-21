import os
import sys
import time
import shutil
import logging
import pathlib
import textwrap
import argparse

import gtirb
from gtirb_rewriting import PassManager

from .gtirb_wrappers import ddisasm, gtirb_pprinter
from .winafl_pass import (
    AddWinAFLDataPass,
    AddWinAFLPass
)
from . import utils

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


def get_args() -> argparse.Namespace:
    """
    Parse command line arguments for PeAR

    :returns: parsed arguments
    """
    # TODO: update description
    parser = argparse.ArgumentParser(
        description= textwrap.dedent(f'''\
Add WinAFL-compatible static fuzzing instrumentation to binaries.

Producing instrumented assembly can be done on any environment with
gtirb-pprinter installed. 

Producing an instrumented binary requires PeAR to be run on a platform that can
build the instrumented binary. E.g. to produce an instrumented 64-bit Windows
binary 64-bit MSVS compiler tools must be installed and to produce a Linux
binary GCC must be installed.

example usage:
- Instrument binary and produce new binary
  python3 -m pear --input-binary BINARY --output-dir OUTPUT_DIR --gen-binary --target-func ADDR
- Instrument binary and cache IR and produce instrumented assembly
  python3 -m pear --input-binary BINARY --output-dir OUTPUT_DIR --ir-cache CACHE_DIR --gen-asm --target-func ADDR
- Instrument binary and cache IR and produce instrumented binary and assembly (recommended)
  python3 -m pear --input-binary BINARY --output-dir OUTPUT_DIR --ir-cache CACHE_DIR --gen-asm --gen-binary --target-func ADDR
- Instrument GTIRB IR and produce instrumented GTIRB IR
  python3 -m pear --input-IR IR_FILE --output-dir OUTPUT_DIR --ir-cache CACHE_DIR --target-func ADDR
        '''),
        formatter_class=argparse.RawTextHelpFormatter
    )

    def path_exists(f):
        if not pathlib.Path(f).exists():
            parser.error(f'File "{f}" not found. \
Hint: running a docker container? Check volume mount location')
        else:
            return f

    def is_hex_address(loc):
        try:
            return int(loc, 16)
        except ValueError:
            parser.error(f'Can\'t parse "{loc}" as address, please provide hex address (e.g. 0x75a0)')

    # show required arguments in seperate header when displaying help
    required = parser.add_argument_group('required arguments')

    # take IR or binary as input
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
    required.add_argument(
        '--target-func', required=True, type=is_hex_address,
        help="Address of target function that will be interrogated during fuzzing"
    )

    parser.add_argument(
        '--gen-binary', action='store_true', required=False,
        help=textwrap.dedent('''\
            Build instrumented binary. Requires gtirb-pprinter to be installed,
            as well as either GCC for Linux binaries or Microsoft assembler for
            Windows binaries. See '--build-server' option for doing build on
            seperate machine.
         ''')
    )
    parser.add_argument(
        '--gen-asm', action='store_true', required=False,
        help=textwrap.dedent('''\
            Generate instrumented assembly. Requires gtirb-pprinter to be
            installed.
        ''')
    )

    # ir cache
    parser.add_argument(
        '--ir-cache', required=False, type=path_exists,
        help=textwrap.dedent('''\
            Dir to use to store generated IRs. Avoids repeatedly disassembling
            the same binary.
        ''')
    )

    args = parser.parse_args()

    return args

if __name__ == "__main__":
    args = get_args()

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

    # Store addresses of basic blocks before our instrumentation modifies this
    mappings = utils.get_address_to_codeblock_mappings(ir)

    # Instrument!
    passes = [
        AddWinAFLDataPass(),
        AddWinAFLPass(mappings, args.target_func)
    ]
    for p in passes:
        manager = PassManager()
        manager.add(p)
        manager.run(ir)

    # Save modified IR
    instrumented_ir_fname = f'{os.path.join(args.output_dir, basename)}.instrumented.gtirb'
    ir.save_protobuf(instrumented_ir_fname)
    log.info(f'Instrumented IR saved to: {instrumented_ir_fname}')

    if args.gen_asm or args.gen_binary:
        # Try to pick suitable output filename
        output_basename= f'{os.path.join(args.output_dir, basename)}.instrumented'.replace('.exe', '')

        # Generate output binary / assembly
        gtirb_pprinter(instrumented_ir_fname, ir, output_basename, args.output_dir, 
                    gen_assembly=args.gen_asm, gen_binary=args.gen_binary)

        ## always gen asm locally 
        # if args.gen_asm:
        #    output_file += '.S'
        #    gtirb_pprinter(instrumented_ir_fname, ir, output_file, args.output_dir,
        #                gen_assembly=True)
        #    log.info(f'Generated assembly saved to: {output_file}')

        # ssh_address=None
        # remote_working_dir=None
        # skip_check=None
        # if args.build_server:
        #    ssh_address=args.build_server
        #    remote_working_dir=args.build_server_working_dir
        #    skip_check=args.skipdir_check

        # if args.gen_binary:
        #    output_file += '.exe'
        #    gtirb_pprinter(instrumented_ir_fname, ir, output_file, args.output_dir,
        #                gen_binary=True,
        #                ssh_address=args.build_server,
        #                static_lib_link=r"C:\Users\alvin\Documents\lib-testing\32\afl-staticinstr.obj",
        #                remote_working_dir=args.build_server_working_dir,
        #                checkdir_exists=skip_check)
        #    log.info(f'Generated binary saved to: {output_file}')