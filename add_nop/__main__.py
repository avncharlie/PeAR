import os
import sys
import time
import logging
import pathlib
import textwrap
import argparse

import gtirb
from gtirb_rewriting import PassManager

from .gtirb_wrappers import ddisasm, gtirb_pprinter
from .nop_pass import AddNopPass

#format="%(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)",

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(levelname)s - %(name)s - %(message)s"
)
log = logging.getLogger(__package__)

def get_args():
    parser = argparse.ArgumentParser(
        description= textwrap.dedent('''\
            Add a nop to program entrypoint and start of every function.
            Supports x86-64 Linux and Windows binaries. Takes a binary or GTIRB
            IR as input, using Ddisasm to disassemble binary if required.
            Optionally caches generated IR of given binary in provided cache.
            Outputs an instrumented GTIRB IR. Optionally generates assembly or a
            binary from IR using gtirb-pprinter. Supports pretty printing
            binaries using a remote SSH-accessible build server.
        '''),
        formatter_class=argparse.RawTextHelpFormatter
    )

    def path_exists(f):
        if not pathlib.Path(f).exists():
            parser.error(f'File "{f}" not found. \
Hint: running a docker container? Check volume mount location')
        else:
            return f

    # show required arguments in seperate header when displaying help
    required = parser.add_argument_group('required arguments')

    # take IR or binary as input
    input = required.add_mutually_exclusive_group(required=True)
    input.add_argument(
        '--input-ir', required=False, type=path_exists,
        help="Path to input GTIRB IR file."
    )
    input.add_argument(
        '--input-binary', required=False, type=path_exists,
        help="Path to input binary. Requires Ddisasm to be installed."
    )

    # output folder + format
    required.add_argument(
        '--output-dir', required=True, type=path_exists,
        help="Directory to store temporary files and instrumentation results."
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

    # build server
    parser.add_argument(
        '--build-server', required=False,
        help=textwrap.dedent('''\
            SSH address of Windows server to use for Windows binary
            pretty-printing (e.g. user@ip).
            Build server requirements:
              - SCP supported
              - SSH keys set up for passwordless access
              - gtirb-pprinter installed and on path
              - working dir exists (set with --build-server-working-dir)
        ''')
    )
    parser.add_argument(
        '--build-server-working-dir', required=False,
        default='./gtirb_pprinter_output',
        help="Dir to use on build server. (default: %(default)s)"
    )
    parser.add_argument(
        '--skip-remote-dir-check', action='store_false', required=False,
        help="Skip checking that remote working directory exists."
    )

    # ir cache
    parser.add_argument(
        '--ir-cache', required=False, type=path_exists,
        help=textwrap.dedent('''\
            Dir to use to store generated IRs. Avoids repeatedly disassembling
            the same binary. Highly recommended.
        ''')
    )

    args = parser.parse_args()

    return args

if __name__ == "__main__":
    args = get_args()

    if args.input_binary: 
        # generate IR if needed
        basename = os.path.basename(args.input_binary)
        ir_file = f'{os.path.join(args.output_dir, basename)}.gtirb'
        ddisasm(
            args.input_binary,
            ir_file,
            ir_cache=args.ir_cache
        )
        args.input_ir = ir_file

    basename = os.path.basename(args.input_ir)
    if basename.endswith('.gtirb'):
        basename = basename[:-len('.gtirb')]

    # load IR
    start_t = time.time()
    ir = gtirb.IR.load_protobuf(args.input_ir)
    diff = round(time.time()-start_t, 3)
    log.info(f'IR loaded in {diff} seconds')

    # run pass
    manager = PassManager()
    manager.add(AddNopPass())
    manager.run(ir)

    # save modified IR
    ir_modified_file = f'{os.path.join(args.output_dir, basename)}.instrumented.gtirb'
    ir.save_protobuf(ir_modified_file)
    log.info(f'Instrumented IR saved to: {ir_modified_file}')

    # generate pretty-printed output if needed
    output_file = f'{os.path.join(args.output_dir, basename)}.instrumented'
    
    ssh_address=None
    remote_working_dir=None
    skip_check=None
    if args.build_server:
        ssh_address=args.build_server
        remote_working_dir=args.build_server_working_dir
        skip_check=args.skip_remote_dir_check

    # local builds
    if args.gen_asm:
        output_file += '.S'
        gtirb_pprinter(ir_modified_file, output_file, gen_assembly=True,
                       ssh_address=args.build_server,
                       remote_working_dir=args.build_server_working_dir,
                       check_remote_dir_exists=skip_check)
        log.info(f'Generated assembly saved to: {output_file}')

    elif args.gen_binary:
        gtirb_pprinter(ir_modified_file, output_file, gen_binary=True,
                       ssh_address=args.build_server,
                       remote_working_dir=args.build_server_working_dir,
                       check_remote_dir_exists=skip_check)
        log.info(f'Generated binary saved to: {output_file}')
