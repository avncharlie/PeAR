# pyright: reportAttributeAccessIssue=false

import os
import sys
import time
import stat
import logging
import pathlib
import textwrap
import argparse

import gtirb

from . import REWRITERS, REWRITER_MAP, GEN_SCRIPT_OPTS
from .utils import get_address_to_byteblock_mappings
from .ddisasm import ddisasm
from .preprocess import (
    preprocess_add_function_names,
    preprocess_rename_data_symbols,
    preprocess_pe_delay_imports,
    preprocess_pe_fix_ordinal_exports,
)
from .rewriters.rewriter import Rewriter
from .arch_utils.linux_utils import fix_arm64_switches, LinuxUtils

log = logging.getLogger(__package__)

def setup_logger(log, level=logging.INFO):
    # ANSI colors
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[94m',     # Blue
        'WARNING': '\033[93m',  # Yellow
        'ERROR': '\033[91m',    # Red
        'CRITICAL': '\033[95m', # Magenta
        'RESET': '\033[0m',
    }

    class CustomFormatter(logging.Formatter):
        def format(self, record):
            color = COLORS.get(record.levelname, '')
            reset = COLORS['RESET']
            log_msg = f"{color}{record.levelname} - {record.name} - {record.getMessage()}{reset}"
            return log_msg

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CustomFormatter())
    log.setLevel(level)
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
        '--debug', action='store_true', required=False,
        help="Turn on debug logging."
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

if __name__ == "__main__":
    args = parse_args()
    setup_logger(log, level=logging.DEBUG if args.debug else logging.INFO)

    if not args.gen_asm and not args.gen_binary:
        log.warning('Neither --gen-asm or --gen-binary passed so nothing will be generated')

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
    outname = (basename + '.' + args.rewriter.name())\
        .replace('.exe', '').replace('.dll', '')

    # load IR and generate mappings
    start_t = time.time()
    ir: gtirb.IR = gtirb.IR.load_protobuf(args.input_ir)
    mappings = get_address_to_byteblock_mappings(ir)
    diff = round(time.time()-start_t, 3)
    log.info(f'IR loaded in {diff} seconds')

    # Check not linux shared library
    if ir.modules[0].file_format == gtirb.Module.FileFormat.ELF \
            and LinuxUtils.is_sharedlib(ir):
        log.error('Linux shared library regeneration not implemented yet -'
                    + ' please raise this as an issue on Github')
        exit(1)

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
    if ir.modules[0].file_format == gtirb.Module.FileFormat.PE:
        if not args.input_binary:
            log.error("If rewriting PE files, please pass original binary (as well as IR if you have it)")
            exit()
        preprocess_pe_delay_imports(ir, args.input_binary)
        preprocess_pe_fix_ordinal_exports(ir)

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