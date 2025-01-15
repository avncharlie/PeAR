import os
import sys
import json
import pathlib
import argparse

# yuck
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(os.path.dirname(SCRIPT_DIR)))
from pear.rewriters.trace.trace_rewriter import BasicBlockInfo

def parse_args():
    parser = argparse.ArgumentParser(description='Parse coverage information.')

    def path_exists(f):
        if not pathlib.Path(f).exists():
            parser.error(f'File "{f}" not found.')
        else:
            return f
    parser.add_argument('--aux-info', type=path_exists, required=True,
                        help='Auxiliary information file')
    parser.add_argument('--cov-file', type=path_exists, required=True,
                        help='Output coverage file from instrumented binary.')

    subparsers = parser.add_subparsers(dest='action', required=True,
                                       help='Action to perform')

    # GenerateEZCOV subparser
    gen_ezcov_p = subparsers.add_parser('GenerateEZCOV',
                                        help='Generate EZCOV output')

    # PrintExecution subparser
    print_exec_p = subparsers.add_parser('PrintExecution',
                                              help='Print execution details')
    args = parser.parse_args()
    return args

def print_execution(map: dict[int, BasicBlockInfo], coverage: list[int]):
    for id in coverage:
        print(map[id].str_repr)

def generate_ezcov(map: dict[int, BasicBlockInfo], coverage: list[int],
                   output: str):
    # We only care if a block was executed or not, not order of execution or
    # how many times we hit any particular block. This is mostly as DRCOV/EZCOV
    # doesn't support storing this information.
    unique_c = set(coverage)
    with open(output, 'w') as f:
        f.write("EZCOV VERSION: 1\n")
        for id in unique_c:
            start_addr = map[id].start_address
            size = map[id].size
            # PeARCov instrumentation only loads coverage of instrumented binary
            address_space = "[  ]" 
            f.write(f"{hex(start_addr)}, {size}, {address_space}\n")
    print(f"EZCOV saved to {output}")

def main():
    args = parse_args()
    aux_info = args.aux_info
    cov_file = args.cov_file
    action = args.action

    # Parse aux info to map of block id to block info
    map: dict[int, BasicBlockInfo] = {}
    with open(aux_info) as f:
        out = json.load(f)
        for x in out:
            bbinfo = BasicBlockInfo(
                id = x['id'],
                start_address = x['start_address'],
                inst_offset = x['inst_offset'],
                size = x['size'],
                str_repr = x['str_repr']
            )
            map[bbinfo.id] = bbinfo

    # Read coverage
    coverage: list[int] = []
    with open(cov_file, 'rb') as f:
        while True:
            b_id = f.read(4)
            if not b_id:
                break
            id = int.from_bytes(b_id, 'little')
            coverage.append(id)

    if action == 'PrintExecution':
        print_execution(map, coverage)
    elif action == 'GenerateEZCOV':
        output_f = cov_file + '.ezcov'
        generate_ezcov(map, coverage, output_f)


if __name__ == '__main__':
    main()
