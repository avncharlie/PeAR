"""
TODO: use:  .decl data_in_code(Begin:address,End:address)
         instead, maybe
"""

import sys
import json
import argparse

import gtirb
import gtirb_functions

def gen_hints(ir, data_symbols, data_between_funcs, not_symbolic_operands):
    '''
    Generate ddisasm hints to mark known data symbols

    data_symbols: dict { data_symbol: size_in_bytes }
      e.g., {"K256": 256, "K256_shaext": 256}

    data_between_funcs: dict { func1: func2 }
      means the bytes strictly between the end of func1 and the start of func2 are data

    not_symbolic_operands: dict { address: operand }
      means operand number `operand` of the instruction at address is not a symbolic operand
    '''
    find_funcs = list(data_between_funcs.keys()) + list(data_between_funcs.values())

    # Collect (sym_name, start_addr, end_addr_exclusive)
    sym_addrs = []
    found_syms = set()
    for sym in ir.symbols:
        if sym.name in data_symbols:
            start = sym._payload.address
            sym_addrs.append((sym.name, start, start + int(data_symbols[sym.name])))
            found_syms.add(sym.name)

    # Warn for missing symbols
    for s in data_symbols.keys():
        if s not in found_syms:
            print(f"[!] Warning: Symbol '{s}' not found in IR", file=sys.stderr)

    # Map function name -> (start, end_exclusive)
    f_addrs = {}
    found_funcs = set()
    functions = gtirb_functions.Function.build_functions(ir.modules[0])
    for func in functions:
        names = set(func.names)
        match_names = names & set(find_funcs)
        if match_names:
            blocks = sorted(func.get_all_blocks(), key=lambda b: b.address)
            start = blocks[0].address
            end = blocks[-1].address + blocks[-1].size
            for n in match_names:
                f_addrs[n] = (start, end)
                found_funcs.add(n)

    # Warn for missing functions in data_between_funcs
    for f in find_funcs:
        if f not in found_funcs:
            print(f"[!] Warning: Function '{f}' not found in IR", file=sys.stderr)

    hints = []

    # Generate "invalid" for each data symbol byte range
    for sym, start, end in sym_addrs:
        for x in range(start, end):
            hints.append(f'disassembly.invalid\t{hex(x)}\t{sym}')

    # Generate "invalid" for bytes strictly between two functions
    for first, second in data_between_funcs.items():
        if first not in f_addrs or second not in f_addrs:
            continue
        end_first = f_addrs[first][1]
        start_second = f_addrs[second][0]
        for x in range(end_first, start_second):
            hints.append(f'disassembly.invalid\t{hex(x)}\tin_between_{first}_{second}')

    # Generate "symbolic_operand_point" fact with negative points for operands that are not symbolic
    for address, operand in not_symbolic_operands.items():
        hints.append(f'disassembly.symbolic_operand_point\t{address}\t{operand}\t-100\tknown_constant')

    return "\n".join(hints)

def parse_args(argv):
    p = argparse.ArgumentParser(description="Generate ddisasm hints from GTIRB")
    p.add_argument("--ir", required=True, help="Input IR file (.gtirb)")
    p.add_argument("--data-symbols", default=None,
                   help='JSON string mapping known data symbols in form symbol->size, e.g. \'{"K256":256}\'')
    p.add_argument("--data-between-funcs", default=None,
                   help='JSON string mapping data between functions in form func1->func2, e.g. \'{"A":"B"}\'')
    p.add_argument("--not-symbolic-operands", default=None,
                   help='JSON string mapping known constants in operations in from instruction_address->operand, e.g. \'{0xf00:1}\' (i.e operand one of instruction at 0xf00 is not symbolic / a constant)')
    p.add_argument("--out", default=None,
                   help="Output file for hints (optional, defaults to stdout)")
    return p.parse_args(argv)

def parse_json_or_empty(s, expect_type=dict, arg_name="argument"):
    if s is None:
        return {}
    try:
        obj = json.loads(s)
    except json.JSONDecodeError as e:
        raise SystemExit(f"Invalid JSON for {arg_name}: {e}")
    if not isinstance(obj, expect_type):
        raise SystemExit(f"{arg_name} must be a {expect_type.__name__}, got {type(obj).__name__}")
    return obj


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    ir = gtirb.IR.load_protobuf(args.ir)

    data_syms = parse_json_or_empty(args.data_symbols, dict, "--data-symbols")
    data_between_funcs = parse_json_or_empty(args.data_between_funcs, dict, "--data-between-funcs")
    not_symbolic_operands = parse_json_or_empty(args.not_symbolic_operands, dict, "--not-symbolic-operands")

    out_str = gen_hints(ir, data_syms, data_between_funcs, not_symbolic_operands)

    if args.out:
        with open(args.out, "w") as f:
            f.write(out_str + "\n")
    else:
        print(out_str)
