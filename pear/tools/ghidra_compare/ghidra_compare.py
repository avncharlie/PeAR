import os
import sys
import json
import logging
import argparse
from bisect import bisect_right

import gtirb
from gtirb.block import CodeBlock, DataBlock
from gtirb_capstone.instructions import GtirbInstructionDecoder

# yuck
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(SCRIPT_DIR))))
from pear.ddisasm import ddisasm
from pear.utils import run_cmd, is_pie, get_address_to_byteblock_mappings
from pear.__main__ import setup_logger

log = logging.getLogger(__package__)
GHIDRA_OUT = '/tmp/ghidra_comp'


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compare code and data detection between GTIRB and Ghidra"
    )
    parser.add_argument(
        "--ir",
        required=False,
        help="Gtirb IR ",
    )
    parser.add_argument(
        "--binary",
        required=True,
        help="Binary",
    )
    parser.add_argument(
        "--ghidra-install",
        required=True,
        help="Ghidra installation directory (e.g ~/tools/ghidra_11.4.1_PUBLIC)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    ghidra_dir = args.ghidra_install
    if not os.path.isdir(ghidra_dir) or \
            not os.path.isfile(os.path.join(ghidra_dir, 'support', 'analyzeHeadless')):
        print(f"Error: {ghidra_dir} doesn't look like a Ghidra install directory.")
        exit()

    binary = args.binary
    basename = os.path.basename(binary)
    ir = args.ir

    # generate IR if none
    if not ir:
        ir = os.path.join('/tmp/', basename + '.gtirb')
        ddisasm(binary, ir)
    if not os.path.isfile(ir):
        print("Error: IR file invalid, or IR failed to generate!")

    return (ir, binary, ghidra_dir, args.verbose)


def get_ranges(inference):
    """
    inference: {addr:int -> "code"/"data"}
    returns   : [(lo:int, hi:int, kind:str), ...]  with no gaps
               hi is inclusive; the next run (if any) starts at hi+1.
    """
    if not inference:
        return []
    addrs = sorted(inference)
    ranges = []
    cur_kind = inference[addrs[0]]
    range_start = addrs[0]
    for idx in range(1, len(addrs)):
        addr      = addrs[idx]
        this_kind = inference[addr]
        if this_kind != cur_kind:
            # close the previous run right before the first addr of the new kind
            ranges.append((range_start, addr - 1, cur_kind))
            range_start = addr
            cur_kind    = this_kind
    # flush the final run
    ranges.append((range_start, addrs[-1], cur_kind))
    return ranges

def _build_index(ranges):
    """
    Turn [(lo, hi, kind), ...] into two parallel lists:
        bounds  – ascending list of start addresses
        spans   – list of (hi, kind) aligned with bounds
    so we can O(log n) query the classification at any address.
    """
    bounds, spans = [], []
    for lo, hi, kind in ranges:
        bounds.append(lo); spans.append((hi, kind))
    return bounds, spans

def _kind_at(addr, bounds, spans, default="unknown"):
    """
    Binary-search the index to get the label at <addr>.
    """
    i = bisect_right(bounds, addr) - 1
    if i >= 0:
        hi, kind = spans[i]
        if addr <= hi:
            return kind
    return default

def diff_ranges(r1, r2, default="unknown"):
    """
    Return [(lo, hi, kind_in_r1, kind_in_r2), ...] where the two
    labellings differ.
    """
    # compress both sets into searchable indexes
    b1, s1 = _build_index(r1)
    b2, s2 = _build_index(r2)

    # candidate breakpoints: every start + (end+1) from both inputs
    split_pts = set()
    for lo, hi, _ in r1 + r2:
        split_pts.add(lo)
        split_pts.add(hi + 1)      # +1 keeps ranges inclusive
    cuts = sorted(split_pts)

    diffs = []
    for i in range(len(cuts) - 1):
        lo = cuts[i]
        hi = cuts[i + 1] - 1       # back to inclusive

        k1 = _kind_at(lo, b1, s1, default)
        k2 = _kind_at(lo, b2, s2, default)

        if k1 != k2:
            # merge with previous diff block if contiguous & same labels
            if diffs and diffs[-1][1] + 1 == lo and diffs[-1][2:] == (k1, k2):
                diffs[-1] = (diffs[-1][0], hi, k1, k2)
            else:
                diffs.append((lo, hi, k1, k2))

    return diffs

def get_ordered_syms(ir):
    real_symbols = filter(
                    lambda x: not x.name.startswith(".L") \
                        and x._payload is not None \
                        and hasattr(x._payload, "address") \
                        and x._payload.address is not None,
                    ir.symbols)
    return sorted(list(real_symbols), key=lambda x: x._payload.address)

def main():
    setup_logger(log)
    ir, binary, ghidra_dir, verbose = parse_args()
    ir: gtirb.IR = gtirb.IR.load_protobuf(ir)
    basename = os.path.basename(binary)

    # Run Ghidra analysis 
    ghidra_out_f = GHIDRA_OUT + basename + '.json'
    ghidra_headless = os.path.join(ghidra_dir, 'support', 'analyzeHeadless')
    cmd = [ghidra_headless, '/tmp', 'temp_proj', '-deleteProject', '-import', binary, '-scriptPath', SCRIPT_DIR, '-postScript', 'ghidra_list_code_addrs.py', ghidra_out_f]

    run_cmd(cmd, should_print=verbose)
    with open(ghidra_out_f) as f:
        ghidra_out = json.load(f)
    
    # Subtract base address if PIE
    base_addr = int(ghidra_out['base_addr'], 16)
    ghidra_inference = ghidra_out['type']
    g_inference = {}
    for addr, t in ghidra_inference.items():
        addr = int(addr, 16)
        if is_pie(ir.modules[0]):
            addr -= base_addr
        g_inference[addr] = t
    # Get code / data address ranges
    ghidra_ranges = get_ranges(g_inference)
    #print(f"GHIDRA:")
    #for lo, hi, k in ghidra_ranges:
    #    print(f"{hex(lo)}–{hex(hi)}\t{k}")

    d_inference = {}
    for block in sorted(ir.byte_blocks, key=lambda e: e.address):
        if type(block) is DataBlock:
            d_inference[block.address] = 'data'
        if type(block) is CodeBlock:
            d_inference[block.address] = 'code'

    #print()
    #for x in sorted(d_inference.keys()):
    #    print(hex(x), d_inference[x])

    ddisasm_ranges = get_ranges(d_inference)
    #print()
    #print(f"DDISASM:")
    #for lo, hi, k in ddisasm_ranges:
    #    print(f"{hex(lo)}–{hex(hi)}\t{k}")
    
    # Cut Ghidra ranges to start where ddisasm starts
    if ddisasm_ranges[0][0] > ghidra_ranges[0][0]:
        assert ghidra_ranges[0][1] > ddisasm_ranges[0][0]
        ghidra_ranges[0] = (
            ddisasm_ranges[0][0],
            ghidra_ranges[0][1],
            ghidra_ranges[0][2]
        )

    mismatches = diff_ranges(ghidra_ranges, ddisasm_ranges)

    plt_start = plt_end = -1
    for x in ir.modules[0].sections:
        if x.name == '.plt':
            plt_start, plt_end = x.address, x.address+x.size
            break

    # ─── simple colour helpers ────────────────────────────────────────────
    CSI   = "\033["          # “Control Sequence Introducer”
    RESET = f"{CSI}0m"

    BOLD  = f"{CSI}1m"
    DIM   = f"{CSI}2m"

    FG = {
        "blk": f"{CSI}30m",
        "red": f"{CSI}31m",
        "grn": f"{CSI}32m",
        "ylw": f"{CSI}33m",
        "blu": f"{CSI}34m",
        "mag": f"{CSI}35m",
        "cyn": f"{CSI}36m",
        "wht": f"{CSI}37m",
        "gry": f"{CSI}90m",   # bright black ≈ grey
    }


    decoder = GtirbInstructionDecoder(ir.modules[0].isa)
    nop_counter = 0
    ddisasm_code_conflicts = 0
    plt_counter = 0

    print(f"\n\n{BOLD}{FG['cyn']}"
          "========================= DISAGREEMENTS ========================="
          f"{RESET}")

    syms = get_ordered_syms(ir)

    for lo, hi, gk, dk in mismatches:
        # find nearest symbols
        previous_sym = None
        next_sym = None
        for x in syms:
            if x._payload.address > lo:
                next_sym = x
                break
            previous_sym = x

        if gk == "data" and dk == "code":
            hdr = FG["mag"]                                  # DDisasm flags code
        elif gk == "code" and dk == "data":
            hdr = FG["ylw"]                                  # Ghidra flags code
        else:
            hdr = FG["wht"]

        header = f"{hdr}{hex(lo)} – {hex(hi)}{RESET}: Ghidra={gk}, DDisasm={dk}\n"
        header += f"Previous symbol: {previous_sym.name} @ {hex(previous_sym._payload.address)} (+{lo - previous_sym._payload.address})"
        if next_sym:
            header += f", Next symbol: {next_sym.name} @ {hex(next_sym._payload.address)}"
        header += "\n"
        to_print = header

        if gk == "data" and dk == "code":
            found, all_nop = False, True
            blocks = ir.byte_blocks_at(lo if lo == hi else range(lo, hi))

            for block in blocks:
                found = True
                for i in decoder.get_instructions(block):
                    mnem = i.insn_name()
                    # grey NOPs; green everything else
                    colour = FG["gry"] if mnem == "nop" else FG["grn"]
                    to_print += f"{colour}{hex(i.address)}: {mnem} {i.op_str}{RESET}\n"
                    if mnem != "nop":
                        all_nop = False
            if all_nop:
                nop_counter += 1
            if not found:
                print(len(list(ir.byte_blocks_at(range(lo, hi)))))
                print(len(list(ir.byte_blocks_at(lo))))
                print(to_print + FG["red"] + "DDisasm code block not found\n" + RESET)
            if not all_nop:
                print(to_print)
                ddisasm_code_conflicts += 1

        elif gk == "code" and dk == "data":
            if lo >= plt_start and hi <= plt_end:
                plt_counter += 1
            else:
                print(to_print)
        else:
            print(to_print)

    print(f"{DIM}Total Ddisasm=data, Ghidra=code conflicts: {ddisasm_code_conflicts}{RESET}")
    print(f"{DIM}Total NOP conflicts hidden: {nop_counter}{RESET}")
    print(f"{DIM}Total conflicts within PLT hidden: {plt_counter}{RESET}")

    if is_pie(ir.modules[0]):
        print(f'Base address in Ghidra: {hex(base_addr)}')

if __name__ == "__main__":
    main()
