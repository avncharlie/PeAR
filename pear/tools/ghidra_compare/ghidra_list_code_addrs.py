#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Emit one line per address that Ghidra classifies as an Instruction.
If you only want function entry-points, see the comment at the end.
"""

import json
from ghidra.program.model.listing import Instruction, Data

def to_hex(n):
    # Jython appends L to hex address, so remove it
    hex_addr = hex(n)
    if hex_addr[-1] == 'L':
        hex_addr = hex_addr[:-1]
    return hex_addr

code_or_data = {}
for cu in currentProgram.getListing().getCodeUnits(True):
    addr = to_hex(cu.getAddress().getOffset())
    if isinstance(cu, Instruction):
        code_or_data[addr] = "code"
    elif isinstance(cu, Data):
        code_or_data[addr] = "data"

base_addr = currentProgram.getImageBase().getOffset()
out = {
    "type": code_or_data,
    "base_addr": to_hex(base_addr)
}

flags = getScriptArgs()
if len(flags) == 0:
    print(json.dumps(out, indent=2))
else:
    outf = flags[0]
    with open(outf, 'w') as f:
        json.dump(out, f, indent=2)

