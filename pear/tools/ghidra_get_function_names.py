'''
Add this directory as a script directory in ghidra:
 - Top toolbar -> Window -> Script Manager
 - In the toolbar of that window, there will be a button with the hover text "Manage Script Directories" (to the left of the red plus)
 - In the Bundle Manager window, click the green plus and find and add the directory this script is in.
 - Back in the Script Manager, search for the name of this file and double click to run it.
'''

import json
import os
from ghidra.util import Msg

def to_hex(n):
    # Jython appends L to hex address, so remove it
    hex_addr = hex(n)
    if hex_addr[-1] == 'L':
        hex_addr = hex_addr[:-1]
    return hex_addr

def run():
    # Get the function manager from the current program
    fm = currentProgram.getFunctionManager()
    prog_name = currentProgram.getName()
    base_addr = currentProgram.getImageBase().getOffset()

    func_map = {}

    # Iterate over all functions in forward order
    for func in fm.getFunctions(True):
        func_name = func.getName()
        func_address = func.getEntryPoint().getOffset()
        # remove illegal characters
        func_name = func_name.replace('@', 'AT')
        func_map[to_hex(func_address)] = func_name

    # Open a file chooser dialog so the user can select the dest of the output file
    dest_dir = askDirectory("Select output folder for function mappings", "Choose directory");
    dest_path = os.path.join(dest_dir.getAbsolutePath(), prog_name + '.funcmap.json')

    # Write the function mapping
    fm = {'func_map': func_map, 'base_addr': to_hex(base_addr)}
    with open(dest_path, 'w') as f:
        json.dump(fm, f, indent=2)

    print("Function mapping JSON written to: " + dest_path)
    Msg.showInfo(currentProgram, None, "Success", "Function mapping JSON written to:\n" + dest_path)

run()
