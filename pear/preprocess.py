import json
import logging

import gtirb
from gtirb import Symbol, CodeBlock, ProxyBlock
import gtirb_rewriting._auxdata as _auxdata

import pefile

from .utils import is_pie, find_symbol

log = logging.getLogger(__name__)

def preprocess_fix_data_align(ir: gtirb.IR):
    '''
    Fix issue breaking data alignment in jump tables by manually setting all
    DataBlock's alignment to four.
    More info here: https://github.com/GrammaTech/gtirb-rewriting/issues/15
    :param ir: ir to fix
    '''
    module = ir.modules[0]
    alignment = _auxdata.alignment.get_or_insert(module)
    for db in module.data_blocks:
        alignment[db] = 1

def preprocess_add_function_names(ir: gtirb.IR, func_names: str):
    # Make sure func mappings are typed correctly
    # And subtract base address from func if PIE
    fn: dict[int, str] = {}
    with open(func_names) as f:
        _funcmap = json.load(f)
        b_addr = _funcmap['base_addr']
        b_addr = int(b_addr, 16) if b_addr.startswith('0x') else int(b_addr)
        for addr, name in _funcmap['func_map'].items():
            if type(addr) == str:
                addr = int(addr, 16) if addr.startswith('0x') else int(addr)
            if is_pie(ir.modules[0]):
                addr -= b_addr # subtract base address for PIE binaries
            fn[addr] = name
    # Rename functions
    names_set = 0
    module = ir.modules[0]
    for f_id, entryBlocks in module.aux_data["functionEntries"].data.items():
        for x in entryBlocks:
            if type(x) == CodeBlock and x.address != None and x.address in fn:
                name_sym = module.aux_data["functionNames"].data[f_id]
                name_sym.name = fn[x.address]
                names_set += 1
    log.info(f"Set {names_set} function names using function map")

# TODO make this a generic symbol renaming thing
def preprocess_rename_data_symbols(ir: gtirb.IR, orig: list[str], repl: list[str]):
    '''
    Replace symbol names in orig with repl. Case insentive search
    e.g. orig[X] -> repl[X]
    '''
    assert len(orig) == len(repl)
    orig = [x.lower() for x in orig]
    module = ir.modules[0]
    elf_symbol_info: dict[Symbol, tuple[int, str, str, str, int]]
    elf_symbol_info = _auxdata.elf_symbol_info.get_or_insert(module)
    for sym, (_, symtype, binding, visibility, _) in elf_symbol_info.items():
        name = sym.name
        if binding == 'LOCAL' and visibility != 'HIDDEN' \
                and symtype == 'OBJECT' and name.lower() in orig:
            sym.name = repl[orig.index(name.lower())]
            log.warning(f'Renaming data symbol "{name}" to "{sym.name}" to prevent issues on reassembly')

def preprocess_pe_fix_ordinal_exports(ir: gtirb.IR):
    '''
    Name the gtirb Symbols corresponding to ordinal exports, so the generated
    assembly will work
    '''
    module = ir.modules[0]
    pe_export_entries = module.aux_data['peExportEntries'].data
    for addr, ordinal, func_name in pe_export_entries:
        if not func_name:
            blocks = list(ir.byte_blocks_at(addr))
            assert len(blocks) > 0, f"Could not find ByteBlock corresponding to ordinal export {ordinal}!"
            db = blocks[0]
            local_sym = find_symbol(ir, db)
            local_sym.name = f"{module.name.split('.')[0]}_ord_func_{ordinal}"

def preprocess_pe_delay_imports(ir: gtirb.IR, bin: str):
    '''
    Rewire symbols imported from delay-loaded DLLs as standardf imports, as
    ddisasm doesn't currently process delay-loaded imports. This will mean that
    if the binary uses a custom delay-load helper is used, it will break...

    How GTIRB handles external calls:

    The libraries that gtirb-pprinter puts at the top of generated
    asm (INCLUDELIB x) are contents of the 'libraries' aux table.
    
    The def files created by gtirb-pprinter and PeAR are generated from the 
    'peImportEntries' table. (map symbol to dll that exports it)

    Calls to external symbols rely on the 'symbolForwarding' table. This maps
    between { local symbols: external symbol }. These local symbols get
    replaced / proxied with the external symbol at pretty print time.

    E.g.: instruction at 0x100 calls 'bar' from 'foo.dll'.
     - 'libraries' table will contain 'foo.dll'
       So 'INCLUDELIB foo.dll.lib' will be generated.
     - 'peImportEntries' table will contain (<address>, <is_ordinal>, 'bar', 'foo.dll')
       So 'foo.dll.def' will be generated stating that 'bar' is an import
     - `symbolForwarding' table will contain {<local sym>: <bar symbol>}
       There will be a SymAddrConst symbolic expression at instruction 0x100
       identifying a call to the <local sym>.
       So at pretty printing time, this call will be instead routed to
       <bar symbol> as it is in the symbol forwarding table.
     - `peImportedSymbols` table should contain both the extern sym.
     
     So to rewire these imports as standard ones:
     - Use pefile to find these imports and the address they IAT address they
       resolve to in the current binary.
     - Find the DataBlock of this IAT address and the corresponding Symbol
     - Create new symbol for the external symbol import (with a ProxyBlock
       payload). 
     - Add a mapping { IAT symbol: new symbol } to the `symbolForwarding` table
     - Add new symbol to `peImportedSymbol` table
     - Add DLL into `libraries` table if it doesn't exist already
     - Add DLL + delay loaded imports to `peImportEntries` table

    :param ir: ir to fix
    :param bin: path to original PE
    '''
    pe = pefile.PE(bin)
    if not hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        # no delay imports to fix
        return

    module = ir.modules[0]
    symbol_forwarding = _auxdata.symbol_forwarding.get_or_insert(module)
    pe_import_entries = _auxdata.pe_import_entries.get_or_insert(module)
    pe_imported_symbols = _auxdata.pe_imported_symbols.get_or_insert(module)
    libraries = _auxdata.libraries.get_or_insert(module)

    log.warning("PE file has delay-loaded imports; converting to normal imports (custom delay-load helpers will be lost!)")

    for mod in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        dll_name = mod.dll.decode()
        for imp in mod.imports:
            ordinal = -1
            if imp.ordinal is not None:
                ordinal = imp.ordinal
                imp_name = f'{dll_name[:-4]}@{ordinal}'
            else:
                imp_name = imp.name.decode()

            imp_addr = imp.address

            blocks = list(ir.byte_blocks_at(imp_addr))
            assert len(blocks) != 0, f'Cannot find block at delay-loaded import "{imp_name}"s address: {hex(imp_addr)}'
            db = blocks[0]
            local_sym = find_symbol(ir, db)
            assert local_sym, f'Cannot find symbol corresponding to block at "{imp_name}"s address'

            # create external symbol for delay-loaded import
            delay_imp_sym = Symbol(
                name=imp_name,
                payload=ProxyBlock(),
                at_end=False,
                module=module)

            # add library to external libraries
            if dll_name not in libraries:
                libraries.append(dll_name)

            # add to imported symbols
            pe_imported_symbols.append(delay_imp_sym)

            # add to symbol forwarding
            symbol_forwarding[local_sym] = delay_imp_sym

            # add to import entries
            pe_import_entries.append((imp_addr, ordinal, imp_name, dll_name))
            log.debug(f'Converted delay-loaded import "{imp_name}" from {dll_name} to standard import')