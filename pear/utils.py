# Generic utility functions

import os
import sys
import uuid
import shutil
import logging
import subprocess
from typing import Optional
from functools import lru_cache
from collections import OrderedDict

import gtirb
import gtirb_rewriting._auxdata as _auxdata
import cpp_demangle

from gtirb import Module
from gtirb.symbol import Symbol
import gtirb_functions
from gtirb_rewriting import (
    Pass,
    Patch,
    PassManager,
    RewritingContext
)

log = logging.getLogger(__name__)

from . import GEN_SCRIPT_OPTS
from . import DUMMY_LIB_NAME
DRY_RUN_WHITELIST = ['ddisasm', 'gtirb-pprinter']

CPP_FILT_WARNING = False

def cppfilt_demangle(mangled: str):
    """
    Attempt to demangle C++ name using c++filt tool from binutils.
    Return original if not cpp name.
    """
    out, _ = run_cmd(['c++filt', mangled], should_print=False, log=False)
    return out.decode().strip()

@lru_cache(maxsize=None)
def demangle(mangled: str):
    """
    Attempt to demangle C++ name using cpp_demangle python lib.
    Return original if not cpp name
    """
    global CPP_FILT_WARNING
    if not mangled.startswith('_Z'):
        return mangled # probably not cpp name
    try:
        return cpp_demangle.demangle(mangled)
    except ValueError:
        if not shutil.which('c++filt'):
            if not CPP_FILT_WARNING:
                log.warning("c++filt not installed (install via binutils package) ... relying only on cpp_demangle to demangle")
                CPP_FILT_WARNING = True
            return mangled
        # fallback to c++filt
        return cppfilt_demangle(mangled)

def is_pie(module: Module):
    binary_type = _auxdata.binary_type.get_or_insert(module)
    return 'PIE' in binary_type

def log_cmd(cmd: list[str],
            working_dir: Optional[str]=None,
            env_vars: Optional[dict]=None):
    """Log command to be run and add to build script if needed"""
    # TODO: remove colours
    green = '\033[92m'
    end = '\033[0m'
    cmd_str = ' '.join(cmd)
    fmt_cmd = green +  cmd_str + end
    wd = ''
    env = ''
    if working_dir:
        wd = f" (with custom working dir '{working_dir}') "
    if env_vars:
        env = f" (with env vars '{env_vars}') "
    extra = wd + env
    if extra != '':
        extra = extra[:-1]

    executing = 'Executing'
    # write to build script
    if GEN_SCRIPT_OPTS.is_dry_run and cmd[0] not in DRY_RUN_WHITELIST:
        executing = 'Would execute'
        assert GEN_SCRIPT_OPTS.gen_output != None
        with open(GEN_SCRIPT_OPTS.gen_output, 'a') as f:
            assert not env_vars, "setting env vars in build script not implemented"
            if working_dir:
                cmd_str = f'pushd {working_dir}\n{cmd_str}\npopd'
            cmd_str += '\n'
            f.write(cmd_str)
            
    log.info(f"{executing}{extra}: " + fmt_cmd)

def run_cmd(cmd: list[str],
            check: Optional[bool]=True,
            log: Optional[bool]=True,
            should_print: Optional[bool]=True,
            working_dir: Optional[str]=None,
            env_vars: Optional[dict]=None) -> tuple[bytes, int]:
    """
    Run command and capture its output and return code. Stream command stdout
    and stderr to stdout as it is produced. Not very efficient.

    :param cmd: command to run.
    :param check: True if exception should be raised on command failure
    :param should_print: True if command output should be printed
    :param working_dir: Working directory command should be executed in. Will
        execute in current dir by default.
    :param env_vars: A dictionary of environment variables to set for the command.
    :returns: A tuple of (command output, return code)
    """
    if log:
        log_cmd(cmd, working_dir, env_vars)
    if GEN_SCRIPT_OPTS.is_dry_run and cmd[0] not in DRY_RUN_WHITELIST:
        return b'', 0
    output = b""

    env = dict(os.environ)
    if env_vars:
        env.update(env_vars)

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               cwd=working_dir, env=env)
    for c in iter(lambda: process.stdout.read(1), b""):
        if should_print:
            sys.stdout.buffer.write(c)
            sys.stdout.buffer.flush()
        output += c

    r_code = process.wait()

    if check and r_code != 0:
        raise subprocess.CalledProcessError(r_code, cmd)
    return (output, r_code)


def check_executables_exist(to_check: list[str]) -> bool:
    """
    Check required executables exist

    :param to_check: list of executable names to check
    :returns: if executables exist
    """
    found = True
    for e in to_check:
        if not shutil.which(e):
            log.error(f'"{e}" not found, install it or add it to path.')
            found = False
    return found

def get_address_to_byteblock_mappings(ir: gtirb.IR) -> OrderedDict[int, uuid.UUID]:
    """
    Generate mapping between addresses and GTIRB ByteBlocks.

    :param module: GTIRB module to build mapping for
    :returns: dictionary of addresses to ByteBlock UUIDs
    """
    f = OrderedDict()
    for block in sorted(ir.byte_blocks, key=lambda e: e.address):
        f[block.address] = block.uuid
    return f

def get_codeblock_to_address_mappings(ir: gtirb.IR) -> OrderedDict[uuid.UUID, int]:
    """
    Generate mapping between codeblocks and address.

    :param module: GTIRB module to build mapping for
    :returns: dictionary of codeblock UUIDs to addresses
    """
    f = OrderedDict()
    for block in sorted(ir.code_blocks, key=lambda e: e.address):
        f[block.uuid] = block.address
    return f


def insert_patch_at_address(patch_address: int, patch: Patch,
                            mappings: OrderedDict[int, uuid.UUID],
                            context: RewritingContext):
    """
    Inserts a patch at a specific address, given a mapping between addresses
    and codeblocks. See get_address_to_codeblock_mappings to generate this
    mapping.

    :param patch_address: Address to insert patch at
    :param patch: patch to insert
    :param mappings: Address to codeblock mappings
    :param context: rewriting context
    """
    # get list of module blocks
    module: gtirb.Module = context._module
    blocks = module.code_blocks

    # Locate block UUID to patch
    # 1. filter blocks with addresses before or equal to patch location
    blocks_before = filter(lambda x: x[0] <= patch_address, mappings.items())
    # 2. find closest one to patch location
    block_addr, block_uuid = sorted(blocks_before, key=lambda x: patch_address - x[0])[0]

    # Find this block
    b_search = list(filter(lambda x: x.uuid == block_uuid, blocks))
    assert len(b_search) == 1, f"Could not find block with address {patch_address}"

    # Patch
    patch_block = b_search[0]
    block_offset = patch_address - block_addr
    context.insert_at(
        patch_block,
        block_offset,
        patch
    )

def align_section(module: Module, section: str, balign: Optional[int]=16):
    '''
    Align the original program data in a section.
    gtirb-rewriting inserts patch data before all other data in the section it
    is inserted into. This can cause a bunch of alignment issues. To fix this,
    we add alignment to the start of the original data.
    :param module: GTIRB Module we are working
    :param section: Section to align
    :param balign: Bytes of alignment needed
    '''

    alignment = _auxdata.alignment.get_or_insert(module)
    sec = None
    for s in module.sections:
        if s.name == section:
            sec = s
    assert sec != None, f"Cannot find section {section}"

    in_prog_dbs = [db for db in sec.data_blocks if db.address is not None]
    sorted_db = sorted(in_prog_dbs, key=lambda e: e.address)

    # Inserted patch data doesn't have an address so it won't be within sorted_dbs
    if len(sorted_db) > 0:
        alignment[sorted_db[0]] = balign


def get_symbols_from_file(obj_path: str, working_dir: str) -> list[str]:
    '''
    Use Ddisasm to get global symbols from object file
    :param obj_path: path of object to disassemble
    :param working_dir: working directory
    :returns: list of global symbol names
    '''
    obj_ir_f = os.path.join(working_dir, 'cov_obj.gtirb')
    # import here to avoid circular import
    from .ddisasm import ddisasm
    ddisasm(obj_path, obj_ir_f, hide=False)
    obj_ir = gtirb.IR.load_protobuf(obj_ir_f)
    obj_module = obj_ir.modules[0]
    symbols_aux = _auxdata.elf_symbol_info.get_or_insert(obj_module)
    symbols = []
    for sym, (_, _, binding, visibility, _) in symbols_aux.items():
        if binding == 'GLOBAL' and visibility != 'HIDDEN':
            symbols.append(sym.name)
    return symbols

def add_symbols_to_ir(symbols: list[str], ir: gtirb.IR):
    '''
    Given a list of symbols, inserts them into an IR
    :param symbols: list of symbol names to insert
    :param ir: IR to insert them into
    '''
    class AddSymbols(Pass):
        def __init__(self, symbols: list[str]):
            super().__init__()
            self.symbols = symbols
        def begin_module(self, module, functions, rewriting_ctx):
            for sym in self.symbols:
                rewriting_ctx.get_or_insert_extern_symbol(sym, DUMMY_LIB_NAME)
    manager = PassManager()
    manager.add(AddSymbols(symbols))
    manager.run(ir)


def get_basic_blocks(function: gtirb_functions.Function) -> list[list[gtirb.CodeBlock]]:
    """
    Return basic blocks within a function (GTIRB CodeBlocks are the same as what
    would be considered basic blocks, at least within the context of AFL
    instrumentation).

    :param function: GTIRB function to construct codeblocks from
    :returns: list of basic blocks, where each basic block is a list of one or
        more Codeblocks that constitutes a basic block.
    """

    blocks: list[list[gtirb.CodeBlock]] = []
    for block in sorted(function.get_all_blocks(), key=lambda e: e.address):
        incoming = list(block.incoming_edges)
        outgoing = list(block.outgoing_edges)

        # Ignore 'detached' blocks that have  no path to or from them.
        if len(incoming) == 0 and len(outgoing) == 0 and not block in function.get_entry_blocks():
            continue

        '''
        Gtirb builds basic blocks across an entire program and not just
        functions. This means that calls are considered to end a basic
        block. However, in the context of AFL instrumentation, we do not
        consider a call to end a basic block. 
        As such, we group blocks that satisfy all these conditions:
          - Do not have an incoming edge from a jump instruction 
          - Have a incoming edge that is a fallthrough and ...
              - The source block of the fallthrough edge has two outgoing 
                edges, being: {Call, Fallthrough}.
        
        i.e consider this block:
          <ASM1>
          call <func>
          <ASM2>
          call <another_func>
        Gtirb would turn this into two basic blocks:
          block 1 (outgoing edges = [CALL, Fallthrough to block 2]:
            <ASM1>
            call <func>
          block 2 (incoming edges = [Fallthrough from block 1]:
            <ASM2>
            call <another_func>
        We consider this one block. As such, we store blocks as lists, and
        the above block would be stored as [block1, block2] in the
        `blocks` array.
        Blocks that don't have calls in them would be stored as singleton
        lists in the `blocks` array.
        '''

        # Check block is fallthrough and doesn't come from branch.
        incoming_edge_types = [x.label.type for x in incoming]
        if gtirb.Edge.Type.Fallthrough in incoming_edge_types and not gtirb.Edge.Type.Branch in incoming_edge_types:
            skip = False
            for incoming_edge in incoming:

                # Retrieve source block that falls through to current block.
                if incoming_edge.label.type == gtirb.Edge.Type.Fallthrough:
                    outgoing_source_edge_types = [x.label.type for x in list(incoming_edge.source.outgoing_edges)]

                    # Check source block has {Call, Fallthrough} as its
                    # outoing edges.
                    if set(outgoing_source_edge_types) == set([gtirb.Edge.Type.Call, gtirb.Edge.Type.Fallthrough]):

                        # Find parent block in blocklist and append self.
                        for blocklist in blocks:
                            for b in blocklist:
                                if b.address == incoming_edge.source.address:
                                    blocklist.append(block)
                                    break

                        skip = True
                        break
            if skip:
                continue

        blocks.append([block])

    return blocks
