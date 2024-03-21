from collections import OrderedDict
import logging
import typing
import uuid

import gtirb
import gtirb_functions
from gtirb_rewriting import (
    Patch,
    RewritingContext
)

log = logging.getLogger(__name__)

def get_address_to_codeblock_mappings(ir: gtirb.IR) -> OrderedDict[int, uuid.UUID]:
    """
    Generate mapping between addresses and codeblocks. Needs to to be generated
    before any modifications have been made to the IR.

    :param module: GTIRB module to build mapping for
    :returns: dictionary of addresses to codeblock UUIDs
    """
    f = OrderedDict()
    for block in sorted(ir.code_blocks, key=lambda e: e.address):
        f[block.address] = block.uuid
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

def backup_regs_x86(label: str):
    '''
    Generate asm for backing up x86 registers to given label
    :param label: label to backup registers to
    '''
    return f'''
        mov    DWORD PTR [{label}], eax
        mov    DWORD PTR [{label} + 0x4], ebx
        mov    DWORD PTR [{label} + 0x8], ecx
        mov    DWORD PTR [{label} + 0xC], edx
        mov    DWORD PTR [{label} + 0x10], edi
        mov    DWORD PTR [{label} + 0x14], esi
        movaps XMMWORD PTR [{label} + 0x20], xmm0
        movaps XMMWORD PTR [{label} + 0x30], xmm1
        movaps XMMWORD PTR [{label} + 0x40], xmm2
        movaps XMMWORD PTR [{label} + 0x50], xmm3
        movaps XMMWORD PTR [{label} + 0x60], xmm4
        movaps XMMWORD PTR [{label} + 0x70], xmm5
        movaps XMMWORD PTR [{label} + 0x80], xmm6
        movaps XMMWORD PTR [{label} + 0x90], xmm7
    '''

def restore_regs_x86(label: str):
    '''
    Generate asm for restoring x86 registers from a given label
    :param label: label to restore registers from
    '''
    return f'''
        mov    eax,  DWORD PTR [{label}]
        mov    ebx,  DWORD PTR [{label} + 0x4]
        mov    ecx,  DWORD PTR [{label} + 0x8]
        mov    edx,  DWORD PTR [{label} + 0xC]
        mov    edi,  DWORD PTR [{label} + 0x10]
        mov    esi,  DWORD PTR [{label} + 0x14]
        movaps xmm0, XMMWORD PTR [{label} + 0x20]
        movaps xmm1, XMMWORD PTR [{label} + 0x30]
        movaps xmm2, XMMWORD PTR [{label} + 0x40]
        movaps xmm3, XMMWORD PTR [{label} + 0x50]
        movaps xmm4, XMMWORD PTR [{label} + 0x60]
        movaps xmm5, XMMWORD PTR [{label} + 0x70]
        movaps xmm6, XMMWORD PTR [{label} + 0x80]
        movaps xmm7, XMMWORD PTR [{label} + 0x90]
    '''

