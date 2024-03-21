
import logging

from gtirb_rewriting import (
    Pass,
    Patch,
    Constraints,
    X86Syntax,
    SingleBlockScope,
    BlockPosition
)

log = logging.getLogger(__name__)

class AddNopPass(Pass):
    """Add a nop to the start of every function"""

    def begin_module(self, module, functions, rewriting_ctx):

        instr_count = 0

        for function in functions:
            entry_blocks = function.get_entry_blocks()

            for block in entry_blocks:
                rewriting_ctx.register_insert(
                    SingleBlockScope(block, BlockPosition.ENTRY),
                    Patch.from_function(lambda _: f'''
                        nop
                    ''', Constraints(x86_syntax=X86Syntax.INTEL))
                )
                instr_count += 1


        log.info(f'Instrumented {instr_count} locations')
