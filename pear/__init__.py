DUMMY_LIB_NAME = "dummylib.lib"

from dataclasses import dataclass

@dataclass
class GenScriptOptions:
    is_dry_run: bool = False
    gen_output: str = ''

# Usage
GEN_SCRIPT_OPTS = GenScriptOptions()

from .rewriters.debug_rewrite import DebugRewriter

# Some rewriters uses DUMMY_LIB_NAME so we have to import after we declare it
from .rewriters.winafl.winafl_rewriter import WinAFLRewriter
from .rewriters.aflpp.aflpp_rewriter import AFLPlusPlusRewriter
from .rewriters.identity import IdentityRewriter
from .rewriters.regenerate import RegenerateRewriter
from .rewriters.trace.trace_rewriter import TraceRewriter


REWRITERS = [
    WinAFLRewriter,
    AFLPlusPlusRewriter,
    TraceRewriter,
    IdentityRewriter,
    RegenerateRewriter
]

REWRITER_MAP = {r.name(): r for r in REWRITERS}
