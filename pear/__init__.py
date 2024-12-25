
# from .nop_pass import fooBar
# from .gtirb_wrappers import ddisasm_disassemble


DUMMY_LIB_NAME = "dummylib.lib"

# rewriter uses DUMMY_LIB_NAME so we have to import after we declare it
from .rewriters.winafl.winafl_rewriter import WinAFLRewriter
from .rewriters.aflpp.aflpp_rewriter import AFLPlusPlusRewriter
from .rewriters.identity import IdentityRewriter
from .rewriters.debug_rewrite import DebugRewriter
from .rewriters.regenerate import RegenerateRewriter

REWRITERS = [WinAFLRewriter, AFLPlusPlusRewriter, IdentityRewriter, RegenerateRewriter]

REWRITER_MAP = {r.name(): r for r in REWRITERS}
