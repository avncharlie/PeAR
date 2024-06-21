
# from .nop_pass import fooBar
# from .gtirb_wrappers import ddisasm_disassemble


DUMMY_LIB_NAME = "dummylib.lib"

# rewriter uses DUMMY_LIB_NAME so we have to import after we declare it
from .rewriters.winafl.winafl_rewriter import WinAFLRewriter

REWRITERS = [WinAFLRewriter]
REWRITER_MAP = {}
for r in REWRITERS:
    name, _ = r.get_info()
    REWRITER_MAP[name] = r