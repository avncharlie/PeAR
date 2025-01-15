import os
import sys
import pytest

from ..utils import run_cmd
from .conftest import linux_only, get_gen_binary_from_pear_output

BUGGY = r'''
#include <stdio.h>

int main() {
    for (int x = 0; x > 4; x++)
        printf("x is: %d\n", x);
}
'''

@linux_only
def test_regenerate(tmp_path_factory: pytest.TempPathFactory,
                    ir_cache: bool):
    build_dir = tmp_path_factory.mktemp('build')
    out_dir = tmp_path_factory.mktemp('out')
    progname = 'buggy'
    bin_path = os.path.join(build_dir, progname) 
    code_path = bin_path + '.c'
    with open(code_path, 'w') as f:
        f.write(BUGGY)

    cmd = ['gcc', '-o', bin_path, code_path]
    run_cmd(cmd)
    ir_cache_arg = []
    if ir_cache:
        ir_cache_arg = ['--ir-cache', ir_cache]
    pear_cmd = [sys.executable, '-m', 'pear'] + ir_cache_arg + \
        ['--input-binary', bin_path, '--output-dir', str(out_dir), '--gen-asm', 'Identity']
    out, _ = run_cmd(pear_cmd)
    asm_path = os.path.join(out_dir, progname + '.Identity.S')

    fixed = ''
    with open(asm_path, 'r') as f:
        prev_line = ''
        for line in f.readlines():
            # check for offending instruction: jg instead of jl
            # will be preceded by a cmp x, 4
            if line.lstrip().startswith('jg') \
                    and prev_line.lstrip().startswith('cmp') \
                    and prev_line.rstrip()[-1] == '4':
                fixed += line.replace('jg', 'jl')
            else:
                fixed += line
            prev_line = line

    fixed_asm = os.path.join(out_dir, 'fixed.S')
    with open(fixed_asm, 'w') as f:
        f.write(fixed)

    fixed_out_dir = tmp_path_factory.mktemp('fixed_out')
    pear_cmd = [sys.executable, '-m', 'pear'] + ir_cache_arg + \
        ['--input-binary', bin_path, '--output-dir', str(fixed_out_dir), 
         '--gen-binary', 'Regenerate', '--from-asm', fixed_asm]
    out, _ = run_cmd(pear_cmd)
    fixed_bin = get_gen_binary_from_pear_output(out)

    out, r = run_cmd([fixed_bin])
    assert out == b'x is: 0\nx is: 1\nx is: 2\nx is: 3\n' and r == 0

