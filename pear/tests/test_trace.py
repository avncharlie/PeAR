import os
import sys
import shutil
import pytest
import importlib

from ..utils import run_cmd
from .conftest import linux_only, get_gen_binary_from_pear_output

TEST_TRACE_DIR = importlib.resources.files(__package__) / 'test_trace'

def build_program(source_file: str, output_location: str) -> str:
    """Compile the source file into an executable."""
    bin_path = os.path.join(output_location, os.path.basename(source_file).replace('.c', ''))
    cmd = ['gcc', '-o', bin_path, source_file]
    run_cmd(cmd)
    return bin_path

def instrument_program(bin_path: str, out_dir: str, ir_cache: bool) -> tuple:
    """Instrument the binary and return the generated binary location and aux file."""
    ir_cache_arg = ['--ir-cache', ir_cache] if ir_cache else []
    pear_cmd = [sys.executable, '-m', 'pear'] + ir_cache_arg + \
        ['--input-binary', bin_path, '--output-dir', str(out_dir), '--gen-binary',
         'Trace', '--add-coverage', '--fast']
    out, _ = run_cmd(pear_cmd)
    traced = get_gen_binary_from_pear_output(out)
    aux_file = os.path.join(out_dir, f'{os.path.basename(bin_path)}.Trace.basicblockinfo.json')
    return traced, aux_file

def run_program(traced: str, out_dir: str) -> str:
    """Run the traced binary and return the coverage file path."""
    _, r = run_cmd([traced], working_dir=str(out_dir))
    assert r == 0
    cov_file = ''
    for f in os.listdir(out_dir):
        if f.endswith('.cov'):
            cov_file = os.path.join(out_dir, f)
            break
    assert cov_file != '', "Generated coverage file not found!"
    return cov_file

@linux_only
def test_trace_basic(tmp_path_factory: pytest.TempPathFactory, ir_cache: bool):
    build_dir = tmp_path_factory.mktemp('build')
    out_dir = tmp_path_factory.mktemp('out')
    progname = 'basic'
    code_path = os.path.join(TEST_TRACE_DIR, f'{progname}.c')

    # build, instrument and run program
    bin_path = build_program(code_path, str(build_dir))
    traced, aux_file = instrument_program(bin_path, str(out_dir), ir_cache)
    cov_file = run_program(traced, str(out_dir))

    # parse coverage output
    print_exec_cmd = [sys.executable, 'pear/tools/parse_coverage.py', 
                      '--aux-info', aux_file, '--cov-file', cov_file,
                      'PrintExecution']
    out, r = run_cmd(print_exec_cmd, should_print=False)

    # Check that functions in output, and called in this order.
    expected = ['_start:', 'main:', 'a:', 'b:', 'c:', '_fini:']
    next = 0
    for line in out.decode().splitlines():
        if line.startswith(expected[next]):
            next += 1
            if next == len(expected):
                break
    assert next == len(expected), "PrintExecution output incorrect"

@linux_only
def test_trace_pthread(tmp_path_factory: pytest.TempPathFactory, ir_cache: bool):
    build_dir = tmp_path_factory.mktemp('build')
    out_dir = tmp_path_factory.mktemp('out')
    progname = 'pthread_test'
    code_path = os.path.join(TEST_TRACE_DIR, f'{progname}.c')

    # build, instrument and run program
    bin_path = build_program(code_path, str(build_dir))
    traced, aux_file = instrument_program(bin_path, str(out_dir), ir_cache)
    cov_file = run_program(traced, str(out_dir))

    # parse coverage output
    print_exec_cmd = [sys.executable, 'pear/tools/parse_coverage.py', 
                      '--aux-info', aux_file, '--cov-file', cov_file,
                      'PrintExecution']
    out, r = run_cmd(print_exec_cmd, should_print=False)

    assert b'print_one:' in out and b'print_two:' in out and r == 0

@linux_only
def test_trace_fork(tmp_path_factory: pytest.TempPathFactory, ir_cache: bool):
    build_dir = tmp_path_factory.mktemp('build')
    out_dir = tmp_path_factory.mktemp('out')
    progname = 'fork_test'
    code_path = os.path.join(TEST_TRACE_DIR, f'{progname}.c')

    # build, instrument and run program
    bin_path = build_program(code_path, str(build_dir))
    traced, aux_file = instrument_program(bin_path, str(out_dir), ir_cache)
    cov_file = run_program(traced, str(out_dir))

    # parse coverage output
    print_exec_cmd = [sys.executable, 'pear/tools/parse_coverage.py', 
                      '--aux-info', aux_file, '--cov-file', cov_file,
                      'PrintExecution']
    out, r = run_cmd(print_exec_cmd, should_print=False)

    assert b'print_one:' in out and b'print_two:' in out and r == 0
    # evidence of two processes being spawned and logging to the one coverage file
    assert out.count(b'_fini') == 2 
