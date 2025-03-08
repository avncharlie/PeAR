import os
import sys
import glob
import pytest
import shutil
import textwrap
import importlib
import subprocess

import gtirb

from enum import Enum
from typing import NamedTuple

from ..utils import run_cmd, check_executables_exist
from .conftest import linux_only, get_gen_binary_from_pear_output

# TODO: this has too much copied code from test_winafl.py.

TEST_PROG_DIR = importlib.resources.files(__package__) / 'test_fuzz'
AFLPP_TIMEOUT=20
GENERIC_TARGET_FUNC_NAME='read_and_test_file'

class TargetProgram(NamedTuple):
    name: str
    binary_path: str
    corpus: str
    target_func_name: str

def prepare_generic_test_binary(prog_name: str,
                                tmp_path_factory: pytest.TempPathFactory,
                                arch: gtirb.Module.ISA) -> TargetProgram:
    '''
    Procedure to build generic test binaries.
    Assumes:
        - There exists 'build_<ARCH>.sh' script in TEST_PROG_DIR/<PROG> to
          build the program for a specified architecture.
        - There exists a fuzzer corpus directory TEST_PROG_DIR/<PROG>/corpus.
        - The program will export a function called GENERIC_TARGET_FUNC_NAME 
          that will be the target fuzzing function.

    See befunge and simple for examples.

    :param prog_name: Name of test program
    :param tmp_path_factory: Used to generate build dir
    :return: TargetProgram with details of built program
    '''
    prog_dir = os.path.join(TEST_PROG_DIR, prog_name)
    build_script = f'./build_{arch.name}.sh'

    # copy program to temp dir
    build_dir = tmp_path_factory.mktemp('build')
    shutil.copytree(prog_dir, build_dir, dirs_exist_ok=True)

    # run build script with correct build environment
    run_cmd([build_script], working_dir=str(build_dir))

    # check binary exists after build
    bin_path = os.path.join(build_dir, f"{prog_name}{arch.name}")
    assert os.path.isfile(bin_path), "binary not found after build"

    return TargetProgram(
        name=prog_name,
        binary_path=bin_path,
        corpus=os.path.join(build_dir, 'corpus'),
        target_func_name=GENERIC_TARGET_FUNC_NAME
    )

@pytest.fixture
def prepare_befunge(tmp_path_factory: pytest.TempPathFactory,
                    arch: gtirb.Module.ISA) -> TargetProgram:
    return prepare_generic_test_binary('befunge', tmp_path_factory, arch)

@pytest.fixture
def prepare_simple(tmp_path_factory: pytest.TempPathFactory,
                   arch: gtirb.Module.ISA) -> TargetProgram:
    return prepare_generic_test_binary('simple', tmp_path_factory, arch)

@pytest.fixture
def prepare_libxml2(tmp_path_factory: pytest.TempPathFactory) -> TargetProgram:
    assert check_executables_exist(['git']), 'git is required to download xmllint'
    assert check_executables_exist(['cmake']), 'cmake is required to build xmllint'

    XMLLINT_TARGET_FUNC = 'parseAndPrintFile'
    working = tmp_path_factory.mktemp('xmllint_test')

    # Download libxml source
    cmd = ['git', 'clone', '--depth', '1', 'https://github.com/GNOME/libxml2',
           str(working / 'libxml2')]
    run_cmd(cmd)

    # Configure (statically link and skip optional shared libs)
    build_dir = 'libxml2-build'
    configure_cmd = f"cmake -S libxml2 -B {build_dir} -D BUILD_SHARED_LIBS=OFF -D LIBXML2_WITH_ICONV=OFF -D LIBXML2_WITH_LZMA=OFF -D LIBXML2_WITH_PYTHON=OFF -D LIBXML2_WITH_ZLIB=OFF"
    run_cmd(configure_cmd.split(' '), working_dir=str(working))

    # Build
    build_cmd = f"cmake --build {build_dir}"
    run_cmd(build_cmd.split(' '), working_dir=str(working))

    # Check xmllint exists after build
    bin_path = working / build_dir / 'xmllint'
    assert bin_path.exists(), "binary not found after build"

    # create corpus using test xml files in libxml2 repo
    corpus = tmp_path_factory.mktemp('corpus')
    source = working / 'libxml2' / 'test' / '*xml'
    xml_files = glob.glob(str(source))
    for file in xml_files:
        shutil.copy(file, corpus)

    return TargetProgram(
        name='xmllint',
        binary_path=str(bin_path),
        corpus=str(corpus),
        target_func_name=XMLLINT_TARGET_FUNC
    )

@pytest.fixture
def prepare_test_program(request: pytest.FixtureRequest) -> TargetProgram:
    return request.getfixturevalue(request.param)

def run_aflpp_test(inst_prog: str, corpus: str, afl_out: str,
                   hide_afl_ui: bool) -> float:
    '''Fuzz binary with AFL++ and return execs per second'''
    inst_prog = str(inst_prog)
    # Ignore the usual system config AFL wants you to set
    hide_ui = []
    if hide_afl_ui:
        hide_ui = ['AFL_NO_UI=1']
    cmd = hide_ui + \
            ['AFL_SKIP_CPUFREQ=1', 'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1',
             'timeout', str(AFLPP_TIMEOUT),
             'afl-fuzz', '-i', corpus, '-o', afl_out, '--', inst_prog, '@@']
    str_cmd = ' '.join(cmd)
    print(f'Fuzzing using cmd: {str_cmd}')
    os.system(str_cmd)

    # Check fuzzer stats file generated with a value for execs per sec
    fuzzer_stats = os.path.join(afl_out, "default", "fuzzer_stats")
    assert os.path.isfile(fuzzer_stats), "AFL fuzzer_stats file not generated, binary failed to fuzz"
    execs_per_sec = None
    with open(fuzzer_stats) as f:
        for l in f:
            if l.startswith('execs_per_sec'):
                execs_per_sec = float((l.split(':')[1]).strip())
    assert execs_per_sec != None, "execs_per_sec stat not found in fuzzer_stats, binary didn't fuzz"
    return execs_per_sec

def run_pear(pear_cmd: str) -> str:
    '''Run PeAR over binary and return instrumented binary'''
    out, _ = run_cmd(pear_cmd.split(' '))
    inst_prog = get_gen_binary_from_pear_output(out)
    # Check instrumented binary exists
    assert inst_prog != None and os.path.isfile(inst_prog), "Instrumented binary not found after PeAR was run"
    return inst_prog

# see test_winafl_rewriter for explanation of the parametrization
@linux_only
@pytest.mark.parametrize(
    'prepare_test_program,arch',
    [
        ('prepare_befunge', gtirb.Module.ISA.X64),
        ('prepare_simple',  gtirb.Module.ISA.X64),
        ('prepare_libxml2', gtirb.Module.ISA.X64)
    ],
    ids=lambda p: p.name if isinstance(p, gtirb.Module.ISA) else p.split('_')[1],
    indirect=['prepare_test_program']
)
def test_aflpp_rewriter(
    prepare_test_program: TargetProgram,
    arch: gtirb.Module.ISA,
    tmp_path_factory: pytest.TempPathFactory,
    hide_afl_ui: bool,
    ir_cache: bool,
):
    test_prog = prepare_test_program
    progname = test_prog.name
    binpath = test_prog.binary_path
    target_func = test_prog.target_func_name
    corpus = test_prog.corpus
    def out_dir():
        return str(tmp_path_factory.mktemp('out'))
    ir_cache_arg = ''
    if ir_cache:
        ir_cache_arg = f'--ir-cache {ir_cache}'

    # Test 1: deferred mode
    pear_cmd = f'{sys.executable} -m pear {ir_cache_arg} --input-binary {binpath} --output-dir {out_dir()} --gen-binary AFL++ --deferred-fuzz-function {target_func}'
    inst_prog = run_pear(pear_cmd)
    def_mode_execs = run_aflpp_test(inst_prog, corpus, out_dir(), hide_afl_ui)
    print(f'Using deferred mode, fuzzed {progname} at {def_mode_execs} execs per sec.')
    
    # Test 2: deferred mode + persistent mode
    pear_cmd = f'{sys.executable} -m pear {ir_cache_arg} --input-binary {binpath} --output-dir {out_dir()} --gen-binary AFL++ --deferred-fuzz-function {target_func} --persistent-mode-function {target_func} --persistent-mode-count 2147483647'
    inst_prog = run_pear(pear_cmd)
    pers_mode_execs = run_aflpp_test(inst_prog, corpus, out_dir(), hide_afl_ui)
    print(f'Using deferred+persistent mode, fuzzed {progname} at {pers_mode_execs} execs per sec.')

    print('\nTo recap:')
    print(f'Using deferred mode, fuzzed {progname} at {def_mode_execs} execs per sec.')
    print(f'Using deferred+persistent mode, fuzzed {progname} at {pers_mode_execs} execs per sec.')

