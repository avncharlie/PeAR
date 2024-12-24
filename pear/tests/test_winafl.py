import os
import sys
import glob
import pytest
import shutil
import pathlib
import platform
import textwrap
import importlib
import subprocess

import gtirb

from enum import Enum
from typing import NamedTuple

from ..utils import run_cmd, check_executables_exist
from .conftest import windows_only, get_gen_binary_from_pear_output

TEST_PROG_DIR = importlib.resources.files(__package__) / 'test_programs'
WINAFL_TIMEOUT=30
GENERIC_TARGET_FUNC_NAME='read_and_test_file'

class TargetProgram(NamedTuple):
    name: str
    binary_path: str
    corpus: str
    target_func_address: int

@pytest.fixture
def devcmd_bat(arch: gtirb.Module.ISA,
               vcvarsall_loc: str,
               tmp_path_factory: pytest.TempPathFactory) -> str:
    '''
    Build bat file used to initialise MSVC environment for given architecture
    '''
    base = tmp_path_factory.mktemp('bat_files')
    if arch == gtirb.Module.ISA.IA32:
        arch_opt = 'x86'
    elif arch == gtirb.Module.ISA.X64:
        arch_opt = 'x64'
    bat = base / f"dev{arch.value}.bat"
    with open(bat, 'w') as f:
        f.write('"' + vcvarsall_loc + f'" {arch_opt}')
    return bat

def get_func_address_in_disasm(prog_path: str, devcmd_bat: str,
                               func_name: str) -> int:
    '''
    Find address of function in binary through parsing its dissasembly generated
    by dumpbin
    
    :param prog_path: Path to binary
    :param devcmd_bat: Appropriate devcmd file for given architecture
    :param func_name: function name to search for
    :returns
    '''
    # first get exported function relative address
    gen_disasm = f'dumpbin /disasm {prog_path}'
    cmd = ['cmd', '/c', f'{devcmd_bat} & {gen_disasm}']
    # run_cmd is too slow to process all the disass output
    disass = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

    found = False
    target_func = None
    for line in disass.splitlines():
        if found:
            target_func = int(line.split(':')[0], 16)
            break
        if line.startswith(func_name+':'):
            found = True
    assert target_func != None, "target function not found in built binary"

    return target_func

def get_exported_func_address(prog_path: str, devcmd_bat: str,
                            func_name: str) -> int:
    '''
    Find address of exported function in binary using dumpbin

    :param prog_path: Path to binary
    :param devcmd_bat: Appropriate devcmd file for given architecture
    :param func_name: function name to search for
    :returns
    '''
    # first get exported function relative address
    dumpbin_exports = f'dumpbin /exports {prog_path}'
    cmd = ['cmd', '/c', f'{devcmd_bat} & {dumpbin_exports}']
    out, _ = run_cmd(cmd, print=False)
    out = out.decode()
    target_func_offset = None
    for line in out.splitlines():
        if func_name in line:
            target_func_offset = int(line.split()[2], 16)
    assert target_func_offset != None, "target function not found in built binary"

    # next get image base
    dumpbin_headers = f'dumpbin /headers {prog_path}'
    cmd = ['cmd', '/c', f'{devcmd_bat} & {dumpbin_headers}']
    out, _ = run_cmd(cmd, print=False)
    out = out.decode()
    image_base = None
    for line in out.splitlines():
        if 'image base' in line:
            image_base = int(line.split()[0], 16)
    assert target_func_offset != None, "image base not found in built binary"

    return image_base + target_func_offset

def prepare_generic_test_binary(prog_name: str,
                                tmp_path_factory: pytest.TempPathFactory,
                                devcmd_bat: str,
                                arch: gtirb.Module.ISA) -> TargetProgram:
    '''
    Procedure to build generic test binaries.
    Assumes:
        - There exists 'build_<ARCH>.bat' script in TEST_PROG_DIR/<PROG> to
          build the program for a specified architecture.
        - There exists a fuzzer corpus directory 'corpus' TEST_PROG_DIR/<PROG>.
        - The program will export a function called GENERIC_TARGET_FUNC_NAME 
          that will be the target fuzzing function .

    See befunge and simple for examples.

    :param prog_name: Name of test program
    :param tmp_path_factory: Used to generate build dir
    :param devcmd_bat: Appropriate devcmd file for given architecture
    :return: TargetProgram with details of built program
    '''
    prog_dir = os.path.join(TEST_PROG_DIR, prog_name)
    build_script = f'build_{arch.name}.bat'

    # copy program to temp dir
    build_dir = tmp_path_factory.mktemp('build')
    shutil.copytree(prog_dir, build_dir, dirs_exist_ok=True)

    # run build script with correct build environment
    cmd = ['cmd', '/c', f'{devcmd_bat} & {build_script}']
    run_cmd(cmd, working_dir=str(build_dir))

    # check binary exists after build
    bin_path = os.path.join(build_dir, f"{prog_name}{arch.name}.exe")
    assert os.path.isfile(bin_path), "binary not found after build"

    # get target function address
    target_func = get_exported_func_address(bin_path, devcmd_bat,
                                            GENERIC_TARGET_FUNC_NAME)

    return TargetProgram(
        name=prog_name,
        binary_path=bin_path,
        corpus=os.path.join(build_dir, 'corpus'),
        target_func_address=target_func
    )

@pytest.fixture
def prepare_befunge(tmp_path_factory: pytest.TempPathFactory, devcmd_bat: str,
                    arch: gtirb.Module.ISA) -> TargetProgram:
    return prepare_generic_test_binary('befunge', tmp_path_factory, devcmd_bat, arch)

@pytest.fixture
def prepare_simple(tmp_path_factory: pytest.TempPathFactory, devcmd_bat: str,
                   arch: gtirb.Module.ISA) -> TargetProgram:
    return prepare_generic_test_binary('simple', tmp_path_factory, devcmd_bat, arch)

@pytest.fixture
def prepare_libxml2(tmp_path_factory: pytest.TempPathFactory, devcmd_bat: str,
                    arch: gtirb.Module.ISA) -> TargetProgram:
    assert check_executables_exist(['git']), 'git is required to download xmllint'

    XMLLINT_TARGET_FUNC = 'parseAndPrintFile'
    working = tmp_path_factory.mktemp('xmllint_test')

    # Download libxml source
    cmd = ['git', 'clone', '--depth', '1', 'https://github.com/GNOME/libxml2',
           str(working / 'libxml2')]
    run_cmd(cmd)

    # Configure (statically link and skip optional shared libs)
    build_dir = 'libxml2-build'
    configure_cmd = f"cmake -S libxml2 -B {build_dir} -D BUILD_SHARED_LIBS=OFF -D LIBXML2_WITH_ICONV=OFF -D LIBXML2_WITH_LZMA=OFF -D LIBXML2_WITH_PYTHON=OFF -D LIBXML2_WITH_ZLIB=OFF"
    cmd = ['cmd', '/c', f'{devcmd_bat} & {configure_cmd}']
    run_cmd(cmd, working_dir=str(working))

    # Build
    build_cmd = f"cmake --build {build_dir}"
    cmd = ['cmd', '/c', f'{devcmd_bat} & {build_cmd}']
    run_cmd(cmd, working_dir=str(working))

    # Check xmllint exists after build
    bin_path = working / build_dir / 'Debug' / 'xmllint.exe'
    assert bin_path.exists(), "binary not found after build"

    # dumpbin /exports and dumpbin /symbols don't show any symbols on the built
    # xmllint binary for some reason, despite being built with a debug flag and
    # the generated PDB containing the symbol we want. The generated disassembly
    # contains symbols however so we use this to find the target function.
    print('Finding xmllint target function..')
    target_func = get_func_address_in_disasm(str(bin_path), devcmd_bat,
                                             XMLLINT_TARGET_FUNC)

    # create corpus using test xml files in libxml2 repo
    corpus = tmp_path_factory.mktemp('corpus')
    source = working / 'libxml2' / 'test' / '*xml'
    xml_files = glob.glob(str(source))
    for file in xml_files:
        shutil.copy(file, corpus)

    return TargetProgram(
        name='xmllint',
        binary_path=bin_path,
        corpus=str(corpus),
        target_func_address=target_func
    )

@pytest.fixture
def prepare_test_program(request: pytest.FixtureRequest) -> TargetProgram:
    return request.getfixturevalue(request.param)

# prepare_test_program will be called with program build fixtures as parameters
# and will call them to generate a TargetProgram
@windows_only
@pytest.mark.parametrize(
    'prepare_test_program,arch',
    [
        ('prepare_befunge', gtirb.Module.ISA.IA32),
        ('prepare_befunge', gtirb.Module.ISA.X64),
        ('prepare_simple',  gtirb.Module.ISA.IA32),
        ('prepare_simple',  gtirb.Module.ISA.X64),
        ('prepare_libxml2', gtirb.Module.ISA.X64)
    ],
    ids=lambda p: p.name if isinstance(p, gtirb.Module.ISA) else p.split('_')[1],
    indirect=['prepare_test_program']
)
def test_winafl_rewriter(
    prepare_test_program: TargetProgram,
    arch: gtirb.Module.ISA,
    winafl_32_loc: str,
    winafl_64_loc: str,
    tmp_path_factory: pytest.TempPathFactory,
    hide_afl_ui: bool,
    devcmd_bat: str
):
    test_prog = prepare_test_program

    # Get right version of WinAFL
    if arch == gtirb.Module.ISA.IA32:
        winafl_loc = winafl_32_loc
    elif arch == gtirb.Module.ISA.X64:
        winafl_loc = winafl_64_loc

    # Use pear to instrument test program
    out_dir = tmp_path_factory.mktemp('out')
    pear_cmd = f'{sys.executable} -m pear --input-binary {test_prog.binary_path} --output-dir {out_dir} --gen-binary WinAFL --target-func {hex(test_prog.target_func_address)}'
    cmd = ['cmd', '/c', f'{devcmd_bat} & {pear_cmd}']
    out, _ = run_cmd(cmd)
    inst_prog = get_gen_binary_from_pear_output(out)

    # Check instrumented binary exists
    assert inst_prog != None and os.path.isfile(inst_prog), "Instrumented binary not found after PeAR was run"
    inst_prog_basename = os.path.basename(inst_prog)

    # Run under WinAFL
    afl_out = str(tmp_path_factory.mktemp('afl-out'))
    inst_prog = str(inst_prog)

    # We generate a bat file to run the instrumented binary under WinAFL for
    # 15 seconds. We check if its successful by verifying the fuzzer_stats
    # file exists, which AFL only seems to create once its begins fuzzing.

    # I used os.system to spawn the WinAFL process as for some reason WinAFL
    # doesn't work when spawned by any Subprocess method. This is why a bat
    # file is used to enforce the timeout instead as I can't find any other way
    # to do it cleanly except for using the Subprocess module.
    cmd = [winafl_loc, '-Y', '-i', test_prog.corpus, '-o', afl_out, '-t',
           '1000+', '--', '-fuzz-iterations', '5000', '--', inst_prog, '"@@"']
    cmd = ' '.join(cmd)
    test_bat = tmp_path_factory.mktemp('run_winafl') / 'run_winafl_test.bat'
    with open(test_bat, 'w') as f:
        s = generate_timer_bat_script(cmd, WINAFL_TIMEOUT, 'afl-fuzz.exe', inst_prog_basename, hide_afl_ui)
        f.write(s)
    print("Running WinAFL with instrumented binary...")
    os.system(f'cmd /c {str(test_bat)}')

    # Ideally I would like to check the exit code of afl-fuzz as well as if
    # fuzzer_stats is created. This is would be possible by updating the bat
    # script, but ideally we should just get Subprocess to work and use its
    # timeout feature instead.
    fuzzer_stats = os.path.join(afl_out, "fuzzer_stats")
    assert os.path.isfile(fuzzer_stats), "AFL fuzzer_stats file not generated, binary failed to fuzz"

def generate_timer_bat_script(cmd, timeout, process_name, filter, hide_output):
    '''
    Generate bat script to run process for a number of seconds before killing it

    :param cmd: command to run
    :param timeout: timeout in seconds
    :param process_name: name of executable being run
        (used to find process to kill)
    :param filter: string that should be in command line args of running process
        (used to find process to kill)
    :param hide_output: if command output should be hidden
    '''
    redirect = '> nul' if hide_output else ''
    return textwrap.dedent(rf'''
        @echo off
        start /b {cmd} {redirect}
        timeout /t {timeout} > nul

        for /f "tokens=*" %%i in ('wmic process where "name='{process_name}' and CommandLine like '%%{filter}%%'" get ProcessId ^| findstr /r /b "[0-9]"') do (
            set "pid=%%i"
        )

        if defined pid (
            taskkill /pid %pid% /f
        ) else (
            echo No matching process found.
        )''')
