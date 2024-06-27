import sys
import os
import pytest
import shutil
import textwrap
import importlib

from enum import Enum

from ..utils import run_cmd


#TODO: check commands exist

class Arch(Enum):
    X86 = '32'
    X64 = '64'

# Discover test programs
TEST_PROG_DIR = importlib.resources.files(__package__) / 'test_programs'
BUILD_32 = "build_32.bat"
BUILD_64 = "build_64.bat"
TEST_PROGS_32 = []
TEST_PROGS_64 = []
for prog in os.listdir(TEST_PROG_DIR):
    if os.path.isdir(os.path.join(TEST_PROG_DIR, prog)):
        prog_base = os.path.join(TEST_PROG_DIR, prog)
        if os.path.isfile(os.path.join(prog_base, BUILD_32)):
            TEST_PROGS_32.append(prog)
        if os.path.isfile(os.path.join(prog_base, BUILD_64)):
            TEST_PROGS_64.append(prog)
WINAFL_TIMEOUT=15

# fuzzer target function name in test programs
TARGET_FUNCTION = 'read_and_test_file'

@pytest.fixture
def build_test_prog(arch, test_prog, devcmd_bat, tmp_path_factory):
    '''
    Build test program given architecture and program name
    '''
    prog_dir = os.path.join(TEST_PROG_DIR, test_prog)

    # get build script according to architecture
    suffix = arch.value
    if arch == Arch.X86:
        build_script = BUILD_32
    elif arch == Arch.X64:
        build_script = BUILD_64
    else:
        assert False, f"Unknown architecture {arch}"

    # copy program to temp dir
    build_dir = tmp_path_factory.mktemp('build')
    shutil.copytree(prog_dir, build_dir, dirs_exist_ok=True)

    # run build script with correct build environment
    cmd = ['cmd', '/c', f'{devcmd_bat} & {build_script}']
    run_cmd(cmd, working_dir=str(build_dir))

    # check binary exists after build
    bin_path = os.path.join(build_dir, f"{test_prog}{suffix}.exe")
    assert os.path.isfile(bin_path), "binary not found after build"

    return bin_path

@pytest.fixture
def devcmd_bat(arch, vcvarsall_loc, tmp_path_factory):
    '''
    Build bat file used to initialise MSVC environment for given architecture
    '''
    base = tmp_path_factory.mktemp('bat_files')
    if arch == Arch.X86:
        arch_opt = 'x86'
    elif arch == Arch.X64:
        arch_opt = 'x64'
    else:
        assert False, f"unknown architecture {arch}"
    bat = base / f"dev{arch.value}.bat"
    with open(bat, 'w') as f:
        f.write('"' + vcvarsall_loc + f'" {arch_opt}')
    return bat

def get_fuzzer_target_func_address(prog_path, devcmd_bat):
    '''
    Find fuzzer target function address using dumpbin
    '''
    # first get target function relative address


    dumpbin_exports = f'dumpbin /exports {prog_path}'
    cmd = ['cmd', '/c', f'{devcmd_bat} & {dumpbin_exports}']
    out, _ = run_cmd(cmd, print=False)
    out = out.decode()
    target_func_offset = None
    for line in out.splitlines():
        if TARGET_FUNCTION in line:
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

@pytest.mark.parametrize("arch,test_prog", 
    [(Arch.X86, test_prog_32) for test_prog_32 in TEST_PROGS_32]
    + [(Arch.X64, test_prog_64) for test_prog_64 in TEST_PROGS_64]
)
def test_winafl_rewrite(arch, test_prog, devcmd_bat, build_test_prog,
                        winafl_32_loc, winafl_64_loc, tmp_path_factory,
                        hide_afl_ui):
    # Get right version of WinAFL
    if arch == Arch.X86:
        winafl_loc = winafl_32_loc
    elif arch == Arch.X64:
        winafl_loc = winafl_64_loc
    else:
        assert False, "unknown architecture"
    
    # Get address of target func to instrument
    test_prog_path = build_test_prog
    target_func = hex(get_fuzzer_target_func_address(test_prog_path, devcmd_bat))
    out_dir = tmp_path_factory.mktemp('out')

    # Use pear to instrument
    pear_cmd = f'{sys.executable} -m pear --input-binary {test_prog_path} --output-dir {out_dir} --gen-binary WinAFL --target-func {target_func}'
    cmd = ['cmd', '/c', f'{devcmd_bat} & {pear_cmd}']
    out, _ = run_cmd(cmd)

    # Find instrumented binary through parsing pear output (pretty messy)
    out = out.decode()
    gen_binary_line = 'Generated binary saved to: '
    inst_prog = None
    for l in out.splitlines():
        if gen_binary_line in l:
            inst_prog = l.split(gen_binary_line)[-1] # get instrumented filename
            inst_prog = inst_prog[:-4] # remove color unicode characters at end
            
    # Check instrumented binary exists
    assert inst_prog != None and os.path.isfile(inst_prog), "Instrumented binary not found after PeAR was run"
    inst_prog_basename = os.path.basename(inst_prog)

    # Run under WinAFL
    afl_out = str(tmp_path_factory.mktemp('afl-out'))
    corpus = str(TEST_PROG_DIR / test_prog / 'corpus')
    inst_prog = str(inst_prog)

    # We generate a bat file to run the instrumented binary under WinAFL for
    # 15 seconds. We check if its successful by verifying the fuzzer_stats
    # file exists, which AFL only seems to create once its begins fuzzing.

    # I used os.system to spawn the WinAFL process as for some reason WinAFL
    # doesn't work when spawned by any Subprocess method. This is why a bat
    # file is used to enforce the timeout instead as I can't find any other way
    # to do it cleanly except for using the Subprocess module.
    cmd = [winafl_loc, '-Y', '-i', corpus, '-o', afl_out, '-t', '1000+',
           '--', '-fuzz-iterations', '5000', '--', inst_prog, '"@@"']
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