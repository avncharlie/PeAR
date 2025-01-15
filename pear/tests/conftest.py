import pytest
import platform

from ..utils import run_cmd

def pytest_addoption(parser):
    parser.addoption("--vcvarsall-loc", action="store")
    parser.addoption("--winafl32-afl-fuzz-loc", action="store")
    parser.addoption("--winafl64-afl-fuzz-loc", action="store")
    parser.addoption("--ir-cache", action="store")
    parser.addoption("--hide-afl-ui", action="store_true")

@pytest.fixture(scope='session')
def vcvarsall_loc(request) -> str:
    loc = request.config.getoption("--vcvarsall-loc")
    assert loc != None, "Provide location to vcvarsall.bat with --vcvarsall-loc option."
    return loc

@pytest.fixture
def winafl_32_loc(request) -> str:
    loc = request.config.getoption("--winafl32-afl-fuzz-loc")
    assert loc != None, "Provide location to 32 bit build of afl-fuzz with --winafl32-afl-fuzz-loc"
    return loc

@pytest.fixture
def winafl_64_loc(request) -> str:
    loc = request.config.getoption("--winafl64-afl-fuzz-loc")
    assert loc != None, "Provide location to 64 bit build of afl-fuzz with --winafl64-afl-fuzz-loc"
    return loc

@pytest.fixture
def hide_afl_ui(request) -> bool:
    return request.config.getoption("--hide-afl-ui")

@pytest.fixture
def ir_cache(request) -> bool:
    return request.config.getoption("--ir-cache")

windows_only = pytest.mark.skipif(
    platform.system() != 'Windows', reason="Windows only test"
)

linux_only = pytest.mark.skipif(
    platform.system() != 'Linux', reason="Linux only test"
)

docker_installed = pytest.mark.skipif(
    not (lambda: _is_docker_working()), reason="Docker is not installed or not working"
)

def _is_docker_working():
    try:
        # Run a simple Docker command to check if Docker is working
        output, _ = run_cmd(["docker", "run", "--rm", "hello-world"], print=False)
        return b"Hello from Docker!" in output
    except:
        return False

def get_gen_binary_from_pear_output(output: bytes) -> str: 
    # Find instrumented binary through parsing pear output (pretty messy)
    out = output.decode()
    gen_binary_line = 'Generated binary saved to: '
    inst_prog = None
    for l in out.splitlines():
        if gen_binary_line in l:
            inst_prog = l.split(gen_binary_line)[-1] # get instrumented filename
            inst_prog = inst_prog[:-4] # remove color ansi characters at end
    return inst_prog
