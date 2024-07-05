import pytest

def pytest_addoption(parser):
    parser.addoption("--vcvarsall-loc", action="store")
    parser.addoption("--winafl32-afl-fuzz-loc", action="store")
    parser.addoption("--winafl64-afl-fuzz-loc", action="store")
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