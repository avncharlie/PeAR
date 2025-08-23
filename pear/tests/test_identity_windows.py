import os
import sys
import shutil
import textwrap
import importlib
import pytest
import tempfile

import gtirb

from enum import Enum
from typing import NamedTuple, Tuple

from ..utils import run_cmd
from .conftest import windows_only, get_gen_binary_from_pear_output, devcmd_bat

TEST_WIN_DIR = importlib.resources.files(__package__) / 'test_identity_windows'
GEN_INPUT_NAME = 'input.txt'
DLL_RUNTIME_NAME = 'testdll.dll'  # Import descriptor expects this name
INPUT = b'bar'

class BuildKind(Enum):
    NAMED = 'named'              # implicit link, exports by name
    ORDINAL = 'ord'              # implicit link, exports NONAME/@ordinal
    DELAY_NAMED = 'delaynamed'   # delay-load, exports by name
    DELAY_ORDINAL = 'delayord'   # delay-load, exports NONAME/@ordinal

class BuiltPair(NamedTuple):
    """Paths to the built EXE and DLL for a given variant."""
    exe: str
    dll: str

def arch_suffix(arch: gtirb.Module.ISA) -> str:
    if arch == gtirb.Module.ISA.IA32:
        return 'x86'
    elif arch == gtirb.Module.ISA.X64:
        return 'x64'
    assert False, f'unsupported ISA "{arch}"'

def build_cmd(cmdline: str, devcmd_bat: str) -> list[str]:
    """Wrap a command to run under the MSVC dev environment."""
    return ['cmd', '/c', f'{devcmd_bat} & {cmdline}']

def write_testfile(dst_dir: str, contents: bytes = b'hello world\n') -> str:
    p = os.path.join(dst_dir, GEN_INPUT_NAME)
    with open(p, 'wb') as f:
        f.write(contents)
    return p

def run_binary_with_dll(exe_path: str, dll_src: str) -> Tuple[bytes, int]:
    """
    Run exe_path with an adjacent DLL named 'testdll.dll'. Returns (output, retcode).
    Executes the absolute EXE path so no working_dir is required.
    """
    run_dir = tempfile.mkdtemp(prefix='pear-id-run-')
    exe_name = os.path.basename(exe_path)

    # Copy EXE
    exe_dst = os.path.join(run_dir, exe_name)
    shutil.copy2(exe_path, exe_dst)

    # Provide the DLL under the expected runtime name
    dll_dst = os.path.join(run_dir, DLL_RUNTIME_NAME)
    shutil.copy2(dll_src, dll_dst)

    # Input file
    inp = write_testfile(run_dir, INPUT)

    # Execute absolute EXE path
    cmd = [exe_dst, inp]
    out, r = run_cmd(cmd)
    return out, r

def build_variant(build_dir: str, devcmd_bat: str, arch: gtirb.Module.ISA, variant: BuildKind) -> BuiltPair:
    """
    Build a single variant in build_dir and return BuiltPair(exe,dll).
    Assumes sources + .def files are present in build_dir.
    Output files are suffixed with arch so x86/x64 can coexist.
    """

    # Compile objects
    for step in [
        'cl /nologo /c testdll.c',
        'cl /nologo /c main.c',
    ]:
        run_cmd(build_cmd(step, devcmd_bat), working_dir=build_dir)

    # Choose DLL flavor + EXE link line based on variant
    if variant == BuildKind.NAMED or variant == BuildKind.DELAY_NAMED:
        # Build named-exports DLL
        run_cmd(build_cmd(
            'link /nologo /DLL testdll.obj /DEF:testdll_named.def /OUT:testdll.named.dll',
            devcmd_bat),
            working_dir=build_dir)
        dll_src = 'testdll.named.dll'
        imp_lib = 'testdll.named.lib'
    else:
        # Build ordinal-only (NONAME) DLL
        run_cmd(build_cmd(
            'link /nologo /DLL testdll.obj /DEF:testdll_ordinal.def /OUT:testdll.ord.dll',
            devcmd_bat),
            working_dir=build_dir)
        dll_src = 'testdll.ord.dll'
        imp_lib = 'testdll.ord.lib'

    # Link EXE for this variant
    if variant == BuildKind.NAMED:
        link_exe = f'link /nologo main.obj {imp_lib} /OUT:main.named.exe'
        exe_src = 'main.named.exe'
    elif variant == BuildKind.ORDINAL:
        link_exe = f'link /nologo main.obj {imp_lib} /OUT:main.ord.exe'
        exe_src = 'main.ord.exe'
    elif variant == BuildKind.DELAY_NAMED:
        link_exe = f'link /nologo main.obj {imp_lib} delayimp.lib /OUT:main.delay.exe /DELAYLOAD:testdll.dll'
        exe_src = 'main.delay.exe'
    elif variant == BuildKind.DELAY_ORDINAL:
        link_exe = f'link /nologo main.obj {imp_lib} delayimp.lib /OUT:main.delayord.exe /DELAYLOAD:testdll.dll'
        exe_src = 'main.delayord.exe'
    else:
        raise AssertionError(f'unknown variant {variant}')

    run_cmd(build_cmd(link_exe, devcmd_bat), working_dir=build_dir)

    # Suffix outputs with arch for collision-free multi-arch runs
    exe_dst = f'{os.path.splitext(exe_src)[0]}.{arch_suffix(arch)}.exe'
    dll_dst = f'{os.path.splitext(dll_src)[0]}.{arch_suffix(arch)}.dll'
    os.replace(os.path.join(build_dir, exe_src), os.path.join(build_dir, exe_dst))
    os.replace(os.path.join(build_dir, dll_src), os.path.join(build_dir, dll_dst))

    exe_path = os.path.join(build_dir, exe_dst)
    dll_path = os.path.join(build_dir, dll_dst)
    assert os.path.isfile(exe_path), f'missing exe for {variant}'
    assert os.path.isfile(dll_path), f'missing dll for {variant}'
    return BuiltPair(exe=exe_path, dll=dll_path)

def run_pear_identity(input_path: str, out_dir: str, devcmd_bat: str, ir_cache: str | bool) -> str:
    """
    Run PeAR Identity on a binary (EXE or DLL). Returns path to generated identity binary.
    We keep the same MSVC env wrapper to ensure toolchains like dumpbin (if
    your pear run might indirectly shell out) have a consistent env; harmless otherwise.
    """
    ir_cache_arg = f'--ir-cache {ir_cache}' if ir_cache else ''
    pear_cmd = f'{sys.executable} -m pear {ir_cache_arg} --input-binary {input_path} --output-dir {out_dir} --gen-binary Identity'
    cmd = build_cmd(pear_cmd, devcmd_bat)
    out, _ = run_cmd(cmd)
    return get_gen_binary_from_pear_output(out)

def check_runs_ok(exe: str, dll: str):
    out, r = run_binary_with_dll(exe, dll)
    assert r == 0, f'process failed (rc={r})'
    assert b'got: ' + INPUT in out, f'unexpected output: {out[:200]!r}'

# Build exe + dll pair for current test architecture + build kind
@pytest.fixture
def build_identity_windows(tmp_path_factory: pytest.TempPathFactory,
                           devcmd_bat: str,
                           arch: gtirb.Module.ISA,
                           variant: BuildKind) -> BuiltPair:
    """
    Copy the tiny source folder and build only the requested variant for the given arch.
    Returns BuiltPair(exe,dll).
    """
    # copy test sources
    build_dir = tmp_path_factory.mktemp('build_win_id')
    shutil.copytree(TEST_WIN_DIR, build_dir, dirs_exist_ok=True)

    # build
    pair = build_variant(str(build_dir), devcmd_bat, arch, variant)

    return pair

#
# Matrix:
#   - arch ∈ {IA32, X64}
#   - variant ∈ {NAMED, ORDINAL, DELAY_NAMED, DELAY_ORDINAL}
# For each (arch, variant):
#   1) rewritten EXE + standard DLL
#   2) normal EXE    + rewritten DLL
#   3) rewritten EXE + rewritten DLL

@windows_only
@pytest.mark.parametrize(
    'variant,arch',
    [
        (BuildKind.NAMED,         gtirb.Module.ISA.IA32),
        (BuildKind.ORDINAL,       gtirb.Module.ISA.IA32),
        (BuildKind.DELAY_NAMED,   gtirb.Module.ISA.IA32),
        (BuildKind.DELAY_ORDINAL, gtirb.Module.ISA.IA32),

        (BuildKind.NAMED,         gtirb.Module.ISA.X64),
        (BuildKind.ORDINAL,       gtirb.Module.ISA.X64),
        (BuildKind.DELAY_NAMED,   gtirb.Module.ISA.X64),
        (BuildKind.DELAY_ORDINAL, gtirb.Module.ISA.X64),
    ],
    ids=lambda p: p.value if isinstance(p, BuildKind) else p.name
)
def test_windows_identity(
    arch: gtirb.Module.ISA,
    variant: BuildKind,
    devcmd_bat: str,
    tmp_path_factory: pytest.TempPathFactory,
    ir_cache: bool,
    build_identity_windows: dict[BuildKind, BuiltPair],
):
    built = build_identity_windows

    out_dir_exe  = tmp_path_factory.mktemp('out_exe')
    out_dir_dll  = tmp_path_factory.mktemp('out_dll')

    # 1) Rewrite EXE
    exe_identity = run_pear_identity(built.exe, str(out_dir_exe), devcmd_bat, ir_cache)
    assert exe_identity and os.path.isfile(exe_identity)

    # 2) Rewrite DLL
    dll_identity = run_pear_identity(built.dll, str(out_dir_dll), devcmd_bat, ir_cache)
    assert dll_identity and os.path.isfile(dll_identity)

    # 1) rewritten EXE + original DLL
    check_runs_ok(exe_identity, built.dll)
    # 2) original EXE + rewritten DLL
    check_runs_ok(built.exe, dll_identity)
    # 3) rewritten EXE + rewritten DLL
    check_runs_ok(exe_identity, dll_identity)