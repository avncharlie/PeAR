import os
import sys
import shutil
import pytest
import importlib

from typing import Callable

import gtirb
import gtirb_rewriting._auxdata as _auxdata

from ..utils import run_cmd
from ..ddisasm import ddisasm
from .conftest import linux_only, docker_installed, get_gen_binary_from_pear_output

TEST_IDENTIY_DIR = importlib.resources.files(__package__) / 'test_identity'
BIN_NAME = 'foo'
BUILD_LIBFOO = ['gcc', '-shared', '-fPIC', 'libfoo.c', '-o', 'libfoo.so', '-nodefaultlibs']
BUILD_FOO_BASE = ['gcc', '-o', BIN_NAME, 'main.c', '-Wl,--no-as-needed', '-L.', '-lfoo']

@linux_only
def test_identity_simple(tmp_path_factory: pytest.TempPathFactory,
                         ir_cache: bool):
    build_dir = tmp_path_factory.mktemp('build')
    shutil.copytree(TEST_IDENTIY_DIR, build_dir, dirs_exist_ok=True)

    run_cmd(BUILD_LIBFOO, working_dir=str(build_dir))
    run_cmd(BUILD_FOO_BASE, working_dir=str(build_dir))

    out_dir = tmp_path_factory.mktemp('out')
    binary = os.path.join(build_dir, BIN_NAME)

    ir_cache_arg = []
    if ir_cache:
        ir_cache_arg = ['--ir-cache', ir_cache]
    pear_cmd = [sys.executable, '-m', 'pear'] + ir_cache_arg + \
        ['--input-binary', binary, '--output-dir', str(out_dir), '--gen-binary', 'Identity']
    out, _ = run_cmd(pear_cmd)
    identity = get_gen_binary_from_pear_output(out)

    # Check that it runs
    cmd = [identity]
    env = {'LD_LIBRARY_PATH': str(build_dir)}
    out, r = run_cmd(cmd, working_dir=str(out_dir), env_vars=env)
    assert r == 0 and b'foo is: 42\n' in out and b'foo is: 420\n' in out

@linux_only
def test_identity_complex(tmp_path_factory: pytest.TempPathFactory,
                         ir_cache: bool):
    build_dir = tmp_path_factory.mktemp('build')
    shutil.copytree(TEST_IDENTIY_DIR, build_dir, dirs_exist_ok=True)

    run_cmd(BUILD_LIBFOO, working_dir=str(build_dir))

    libnothings_dir = build_dir / 'libnothings'
    libnothings_dir.mkdir(exist_ok=True)

    empty_file_path = build_dir / 'emptyfile.c'
    f = open(empty_file_path, 'w')
    f.close()

    libnothing_build = ['gcc', '-shared', '-fPIC', str(empty_file_path), '-o', str(libnothings_dir / 'libnothing.so'), '-nodefaultlibs']
    run_cmd(libnothing_build, working_dir=str(build_dir))
    libnothing2_build = ['gcc', '-shared', '-fPIC', str(empty_file_path), '-o', str(libnothings_dir / 'libnothing2.so'), '-nodefaultlibs']
    run_cmd(libnothing2_build, working_dir=str(build_dir))

    build_stack_size = 4000000
    build_foo_complex = BUILD_FOO_BASE + [
        '-L', str(libnothings_dir), '-lnothing', '-lnothing2',
        '-Wl,-rpath,' + str(build_dir), '-Wl,-rpath,' + str(libnothings_dir),
        '-Wl,-z,execstack', f'-Wl,-z,stack-size={build_stack_size}', '-no-pie'
    ]
    run_cmd(build_foo_complex, working_dir=str(build_dir))

    out_dir = tmp_path_factory.mktemp('out')
    binary = os.path.join(build_dir, BIN_NAME)

    ir_cache_arg = []
    if ir_cache:
        ir_cache_arg = ['--ir-cache', ir_cache]
    pear_cmd = [sys.executable, '-m', 'pear'] + ir_cache_arg + \
        ['--input-binary', binary, '--output-dir', str(out_dir), '--gen-binary', 'Identity']
    out, _ = run_cmd(pear_cmd)
    identity = get_gen_binary_from_pear_output(out)

    # Check that it runs (shouldn't need LD_LIBRARY_PATH as we set rpath)
    cmd = [identity]
    out, r = run_cmd(cmd, working_dir=str(out_dir))
    assert r == 0 and b'foo is: 42\n' in out and b'foo is: 420\n' in out

    # Check that the build options for the original binary were replicated for
    # the generated identity binary
    identity_ir = out_dir / 'identity_ir.gtirb'
    ddisasm(identity, str(identity_ir))
    ir = gtirb.IR.load_protobuf(identity_ir)
    module = ir.modules[0]

    libraries = _auxdata.libraries.get_or_insert(module)
    rpaths = _auxdata.library_paths.get_or_insert(module)
    exec_stack: bool = module.aux_data['elfStackExec'].data
    stack_size: int = module.aux_data['elfStackSize'].data
    binary_type = _auxdata.binary_type.get_or_insert(module)

    assert exec_stack == True
    assert stack_size == build_stack_size
    assert 'PIE' not in binary_type
    assert str(build_dir) in rpaths and str(libnothings_dir) in rpaths
    expected_libraries = ['libc.so.6', 'libfoo.so', 'libnothing.so', 'libnothing2.so']
    assert set(libraries) == set(expected_libraries)

def run_docker_test(docker_image: str,
                    bin_path: str,
                    call_args: list[str],
                    check_func: Callable[[bytes], bool],
                    tmp_path_factory: pytest.TempPathFactory, ir_cache: bool):
    temp_dir = tmp_path_factory.mktemp('test')

    # Use long running command to keep image alive
    container_id_cmd = ["docker", "create", "--rm", docker_image, "yes"]
    output, _ = run_cmd(container_id_cmd)
    container_id = output.decode().strip()
    run_cmd(["docker", "start", container_id])

    basename = os.path.basename(bin_path)

    try:
        # Extract binary from container
        dest_path = temp_dir / basename
        run_cmd(["docker", "cp", f"{container_id}:{bin_path}", str(dest_path)])

        # Run PeAR on it
        out_dir = tmp_path_factory.mktemp('out')
        ir_cache_arg = ['--ir-cache', ir_cache] if ir_cache else []
        pear_cmd = [sys.executable, '-m', 'pear'] + ir_cache_arg + ["--input-binary", str(dest_path), "--output-dir", str(out_dir), "--gen-binary", "Identity"]
        out, _ = run_cmd(pear_cmd)

        # Copy instrumented binary back into the container
        inst_binary_path = get_gen_binary_from_pear_output(out)
        inst_binary_name = os.path.basename(inst_binary_path)
        run_cmd(["docker", "cp", str(inst_binary_path), f"{container_id}:/"])

        # Run inside container
        exec_cmd = ["docker", "exec", container_id, f"/{inst_binary_name}"] + call_args
        exec_output, r = run_cmd(exec_cmd)

        # Check ran without error
        assert r == 0
        assert check_func(exec_output)

    finally:
        # Ensure the container is stopped and removed
        run_cmd(["docker", "stop", "-t", "1", container_id])

@linux_only
@docker_installed
def test_identity_on_gtirb_pprinter(tmp_path_factory: pytest.TempPathFactory,
                                    ir_cache: bool):

    run_docker_test(
        docker_image="grammatech/ddisasm",
        bin_path="/usr/local/bin/gtirb-pprinter",
        call_args = ['--version'],
        check_func=lambda out: len(out.decode().split()[0].split('.')) == 3,
        tmp_path_factory=tmp_path_factory,
        ir_cache=ir_cache
    )

@linux_only
@docker_installed
def test_identity_on_ls(tmp_path_factory: pytest.TempPathFactory, ir_cache:
                        bool):
    run_docker_test(
        docker_image="ubuntu:24.04",
        bin_path="/bin/ls",
        call_args = ['--version'],
        check_func=lambda out: "ls (GNU coreutils)" in out.decode(),
        tmp_path_factory=tmp_path_factory,
        ir_cache=ir_cache
    )

@linux_only
@docker_installed
def test_identity_ctors_dtors(tmp_path_factory: pytest.TempPathFactory,
                              ir_cache: bool):
    # The ls binary from Ubuntu 12.04 has a ctors/dtors section, which we test
    # we can handle correctly
    run_docker_test(
        docker_image="ubuntu:12.04",
        bin_path="/bin/ls",
        call_args = ['--version'],
        check_func=lambda out: "ls (GNU coreutils)" in out.decode(),
        tmp_path_factory=tmp_path_factory,
        ir_cache=ir_cache
    )
