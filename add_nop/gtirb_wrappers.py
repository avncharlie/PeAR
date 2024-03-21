"""Wrappers around ddisasm and gtirb-pprinter"""

import os
import sys
import shutil
import logging
import hashlib
import subprocess
from typing import Optional

import gtirb

log = logging.getLogger(__name__)

def md5(fname: str) -> str:
    """
    Calculate md5 checksum of file.

    :param fname: path of file to checksum
    :returns: checksum of file
    """
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def run_cmd(cmd: list[str], check: bool = True, print: bool = True) -> tuple[bytes, int]:
    """
    Run command and capture its output and return code. Stream command stdout
    and stderr to stdout as it is produced. Not very efficient.

    :param cmd: command to run.
    :param check: True if exception should be raised on command failure
    :param print: True if command output should be printed
    :returns: A tuple of (command output, return code)
    """
    log.info("Executing: " + " ".join(cmd))
    output = b""

    process : subprocess.Popen = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT)
    for c in iter(lambda: process.stdout.read(1), b""):
        if print:
            sys.stdout.buffer.write(c)
            sys.stdout.buffer.flush()
        output += c

    r_code = process.wait()

    if check and r_code != 0:
        raise subprocess.CalledProcessError(r_code, cmd)
    return (output, r_code)

def ddisasm(binary: str, output: str, ir_cache: Optional[str]=None):
    """
    Generate GTIRB IR of binary using ddisasm. Use cache if specified.

    :param binary: File location of input binary
    :param output: File location of output IR
    :param ir_cache: Location of IR cache
    """
    cache_fname = None
    if ir_cache:
        # cache is structured as folder of GTIRB IR files.
        # the names of these files are the md5 checksums of the binaries they
        # were disassembled from.

        cache_fname = f"{md5(binary)}.gtirb"
        for entry in os.listdir(ir_cache):
            if entry == cache_fname:
                # cache hit. copy cached IR to output location
                print("Using IR from cache")
                shutil.copy(os.path.join(ir_cache, entry), output)
                return

    # disassemble binary
    cmd = ["ddisasm", binary, "--ir", output]
    run_cmd(cmd)

    assert os.path.isfile(output), "ddisasm failed to produce output IR"

    # store in cache
    if ir_cache:
        assert cache_fname is not None
        shutil.copy(output, os.path.join(ir_cache, cache_fname))
        print("Added IR to cache")

def gtirb_pprinter(ir_file: str, output: str,
                            gen_assembly: Optional[bool]=False,
                            gen_binary: Optional[bool]=False,
                            ssh_address: Optional[str]=None,
                            remote_working_dir: Optional[str]=None,
                            check_remote_dir_exists: Optional[bool]=True):
    """
    Generate assembly code or binary using gtirb-pprinter locally or through
    SSH.

    One of gen_assembly or gen_binary parameters must be true. To use SSH
    functionality, provide an SSH address (in form user@ipaddress), as well as
    a remote working directory. Requirements:
        - Remote server running Windows
        - gtirb-pprinter on PATH
        - MSVC tools available on PATH (i.e Visual Studio Developer command
            prompt)
        - SSH keys set up (no password entry required to log in)
        - SCP supported
        - Remote working directory exists and is accessible

    :param ir_file: file location of GTIRB IR to generate from
    :param output: file location of output assembly or binary
    :param gen_assembly: True if generating assembly
    :param gen_binary: True if generating binary
    :param ssh_address: String of form user@ipaddress identifying SSH address
        of remote build server
    :param remote_working_dir: Location of working directory on build server
    :param check_remote_dir_exists: True if remote working directory should be
        checked to exist before using
    """
    assert gen_assembly or gen_binary, \
        "One of gen_assembly or gen_binary must be true"

    gen_flag = '--asm' if gen_assembly else '--binary'
    if not ssh_address:
        # local
        cmd = ["gtirb-pprinter", ir_file, gen_flag, output]
        run_cmd(cmd)
        return

    # remote
    assert remote_working_dir is not None, \
        "must provide remote working directory if running remotely"

    # Check working dir exists
    # as SSH returns the exit status of the remote command, the ssh command
    # will fail and raise an exception if the file isn't found
    if check_remote_dir_exists:
        err_msg = f"Remote working directory {remote_working_dir} not found on build server"
        cmd = ["ssh", ssh_address, f"dir {remote_working_dir}"]
        try:
            out, _ = run_cmd(cmd, print=False)
        except subprocess.CalledProcessError as exc:
            raise FileNotFoundError(err_msg) from exc
        else:
            # just in case error not raised for some reason, also check output
            powershell_not_found = b'PathNotFound' 
            cmd_not_found = b'File Not Found' 
            if powershell_not_found in out or cmd_not_found in out:
                raise FileNotFoundError(err_msg)

    # Copy IR file to remote working dir
    cmd = ["scp", ir_file, f"{ssh_address}:{remote_working_dir}"]
    run_cmd(cmd)

    # Run gtirb-pprinter on file
    basename = os.path.basename(ir_file)
    remote_ir_loc = os.path.join(remote_working_dir, basename)
    remote_output = os.path.join(remote_working_dir, f'{basename}.instrumented')
    if gen_assembly: remote_output += '.S'
    remote_cmd = f"gtirb-pprinter {remote_ir_loc} {gen_flag} {remote_output}"
    run_cmd(["ssh", ssh_address, remote_cmd])

    # Copy back to local
    cmd = ["scp", f"{ssh_address}:{remote_output}", output]
    run_cmd(cmd)
