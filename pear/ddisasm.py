"""Wrapper around ddisasm"""

import os
import shutil
import logging
import hashlib
from typing import Optional

from .utils import run_cmd, check_executables_exist


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
                # found. copy cached IR to output location
                log.info("Found IR in cache")
                shutil.copy(os.path.join(ir_cache, entry), output)
                return

    # disassemble binary
    assert check_executables_exist(['ddisasm']), "ddisasm not found"
    cmd = ["ddisasm", binary, "--ir", output]
    run_cmd(cmd)

    assert os.path.isfile(output), "ddisasm failed to produce output IR"

    # store in cache
    if ir_cache:
        assert cache_fname is not None
        shutil.copy(output, os.path.join(ir_cache, cache_fname))
        log.info("Added IR to cache")