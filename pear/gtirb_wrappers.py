"""Wrappers around ddisasm and gtirb-pprinter"""

import re
import os
import sys
import shutil
import logging
import hashlib
import subprocess
from typing import Optional

import gtirb

from . import DUMMY_LIB_NAME

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

def run_cmd(cmd: list[str],
            check: Optional[bool]=True,
            print: Optional[bool]=True,
            working_dir: Optional[str]= None) -> tuple[bytes, int]:
    """
    Run command and capture its output and return code. Stream command stdout
    and stderr to stdout as it is produced. Not very efficient.

    :param cmd: command to run.
    :param check: True if exception should be raised on command failure
    :param print: True if command output should be printed
    :param working_dir: Working directory command should be executed in. Will
        execute in current dir by default.
    :returns: A tuple of (command output, return code)
    """
    # TODO: remove colours
    green = '\033[92m'
    blue = '\033[94m'
    end = '\033[0m'
    log.info("Executing: " + green +  " ".join(cmd) + end)
    output = b""

    process : subprocess.Popen = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT,
                                                  cwd=working_dir)
    for c in iter(lambda: process.stdout.read(1), b""):
        if print:
            sys.stdout.buffer.write(c)
            sys.stdout.buffer.flush()
        output += c

    r_code = process.wait()

    if check and r_code != 0:
        raise subprocess.CalledProcessError(r_code, cmd)
    return (output, r_code)

def check_executables_exist(to_check: list[str]) -> bool:
    """
    Check required executables exist

    :param to_check: list of executable names to check
    :returns: if executables exist
    """
    found = True
    for e in to_check:
        if not shutil.which(e):
            log.error(f'"{e}" not found, install it or add it to path.')
            found = False
    return found


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

def generate_def_file(ir: gtirb.IR, out_folder: str,
                      ignore_dlls: Optional[list[str]]=None) -> dict[str, str]:
    """
    Generate '.def' file for lib.exe to use to generate a '.lib' file declaring
    functions from external dlls used in IR. The generated lib file is used
    when linking the pretty printed assembly to these dlls.

    Output files will be generated to: {out_folder}/{dllname}.def
        e.g. for KERNEL32.dll: {out_folder}/KERNEL32.dll.def

    :param ir: GTIRB IR being def file being generated for
    :param out_folder: Path of output folder.
    :param filter_dlls: Names of dlls to ignore generating def files for
    :returns: mapping of dll names to their generated def files
    """

    if not ignore_dlls:
        ignore_dlls = []

    exports = {}
    for module in ir.modules:
        for _, _, func_name, lib in module.aux_data['peImportEntries'].data:
            if lib not in ignore_dlls:
                if lib not in exports:
                    exports[lib] = []
                exports[lib].append(func_name)

    def_file_mappings = {}

    for lib in exports:
        out_fname = f'{os.path.join(out_folder, lib)}.def'
        def_file_mappings[lib] = out_fname

        with open(out_fname, 'w') as f:
            f.write(f'LIBRARY "{lib}"\n\nEXPORTS\n')
            for func in exports[lib]:
                f.write(f'    {func}\n')

        log.info(f"Generated DEF file for {lib} at: {out_fname}")

    return def_file_mappings

def gtirb_pprinter(ir_file: str, ir: gtirb.IR, output: str, working_dir: str,
                   gen_assembly: Optional[bool]=False,
                   gen_binary: Optional[bool]=False,
                   obj_link: Optional[str]=None):
    """
    Generate assembly code or binary using gtirb-pprinter locally. At least one
    of gen_assembly or gen_binary must be true. Build system must be installed
    and accessible (MSVC for Windows, GCC for Linux).

    For PE binaries, we use our own build process as gtirb-pprinter's binary
    printing doesn't allow us to link our own static libraries into the
    generated binary.

    :param ir_file: File location of GTIRB IR to generate from
    :param ir: GTIRB IR being printed (loaded version of ir_file)
    :param output: File location of output assembly and/or binary. '.exe' will
        be added for output binary and '.S' for assembly.
    :param working_dir: Local working directory to generate intermediary files
    :param gen_assembly: True if generating assembly
    :param gen_binary: True if generating binary
    :param obj_link: Path of object to link into instrumented binary.
    """
    assert gen_assembly or gen_binary, \
        "At least one of gen_assembly or gen_binary must be true"

    basename = os.path.basename(output)

    # Generate assembly (required for binary generation as well)
    assert check_executables_exist(['gtirb-pprinter']), "gtirb-pprinter not found"
    asm_fname = f'{output}.S' if gen_assembly else os.path.join(working_dir, f'{basename}.S')
    cmd = ["gtirb-pprinter", ir_file, '--asm', asm_fname]
    run_cmd(cmd)
    log.info(f'Generated assembly saved to: {asm_fname}')

    # Generate def files to use for linking dlls in final binary
    def_files = generate_def_file(ir, working_dir, ignore_dlls=[DUMMY_LIB_NAME])

    # Modify ASM to link to our lib files.
    # The default name gtirb-pprinter for the lib files is the dll name + lib,
    # which is encoded in the generated assembly.
    # e.g. for Kernel32.dll the gtirb-generated generated lib file would be
    # KERNEL32.LIB.
    # This causes conflicts with the actual Kernel32.lib which we need to use
    # to link most static libraries. So we name our lib files something
    # different (e.g. we rename Kernel32.dll to Kernel32.dll.lib) to avoid this. 
    # Below, we modify the gtirb-generated assembly to use our naming scheme.
    asm = None
    with open(asm_fname, 'r') as f:
        asm = f.read()
    for dll in def_files:
        #  generate gtirb-pprinter's name for a lib
        gtirb_lib_name = dll
        if dll.endswith('.dll'):
            gtirb_lib_name = dll[:-4]+'.lib'
        #  generate our own name
        new_lib_name = f'{dll}.lib'
        new_includelib_line= f'INCLUDELIB {new_lib_name}'
        old_includelib_line = f'INCLUDELIB {gtirb_lib_name}'
        #  replace reference in asm with our new name.
        asm = asm.replace(old_includelib_line, new_includelib_line)
    # Remove dummy library include. Symbols 'used' by dummy library will be
    # fullfilled by static library we later link. Dummy library included as
    # gtirb doesn't allow referencing symbols unless we define the dll they
    # come from, which it attempts to import while binary pretty printing.
    dummy_lib_include = f'INCLUDELIB {DUMMY_LIB_NAME}\n'
    asm = asm.replace(dummy_lib_include, '')
    # Write back modified ASM
    with open(asm_fname, 'w') as f:
        f.write(asm)

    if gen_assembly:
        return

    # Check MSVC build tools accessible and right architecture
    is_64bit = ir.modules[0] == gtirb.Module.ISA.X64
    assert check_executables_exist(['cl']), \
        "MSVC build tools not found, are you running in a developer command prompt?"
    cl_out, _ = run_cmd(["cl"], print=False)
    if is_64bit:
        assert b"for x64" in cl_out, \
            "64-bit MSVC build tools must be used to generate 64-bit instrumented binary"
    else:
        assert b"for x86" in cl_out, \
            "32-bit MSVC build tools must be used to generate 32-bit instrumented binary"
    log.info(f"{'64-bit' if is_64bit else '32-bit'} MSVC build tools found.")

    # Generate lib files from def files
    for dll in def_files:
        def_file = def_files[dll]
        lib_file = os.path.join(working_dir, f'{dll}.lib')
        cmd = ['lib', r'/nologo', fr'/def:{def_file}', fr'/out:{lib_file}',
               r'/MACHINE:X86']
        run_cmd(cmd)

    # Generate object from instrumented assembly
    obj_name = f'{basename}.obj'
    obj_path = os.path.join(working_dir, obj_name)
    cmd = ["ml", r'/nologo', r'/c', fr'/Fo{obj_path}', f'{asm_fname}']
    run_cmd(cmd)

    # Build instrumentation object to link in
    static_obj_folder = f"instrumentation_objs\WindowsX86"
    static_obj_src_path = os.path.join(static_obj_folder, "afl-staticinstr.c")
    static_obj_fname = "afl-staticinstr.obj"
    static_obj_path = os.path.join(working_dir, static_obj_fname)
    cmd = ["cl", r"/nologo", r"/c", static_obj_src_path, fr'/Fo{static_obj_path}']
    run_cmd(cmd)


    # Generate executable, linking in files if needed
    to_link = ["vcruntime.lib", "ucrt.lib", "kernel32.lib", "user32.lib", static_obj_fname]
    binary_name = f'{basename}.exe'
    binary_path = os.path.join(working_dir, f'{basename}.exe')
    cmd = ["cl", r'/nologo', f'{obj_name}', fr'/Fe{binary_name}', r'/link'] + to_link + [r'/ENTRY:_EntryPoint', r'/SUBSYSTEM:console']
    run_cmd(cmd, working_dir=working_dir)

    log.info(f'Generated binary saved to: {binary_path}')

def _remote_gtirb_pprinter(ir_file: str, ir: gtirb.IR, output: str, 
                            working_dir: str,
                            gen_assembly: Optional[bool]=False,
                            gen_binary: Optional[bool]=False,
                            ssh_address: Optional[str]=None,
                            static_lib_link: Optional[str]=None,
                            remote_working_dir: Optional[str]=None,
                            check_remote_dir_exists: Optional[bool]=True):
    """
    Generate assembly code or binary using gtirb-pprinter locally. Optionally
    build binary on remote server using SSH. Optionally link static libraries
    to built binary.

    One of gen_assembly or gen_binary parameters must be true. To use SSH
    functionality, provide an SSH address (in form user@ipaddress), as well as
    a remote working directory. Requirements:
        - Remote server running Windows
        - MSVC tools available on PATH (i.e Visual Studio Developer command
            prompt)
        - SSH keys set up (no password entry required to log in)
        - SCP supported
        - Remote working directory exists and is accessible

    :param ir_file: File location of GTIRB IR to generate from
    :param ir: GTIRB IR being printed (loaded version of ir_file)
    :param output: File location of output assembly or binary
    :param working_dir: Local working directory to generate intermediary files
    :param gen_assembly: True if generating assembly
    :param gen_binary: True if generating binary
    :param static_lib_link: Path of static library to link into pretty printed
        binary. Only valid if generating PE binary.
    :param ssh_address: String of form user@ipaddress identifying SSH address
        of remote build server
    :param remote_working_dir: Location of working directory on build server
    :param check_remote_dir_exists: True if remote working directory should be
        checked to exist before proceeding.
    """
    assert gen_assembly or gen_binary, \
        "One of gen_assembly or gen_binary must be true"

    # Local generation
    gen_flag = '--asm' if gen_assembly else '--binary'
    if not ssh_address:
        cmd = ["gtirb-pprinter", ir_file, gen_flag, output]
        run_cmd(cmd)
        return

    # Check working dir exists
    # as SSH returns the exit status of the remote command, the ssh command
    # will fail and raise an exception if the file isn't found
    assert remote_working_dir != None, "Must provide remote working dir"
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

    # Check is 32 bit
    for module in ir.modules:
        assert module.isa == gtirb.Module.ISA.IA32, "Only 32 bit supported"

    basename = os.path.basename(output).replace('.exe', '')

    # Generate asm 
    asm_fname = os.path.join(working_dir, f'{basename}.S')
    cmd = ["gtirb-pprinter", ir_file, '--asm', asm_fname]
    run_cmd(cmd)

    # Generate def files to use with linking dlls in final binary
    def_files = generate_def_file(ir, working_dir, [DUMMY_LIB_NAME])

    # Modify ASM to link to our lib files.
    # The default name gtirb-pprinter for the lib files is the dll name + lib,
    # which is encoded in the generated assembly.
    # e.g. for Kernel32.dll the generated lib file will be KERNEL32.LIB.
    # This causes conflicts with the actual Kernel32.lib which we need to use
    # to link most static libraries. So we name our lib files something
    # different to avoid this.
    asm = None
    with open(asm_fname, 'r') as f:
        asm = f.read();

    for dll in def_files:
        gtirb_lib_name = dll
        if dll.endswith('.dll'):
            gtirb_lib_name = dll[:-4]+'.lib'

        new_lib_name = f'{dll}.lib'
        new_includelib_line= f'INCLUDELIB {new_lib_name}'
        old_includelib_line = f'INCLUDELIB {gtirb_lib_name}'

        # inefficient
        asm = asm.replace(old_includelib_line, new_includelib_line)

    # Remove dummy library include. Symbols 'used' by dummy library will be
    # fullfilled by static library we later link. Dummy library included as
    # gtirb doesn't allow referencing symbols unless we define the dll they
    # come from, which it attempts to import while binary pretty printing
    dummy_lib_include = f'INCLUDELIB {DUMMY_LIB_NAME}\n'
    asm = asm.replace(dummy_lib_include, '')

    # Write back modified ASM
    with open(asm_fname, 'w') as f:
        f.write(asm)

    # We have the def files and the corrected asm, time to scp over to build
    # server and build
    cmd = ["scp"]
    # send over def files
    for dll in def_files:
        cmd.append(def_files[dll])
    # send over asm
    cmd.append(asm_fname)
    cmd.append(f"{ssh_address}:{remote_working_dir}")
    run_cmd(cmd)

    # Generate lib files from def files
    for dll in def_files:
        remote_lib = os.path.join(remote_working_dir, f'{dll}.lib')
        remote_def = os.path.join(remote_working_dir, os.path.basename(def_files[dll]))

        cmd = ["ssh", ssh_address, fr"lib.exe /nologo /def:{remote_def} /out:{remote_lib} /MACHINE:X86"]
        run_cmd(cmd)

    # Generate object file from instrumented assembly
    remote_asm = os.path.join(remote_working_dir, os.path.basename(asm_fname))
    obj_fname = f'{basename}.obj'
    remote_obj = os.path.join(remote_working_dir, obj_fname)
    cmd = ["ssh", ssh_address, fr"ml.exe /nologo /c /Fo{remote_obj} {remote_asm}"]
    run_cmd(cmd)

    # Generate executable, linking files if needed
    binary_fname = f'{basename}.exe'
    remote_binary = os.path.join(remote_working_dir, binary_fname)

    # cl command must be run from same directory containing def files for linker to find them
    cmd1 = f"cd {remote_working_dir}"
    extra_libs = []
    if static_lib_link:
        extra_libs = ["vcruntime.lib", "ucrt.lib", "kernel32.lib", "user32.lib", static_lib_link]
    cmd2 = fr"cl /nologo {obj_fname} /Fe{binary_fname} /link {' '.join(extra_libs)} /ENTRY:_EntryPoint /SUBSYSTEM:console"

    cmd = ["ssh", ssh_address, '; '.join([cmd1, cmd2])]
    run_cmd(cmd)

    # copy binary back to local
    cmd = ["scp", f"{ssh_address}:{remote_binary}", output]
    run_cmd(cmd)