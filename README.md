# PeAR
PeAR is a binary instrumentation tool built using the GTIRB framework
that can add AFL++ or WinAFL instrumentation to x64 Linux and x86/x64 Windows
binaries. It also supports adding coverage tracing instrumentation to x64/ARM64
Linux binaries. It can be easily extended to develop other binary
instrumentation tools.

## Features
**Multiplatform binary fuzzing and tracing.** Details on the specific rewriters
PeAR implements are below. You should probably also use the `--ir-cache` option
to cache the disassembled binary IR, but this is ommitted from the examples.

**Instrument binaries from anywhere.** PeAR ensures the instrumented binary
preserves the original binary's properties (shared libraries, rpath, PIE, exec
stack and stack size).  PeAR can also regenerate Windows and Linux binaries
without having the shared libraries they use on the system it is running on.
This makes it easy to instrument binaries from other systems.

**Practical.** PeAR uses GTIRB, a highly powerful binary rewriting framework
capable of succesfully instrumenting real-world binaries, even if they are
stripped (e.g can succesfully instrument libxml2, openssh, nginx).

**Import Ghidra function names.** PeAR can insert function names from Ghidra
into stripped binaries. Use the [ghidra_get_function_names.py](pear/tools/ghidra_get_function_names.py) 
script to generate a function address to name mapping, then pass that to the
`--func-names` option when instrumenting a binary. Use the Identity rewriter if
you'd just like to add the function names and nothing more.

### AFL++ Rewriter
Adds AFL++ instrumentation for fuzzing x64 Linux binaries.
- Supports advanced fuzzing modes:
  - **Deferred mode**: Skips program initialisation by starting fuzzing at a
    specific point
  - **Persistent mode**: Repeatedly fuzz target function without restarting binary,
    significantly improving performance
  - **Shared memory fuzzing**: Uses shared memory between the fuzzer and target
    program to transfer testcases, significantly improving performance
    - This requires a writing a shared memory hook to transfer the testcase
      to the target program. See [hook.c](sharedmem_hook_template/hook.c) for an
      example.
- Example usage:
  - `./PeAR.sh --input-binary program --output-dir out --gen-binary AFL++`
  - Deferred: `./PeAR.sh --input-binary program --output-dir out --gen-binary AFL++ --deferred-fuzz-function process_input`
  - Deferred+persistent: `./PeAR.sh --input-binary program --output-dir out --gen-binary AFL++ --deferred-fuzz-function process_input --persistent-mode-function process_input --persistent-mode-count 10000`
  - Deferred+persistent+sharedmem: `./PeAR.sh --input-binary program --output-dir out --gen-binary AFL++ --deferred-fuzz-function process_input --persistent-mode-function process_input --persistent-mode-count 10000 --sharedmem-call-function process_input --sharedmem-obj hook.o`
- Run `./PeAR.sh --input-binary program --output-dir out --gen-binary AFL++ -h`
  for more options.

### WinAFL Rewriter
Adds WinAFL instrumentation for fuzzing x86 or x64 Windows binaries. 
- Example usage: `./PeAR.bat --input-binary program.exe --output-dir out --gen-binary WinAFL --target-func 0x401000`

### Trace Rewriter
Adds basic block tracing to Linux binaries. When the instrumented binary is run,
it will output the coverage file: `<progname>.<PID>.cov`. This can be processed
to show the instructions that ran during that execution, or generate an EZCOV
file to use with the [Cartographer Ghidra plugin](https://github.com/nccgroup/Cartographer) 
to visualise the execution.

The Trace rewriter is faster than DynamoRIO drcov for coverage tracing. On x64
systems, it has a ~10x slowdown compared to ~80x for DynamoRIO drcov. On ARM64
systems, it has a ~20x slowdown compared to ~40x for DynamoRIO drcov.

- Options:
  - `--print-execution`: Print instructions as they execute
  - `--add-coverage`: Generate coverage output on runs
  - `--fast`: Use fast tracing (may lose data on abnormal termination)
  - `--slow`: Use slow tracing (logs more info on abnormal termination)
- Example usage:
  - Instrument program: `pear --input-binary program --output-dir out --gen-binary Trace --add-coverage --fast`
    - This will also generate an auxillary info file, e.g. `out/program.Trace.basicblockinfo.json`.
  - Print executed instructions: `python3 pear/tools/parse_coverage.py --aux-info out/program.Trace.basicblockinfo.json --cov-file <COV_FILE> PrintExecution`
  - Generate EZCOV: `python3 pear/tools/parse_coverage.py --aux-info out/program.Trace.basicblockinfo.json --cov-file <COV_FILE> GenerateEZCOV`

### Identity Rewriter
A diagnostic rewriter that lifts a binary to GTIRB IR and attempts to regenerate
it without any transformations. This is useful for:
- Testing if GTIRB can correctly disassemble and reassemble a binary
- Getting the assembly source of the binary for manual patching before
  re-assembling with the Regenerate rewriter
- Example usage:
  - `pear --input-binary program --output-dir out --gen-binary Identity`
  - `pear --input-binary program --output-dir out --gen-asm Identity`

### Regenerate Rewriter
Regenerates a binary from instrumented assembly source while preserving the
original binary's properties.
- Example usage:
  - First get program assembly: `pear --input-binary program --output-dir out --gen-binary Identity`
  - Modify this assembly as needed.
  - Regenerate binary from modifies assembly: `pear --input-binary program --output-dir out --gen-binary Regenerate --from-asm out/program.Identity.S`

## Run using Docker (recommended for Linux)
1. Make sure docker is installed and you can run it non-root.
2. Install python 3, max version python 3.10.
3. (Optional but recommended) Create a virtual environment to run PeAR in.
4. Install dependencies with `python -m pip install -r requirements.txt`.
4. Run using `./PeAR.sh`. This shell script sets up wrappers for `ddisasm` and
   `gtirb-pprinter` that passthrough to docker.

To use the wrappers yourself, run `source ./enable_wrappers.sh`. Then run
`deactivate_wrappers` to remove them.

## Run locally (recommended for Windows)
1. Download `ddisasm` and `gtirb-pprinter` binaries here:
   https://download.grammatech.com/gtirb/files/windows-release/, and put them on
   your PATH.
3. Install python 3, max version python 3.10.
4. (Optional but recommended) Create a virtual environment to run PeAR in.
5. Install dependencies with `python -m pip install -r requirements.txt`.
6. Run `python -m pear -h` or `.\PeAR.bat -h` to get started.

## Run tests
To run tests on Windows, run: `pytest .\pear\ -v -rA -s --ir-cache IR_CACHE --vcvarsall-loc VCVARSALL_LOC --winafl32-afl-fuzz-loc AFL32_LOC --winafl64-afl-fuzz-loc AFL64_LOC`.

Windows Defender could prevent the tests from running correctly. To temporarily
disable it while running tests, open the Windows Security app -> Virus and
threat protection -> 'Manage settings' under Virus and threat protection
settings -> turn off 'Real-time protection'.

Running tests requires:
1. The location of your `vcvarsall.bat`. This is used to run the MSVC
development environment, which is used to test PeAR with different
architectures. On my computer the location is:
`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat`.
2. The location of your 32-bit and 64-bit builds of WinAFL (the `afl-fuzz`
binary)

The `--ir-cache` argument is optional but recommended to speed up the tests.
Provide it a directory (in which it will cache IR files generated during the
test run).

For Linux, use `pytest.sh` (which sets up docker wrappers for the GTIRB tools),
and omit the `--vcvarsall-loc`, `--winafl32-afl-fuzz-loc`,
`--winafl64-afl-fuzz-loc` options.

I recommend using the `-v -rA -s` arguments with pytest so you can see the tests
as they run live, including the WinAFL/AFL++ UI as the instrumented test
binaries get run. If you want to hide this UI, use `--hide-afl-ui`.
