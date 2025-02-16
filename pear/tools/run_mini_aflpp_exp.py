import os
import sys
import stat
import time
import pathlib
import argparse
import tempfile
import statistics

def parse_args():
    parser = argparse.ArgumentParser(description='Setup and run AFL++ experiment.')
    def path_exists(f):
        if not pathlib.Path(f).exists():
            parser.error(f'File/folder "{f}" not found.')
        else:
            return f

    parser.add_argument('--exp-binaries', type=path_exists, required=True,
                        help='Folder of binaries to test')
    parser.add_argument('--corpus', type=path_exists, required=True,
                        help='Corpus to test with')
    parser.add_argument('--timeout', required=True,
                        help='How long to run each trial (value to be used in "timeout" command)')
    parser.add_argument('--trials', type=int, required=True,
                        help='Number of trials')
    parser.add_argument('--start-core', type=int, required=False,
                        help='Optional, trials will be tied to this core and consecutive cores')

    args = parser.parse_args()
    return args


def get_execs_per_sec(afl_out_dir: str):
    stats = os.path.join(os.path.join(afl_out_dir, 'default'), 'fuzzer_stats')
    with open(stats, 'r') as f:
        for l in f:
            if l.startswith('execs_per_sec'):
                return float(l.split()[-1])
    return None

if __name__ == '__main__':
    args = parse_args()
    bindir = args.exp_binaries

    testbins = []
    for x in os.listdir(bindir):
        testbins.append(os.path.abspath(os.path.join(bindir, x)))

    corpus = os.path.abspath(args.corpus)
    timeout = args.timeout
    trials = args.trials
    start_core = args.start_core

    with tempfile.TemporaryDirectory('-afl-out') as out:
        print(f'Running experiments in directory {out}')
        no_trials = trials * len(testbins)
        info = f'Running {no_trials} tests. Testing binaries: {testbins}, with corpus "{corpus}", with timeout: {timeout}'
        if start_core != None:
            info = info + f', using cores {start_core} to {start_core+no_trials}'
        info = info + '.'
        print(info)

        script = "#!/bin/bash\nset -mbx\n"

        out_dirs = {}

        curr_core = start_core
        count = 0
        cmds = []
        for binary in testbins:
            out_dirs[binary] = []
            for t in range(trials):
                taskset = ''
                no_affinity = ''
                if start_core != None:
                    taskset = f'taskset -c {curr_core}'
                    no_affinity = 'AFL_NO_AFFINITY=1' # need this as we are picking cores not AFL
                    curr_core += 1
                out_dir = os.path.join(out, f'afl-out-{os.path.basename(binary)}-{t}')
                out_dirs[binary].append(out_dir)
                cmd = f'{no_affinity} AFL_NO_UI=1 timeout {timeout} {taskset} afl-fuzz -i {corpus} -o {out_dir} -- {binary} @@ &'
                cmds.append(cmd)
                count += 1
        script += '\n'.join(cmds)
        # wait until all trials finish
        script += '\nwait'

        print('Generated experiment script:')
        print('-'*80)
        print(script)
        print('-'*80)

        input('Press enter to run... ')

        # write script and make executable
        script_path = os.path.join(out, 'run_exp.sh')
        with open(script_path, 'w') as f:
            f.write(script)
        st = os.stat(script_path)
        os.chmod(script_path, st.st_mode | stat.S_IEXEC)

        # run!
        os.system(f'{script_path}')

        print('-'*80)
        for bin, out_folders in out_dirs.items():
            speeds = []
            for f in out_folders:
                s = get_execs_per_sec(f) 
                if s == None:
                    print('WARNING! could not find execs_per_sec within fuzzer out folder {f} for binary {bin}!')
                else:
                    speeds.append(s)
            avg = statistics.fmean(speeds)
            print(f'{bin}: {avg} execs per second')

        input('Press enter to delete the temp dir ...')

'''
AFL_NO_UI=1 timeout 4 taskset -c 0 ~/AFLplusplus/afl-fuzz -i in/befunge-files/examples -o afl-out -- in/befunge.AFL++.exe @@ &
AFL_NO_UI=1 timeout 4 taskset -c 1 ~/AFLplusplus/afl-fuzz -i in/befunge-files/examples -o afl-out2 -- in/befunge.AFL++.exe @@ &
'''
