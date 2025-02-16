import os
import re
import argparse
import statistics
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser(
        description="Calculate average execs_per_sec for each target."
    )
    parser.add_argument(
        "--experiment-loc",
        required=True,
        help="Folder containing AFL outfolders (e.g., afl-out-befunge.afl-0, afl-out-befunge.AFL++.exe-1, etc.)",
    )
    args = parser.parse_args()

    exp_loc = args.experiment_loc
    if not os.path.isdir(exp_loc):
        print(f"Error: {exp_loc} is not a directory.")
        return

    # Regex to match folder names like 'afl-out-<target>-<number>'
    pattern = re.compile(r"^afl-out-(.+)-\d+$")
    results = defaultdict(list)

    for entry in os.listdir(exp_loc):
        entry_path = os.path.join(exp_loc, entry)
        if not os.path.isdir(entry_path):
            continue
        m = pattern.match(entry)
        if not m:
            continue
        target = m.group(1)
        stats_path = os.path.join(entry_path, "default", "fuzzer_stats")
        if not os.path.isfile(stats_path):
            print(f"Warning: {stats_path} not found.")
            continue

        with open(stats_path) as f:
            for line in f:
                if line.startswith("execs_per_sec"):
                    try:
                        value = float(line.split(":", 1)[1].strip())
                        results[target].append(value)
                    except ValueError:
                        print(f"Warning: Invalid execs_per_sec value in {stats_path}.")
                    break

    for target, values in results.items():
        if values:
            avg = statistics.fmean(values)
            print(f"{target}: {avg:.2f} execs/sec (from {len(values)} trials)")
        else:
            print(f"{target}: No valid execs_per_sec data found.")

if __name__ == "__main__":
    main()
