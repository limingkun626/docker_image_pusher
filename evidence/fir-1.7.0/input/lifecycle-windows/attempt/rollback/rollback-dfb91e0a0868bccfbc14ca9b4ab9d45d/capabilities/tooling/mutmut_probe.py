from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


MUTMUT = (
    "/mnt/f/Codex/reports/fir-capability-admission-r1-20261114/"
    "work/runtimes/wsl/mutmut/bin/mutmut"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    args = parser.parse_args()
    target = Path(args.target).resolve()
    if os.name == "nt":
        wsl = shutil.which("wsl.exe")
        if wsl is None:
            sys.stderr.write("wsl.exe is unavailable\n")
            return 127
        prefix = [
            wsl,
            "-d",
            "Ubuntu2404",
            "--",
            "unshare",
            "-n",
            "--",
            os.environ.get("FIR_MUTMUT", MUTMUT),
        ]
    else:
        executable = shutil.which("mutmut")
        if executable is None:
            sys.stderr.write("mutmut executable is unavailable\n")
            return 127
        prefix = [executable]
    run = subprocess.run(
        [*prefix, "run", "--max-children", "1"],
        cwd=target,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=100,
        check=False,
    )
    if run.returncode != 0:
        sys.stderr.write(run.stderr)
        return run.returncode
    results = subprocess.run(
        [*prefix, "results"],
        cwd=target,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    sys.stdout.write(results.stdout)
    sys.stderr.write(results.stderr)
    return results.returncode


if __name__ == "__main__":
    raise SystemExit(main())
