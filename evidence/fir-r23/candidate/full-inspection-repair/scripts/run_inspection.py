#!/usr/bin/env python3
import sys

sys.dont_write_bytecode = True

from full_inspection_repair.cli import main


def run() -> int:
    return main()


if __name__ == "__main__":
    raise SystemExit(run())
