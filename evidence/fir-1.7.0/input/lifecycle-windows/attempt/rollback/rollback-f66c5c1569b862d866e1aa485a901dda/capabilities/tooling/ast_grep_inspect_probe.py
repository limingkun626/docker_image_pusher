from __future__ import annotations

import json
import subprocess
import sys


REQUIRED_ITEM_FIELDS = {"text", "range", "file", "language"}


def main() -> int:
    tool, *arguments = sys.argv[1:]
    completed = subprocess.run(
        [tool, *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode not in {0, 1}:
        sys.stderr.write(completed.stderr)
        return completed.returncode
    try:
        results = json.loads(completed.stdout)
    except json.JSONDecodeError:
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        return 2
    if not isinstance(results, list):
        print(json.dumps({"classification": "INVALID_CONTRACT", "results": []}))
        return 0
    if any(
        not isinstance(item, dict)
        or REQUIRED_ITEM_FIELDS - set(item)
        for item in results
    ):
        print(json.dumps({"classification": "INVALID_CONTRACT", "results": results}))
        return 0
    print(
        json.dumps(
            {
                "classification": (
                    "DEFECT_DETECTED" if results else "CLEAN"
                ),
                "results": results,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
