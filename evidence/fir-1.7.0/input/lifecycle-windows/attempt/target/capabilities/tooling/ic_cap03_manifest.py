from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    args = parser.parse_args()
    root = Path(args.target)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    actual_ids = []
    errors = []
    for item in manifest["files"]:
        path = root / item["path"]
        if not path.is_file():
            errors.append(f"missing:{item['path']}")
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            errors.append(f"hash:{item['path']}")
        actual_ids.extend(item.get("test_ids", []))
    if len(actual_ids) != manifest["expected_test_count"]:
        errors.append("test-count")
    print(
        json.dumps(
            {
                "classification": "VALID" if not errors else "INVALID",
                "errors": errors,
                "test_count": len(actual_ids),
                "test_ids": actual_ids,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
