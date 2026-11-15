from __future__ import annotations

import argparse
import json
from pathlib import Path


def validate(case: dict) -> dict:
    errors = []
    if case.get("attempts") != 1:
        errors.append("ATTEMPT_LIMIT")
    if not case.get("scope_id"):
        errors.append("MISSING_SCOPE")
    if not case.get("fail_before"):
        errors.append("MISSING_FAIL_BEFORE")
    if not case.get("fix_pass"):
        errors.append("MISSING_FIX_PASS")
    if case.get("regression"):
        errors.append("REGRESSION")
    if not case.get("mutation"):
        errors.append("MISSING_MUTATION")
    if case.get("accepted"):
        errors.append("ACCEPTED_CANNOT_CLOSE")
    if case.get("caller_count"):
        errors.append("CALLER_COUNT_REJECTED")
    return {
        "case": case.get("name"),
        "classification": "VALID" if not errors else "INVALID",
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    args = parser.parse_args()
    payload = json.loads((Path(args.target) / "cases.json").read_text(encoding="utf-8"))
    print(json.dumps({"receipts": [validate(case) for case in payload["cases"]]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
