from __future__ import annotations

import argparse
import json
from pathlib import Path


def project(case: dict) -> dict:
    requirements = case.get("requirements", [])
    risks = case.get("risks", [])
    blocking = []
    if not requirements:
        blocking.append("EMPTY_DENOMINATOR")
    for risk in risks:
        if risk.get("severity", "").lower() == "critical":
            blocking.append("CRITICAL_FINDING")
        if risk.get("status") not in {"FIXED", "FALSE_POSITIVE"}:
            blocking.append("OPEN_RISK")
        if risk.get("status") == "FIXED" and not risk.get("evidence_sha256"):
            blocking.append("CLOSED_WITHOUT_EVIDENCE")
    return {
        "case": case.get("name"),
        "aggregate_status": "BLOCKED" if blocking else "ALIGNED",
        "blocking": sorted(set(blocking)),
        "denominator": len(requirements),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    args = parser.parse_args()
    target = Path(args.target)
    path = target if target.is_file() else target / "cases.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps({"projections": [project(case) for case in payload["cases"]]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
