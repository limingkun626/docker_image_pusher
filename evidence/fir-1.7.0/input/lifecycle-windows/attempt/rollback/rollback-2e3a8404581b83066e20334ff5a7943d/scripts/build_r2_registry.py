from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMAS = (
    "evidence-fact.schema.json",
    "execution-receipt-v2.schema.json",
    "oracle-receipt.schema.json",
    "lifecycle-receipt.schema.json",
    "cell-solution-contract.schema.json",
    "taxonomy-disposition.schema.json",
)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--r2-snapshot", required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()

    snapshot = Path(args.r2_snapshot).resolve()
    candidate = Path(args.candidate).resolve()
    contracts = candidate / "contracts"
    policies = candidate / "policies"
    contracts.mkdir(parents=True, exist_ok=True)
    policies.mkdir(parents=True, exist_ok=True)

    for name in SCHEMAS:
        source = snapshot / "schemas" / name
        (contracts / name).write_bytes(source.read_bytes())

    package_dir = candidate / "scripts" / "full_inspection_repair"
    package_dir.mkdir(parents=True, exist_ok=True)
    native_source = snapshot / "work" / "native" / "native_p2.py"
    oracle_source = snapshot / "work" / "native" / "oracles_p2.py"
    (package_dir / "native_p2.py").write_bytes(native_source.read_bytes())
    oracle_text = oracle_source.read_text(encoding="utf-8").replace(
        "from native_p2 import",
        "from .native_p2 import",
    )
    (package_dir / "oracles_p2.py").write_text(oracle_text, encoding="utf-8")

    policy_source = snapshot / "policies" / "taxonomy-policy-v2.json"
    policy_bytes = policy_source.read_bytes()
    policy = json.loads(policy_bytes)
    policy_digest = canonical_digest(policy)
    (policies / "taxonomy-policy-v2.json").write_bytes(policy_bytes)

    dispositions = read_jsonl(snapshot / "02_72_cell_final_disposition.jsonl")
    contracts_all = read_jsonl(snapshot / "08_solution_contracts.jsonl")
    cell_contracts = [
        row for row in contracts_all if row.get("scope_kind") == "CELL"
    ]
    adapters = read_jsonl(snapshot / "05_external_adapter_bindings.jsonl")
    if len(dispositions) != 72 or len(cell_contracts) != 72:
        raise ValueError("R2 source does not contain a complete 72-cell denominator")
    if len({row["cell_id"] for row in dispositions}) != 72:
        raise ValueError("R2 dispositions contain duplicate cell IDs")
    if len(adapters) != 11:
        raise ValueError("R2 source does not contain eleven external adapters")
    if any(row["policy_digest"] != policy_digest for row in dispositions):
        raise ValueError("R2 disposition policy digest does not match policy-v2")
    for row in adapters:
        if row.get("exact_module", {}).get("tool") and not row.get(
            "exact_command"
        ):
            raise ValueError(f"adapter lacks exact argv: {row['cell_id']}")
        row["release_authority"] = False

    terminal_counts = dict(
        sorted(Counter(row["terminal_state"] for row in dispositions).items())
    )
    expected = {
        "COVERED_BY_EXACT_ADAPTER": 11,
        "COVERED_BY_INDEPENDENT_ORACLE": 16,
        "COVERED_BY_NATIVE_DETECTOR": 35,
        "MERGED_WITH_PRIMARY_CELL": 2,
        "NOT_APPLICABLE_WITH_PROOF": 8,
    }
    if terminal_counts != expected:
        raise ValueError(f"unexpected terminal counts: {terminal_counts}")

    registry: dict[str, Any] = {
        "schema_version": 2,
        "registry_id": "FIR-SKILL-CELL-SOLUTIONS",
        "registry_version": "1.0.0",
        "policy_file": "policies/taxonomy-policy-v2.json",
        "policy_version": policy["version"],
        "policy_digest": policy_digest,
        "terminal_counts": terminal_counts,
        "dispositions": dispositions,
        "contracts": cell_contracts,
        "external_adapters": adapters,
    }
    registry["registry_digest"] = canonical_digest(registry)
    write_json(policies / "cell-solution-registry.json", registry)
    print(
        canonical_json(
            {
                "status": "PASS",
                "cells": len(dispositions),
                "contracts": len(cell_contracts),
                "adapters": len(adapters),
                "terminal_counts": terminal_counts,
                "policy_digest": policy_digest,
                "registry_digest": registry["registry_digest"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
