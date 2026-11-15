from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.r2_engine import (
    REGISTRY_PATH,
    TAXONOMY_POLICY_PATH,
    load_registry,
)


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_r2_schemas_and_frozen_records_validate() -> None:
    names = (
        "evidence-fact.schema.json",
        "execution-receipt-v2.schema.json",
        "oracle-receipt.schema.json",
        "lifecycle-receipt.schema.json",
        "cell-solution-contract.schema.json",
        "taxonomy-disposition.schema.json",
    )
    validators = {}
    for name in names:
        schema = json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema)

    registry = load_registry()
    for row in registry["dispositions"]:
        assert not list(
            validators["taxonomy-disposition.schema.json"].iter_errors(row)
        )
    for row in registry["contracts"]:
        assert not list(
            validators["cell-solution-contract.schema.json"].iter_errors(row)
        )


def test_registry_is_bound_to_policy_and_full_terminal_denominator() -> None:
    registry = load_registry()
    policy = json.loads(TAXONOMY_POLICY_PATH.read_text(encoding="utf-8"))

    assert registry["policy_digest"] == canonical_digest(policy)
    assert len(registry["dispositions"]) == 72
    assert len({row["cell_id"] for row in registry["dispositions"]}) == 72
    assert registry["terminal_counts"] == {
        "COVERED_BY_EXACT_ADAPTER": 11,
        "COVERED_BY_INDEPENDENT_ORACLE": 16,
        "COVERED_BY_NATIVE_DETECTOR": 35,
        "MERGED_WITH_PRIMARY_CELL": 2,
        "NOT_APPLICABLE_WITH_PROOF": 8,
    }
    material = dict(registry)
    digest = material.pop("registry_digest")
    assert digest == canonical_digest(material)


def test_adapter_registry_is_exact_and_non_authoritative() -> None:
    registry = load_registry()
    adapters = registry["external_adapters"]

    assert len(adapters) == 11
    assert len({row["cell_id"] for row in adapters}) == 11
    for row in adapters:
        assert row["release_authority"] is False
        assert row["exact_command"]
        assert row["exact_module"]["tool"]
        assert row["exact_module"]["version"]


def test_candidate_tree_declares_1_7_and_contains_no_caches() -> None:
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    operations = (ROOT / "references" / "operations.md").read_text(encoding="utf-8")
    package = (ROOT / "scripts" / "full_inspection_repair" / "__init__.py").read_text(
        encoding="utf-8"
    )

    assert "version: 1.7.0" in skill
    assert "Skill package version: `1.7.0`" in operations
    assert '__version__ = "1.7.0"' in package
    assert not [
        path
        for path in ROOT.rglob("*")
        if path.name in {"__pycache__", ".pytest_cache", ".ruff_cache"}
    ]
