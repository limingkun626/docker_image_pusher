from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.adapters import build_subject
from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.source_inventory import (
    SourceInventoryError,
    assert_source_closure_complete,
    assert_source_inventory_current,
    build_source_closure,
    build_source_closure_evidence,
    build_source_inventory,
)


def _subject(tmp_path: Path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: inventory-demo\nversion: 1.0.0\n---\n\n"
        "The runtime must block stale input.\n",
        encoding="utf-8",
    )
    return build_subject(tmp_path, "SKILL")


def _resign(inventory: dict[str, object]) -> None:
    inventory.pop("source_inventory_digest", None)
    inventory["source_inventory_digest"] = canonical_digest(inventory)


def _evidence(inventory: dict[str, object]) -> dict[str, dict[str, object]]:
    return build_source_closure_evidence(
        inventory,
        scope_id="scope:test",
        semantic_report={
            "report_digest": "1" * 64,
            "cells": [
                {
                    "evidence_plane": "LIFECYCLE",
                    "receipt_digest": "2" * 64,
                },
                {
                    "evidence_plane": "BEHAVIOR",
                    "receipt_digest": "3" * 64,
                },
                {
                    "evidence_plane": "STATIC",
                    "receipt_digest": "4" * 64,
                },
            ],
        },
        environment_digest="5" * 64,
    )


def test_t_src_01_inventory_emits_every_typed_source(tmp_path: Path) -> None:
    inventory = build_source_inventory(_subject(tmp_path))

    assert {
        item["source_type"] for item in inventory["sources"]
    } == {
        "RESOURCE",
        "CLAIM",
        "INVARIANT",
        "PLANE",
        "BEHAVIOR",
        "RUNTIME",
        "LIFECYCLE",
        "EXTERNAL",
    }
    assert len({item["source_id"] for item in inventory["sources"]}) == len(
        inventory["sources"]
    )
    assert inventory["source_denominator_digest"]


def test_t_src_02_unknown_source_type_blocks(tmp_path: Path) -> None:
    inventory = build_source_inventory(_subject(tmp_path))
    inventory["sources"][0]["source_type"] = "UNKNOWN"
    _resign(inventory)

    with pytest.raises(SourceInventoryError, match="unknown source type"):
        build_source_closure(inventory)


def test_t_src_03_missing_required_source_blocks(tmp_path: Path) -> None:
    inventory = build_source_inventory(_subject(tmp_path))
    skill = next(
        item for item in inventory["sources"] if item["locator"] == "SKILL.md"
    )
    skill["applicability"] = "REQUIRED_MISSING"
    _resign(inventory)

    closure = build_source_closure(inventory)
    with pytest.raises(SourceInventoryError, match="nonterminal"):
        assert_source_closure_complete(closure)


def test_t_src_04_na_without_proof_blocks(tmp_path: Path) -> None:
    inventory = build_source_inventory(_subject(tmp_path))
    inventory["sources"][0]["applicability"] = "NOT_APPLICABLE_WITH_PROOF"
    inventory["sources"][0]["proof_ref"] = None
    _resign(inventory)

    with pytest.raises(SourceInventoryError, match="lacks proof"):
        build_source_closure(inventory)


def test_t_src_05_candidate_binding_is_not_reusable(tmp_path: Path) -> None:
    subject = _subject(tmp_path)
    inventory = build_source_inventory(subject, candidate_digest="b" * 64)

    with pytest.raises(SourceInventoryError, match="candidate binding"):
        assert_source_inventory_current(
            inventory,
            subject_digest=subject.tree_digest,
            candidate_digest="c" * 64,
        )
    closure = build_source_closure(
        inventory,
        scope_id="scope:test",
        evidence=_evidence(inventory),
    )
    assert_source_closure_complete(closure)


def test_source_closure_does_not_self_certify_applicable_sources(
    tmp_path: Path,
) -> None:
    inventory = build_source_inventory(_subject(tmp_path))
    closure = build_source_closure(inventory)

    assert any(
        item["terminal_status"] == "UNCOVERED"
        for item in closure["records"]
    )
    with pytest.raises(SourceInventoryError, match="nonterminal"):
        assert_source_closure_complete(closure)


def test_source_closure_rejects_opaque_unresolved_evidence(
    tmp_path: Path,
) -> None:
    inventory = build_source_inventory(_subject(tmp_path))
    closure = build_source_closure(
        inventory,
        scope_id="scope:test",
        evidence=_evidence(inventory),
    )
    closure["records"][0]["evidence_refs"] = ["never-executed"]
    closure["closure_digest"] = canonical_digest(
        {key: value for key, value in closure.items() if key != "closure_digest"}
    )

    with pytest.raises(SourceInventoryError, match="unresolved evidence"):
        assert_source_closure_complete(closure)
