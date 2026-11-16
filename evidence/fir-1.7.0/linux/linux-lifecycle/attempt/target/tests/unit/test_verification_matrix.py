from __future__ import annotations

import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import cli
from full_inspection_repair.verification_matrix import (
    MatrixBlocked,
    build_case_registry,
    reconcile_evaluation,
    verify_matrix_binding,
)
from full_inspection_repair.contracts import material_digest
from full_inspection_repair.semantic_matrix import (
    build_semantic_evaluation_matrix,
    semantic_report_projection,
)


def test_all_unscored_is_inconclusive_not_success():
    with pytest.raises(MatrixBlocked, match="unscored"):
        reconcile_evaluation(
            requested=["a", "b"],
            attempts={"a": "UNSCORED", "b": "UNSCORED"},
            f2p={"a"},
            p2p={"b"},
        )


def test_missing_requested_case_blocks():
    with pytest.raises(MatrixBlocked, match="missing"):
        reconcile_evaluation(
            requested=["a", "b"],
            attempts={"a": "PASS"},
            f2p={"a"},
            p2p={"b"},
        )


def test_f2p_and_p2p_must_both_pass():
    with pytest.raises(MatrixBlocked, match="F2P/P2P"):
        reconcile_evaluation(
            requested=["a", "b"],
            attempts={"a": "PASS", "b": "FAIL"},
            f2p={"a"},
            p2p={"b"},
        )


def test_clean_matrix_passes():
    result = reconcile_evaluation(
        requested=["a", "b"],
        attempts={"a": "PASS", "b": "PASS"},
        f2p={"a"},
        p2p={"b"},
    )

    assert result["status"] == "PASS"


def test_cli_evaluation_requires_case_identities_and_complete_bindings(
    tmp_path: Path,
):
    expected = {
        "run_id": "run:test",
        "scope_digest": "4" * 64,
        "subject_digest": "5" * 64,
        "candidate_digest": "6" * 64,
    }
    evidence = {
        "requested": ["case-a"],
        "attempts": {"case-a": "PASS"},
        "f2p": ["case-a"],
        "p2p": [],
        "case_identities": {
            "case-a": {
                "fixture_digest": "1" * 64,
                "runner_digest": "2" * 64,
                "tool_digest": "3" * 64,
            }
        },
        **expected,
    }
    registry = build_case_registry(evidence["case_identities"])
    evidence["case_registry_digest"] = registry["registry_digest"]
    path = tmp_path / "evaluation.json"
    path.write_text(__import__("json").dumps(evidence), encoding="utf-8")
    load = lambda: cli._load_evaluation_matrix(
        str(path), **expected, case_registry=registry
    )
    assert load()["status"] == "PASS"

    for missing in (
        "case_identities",
        "run_id",
        "scope_digest",
        "subject_digest",
        "candidate_digest",
        "case_registry_digest",
    ):
        incomplete = dict(evidence)
        incomplete.pop(missing)
        path.write_text(__import__("json").dumps(incomplete), encoding="utf-8")
        with pytest.raises(MatrixBlocked):
            load()

    mismatch = dict(evidence)
    mismatch["candidate_digest"] = "7" * 64
    path.write_text(__import__("json").dumps(mismatch), encoding="utf-8")
    with pytest.raises(MatrixBlocked, match="does not match the frozen run"):
        load()

    foreign = {
        **evidence,
        "requested": ["foreign-case"],
        "attempts": {"foreign-case": "PASS"},
        "f2p": ["foreign-case"],
        "case_identities": {
            "foreign-case": {
                "fixture_digest": "7" * 64,
                "runner_digest": "8" * 64,
                "tool_digest": "9" * 64,
            }
        },
    }
    path.write_text(__import__("json").dumps(foreign), encoding="utf-8")
    with pytest.raises(MatrixBlocked, match="has no expected identity"):
        load()


def test_matrix_counts_must_reconcile_with_case_statuses():
    identities = {
        "case-a": {
            "fixture_digest": "1" * 64,
            "runner_digest": "2" * 64,
            "tool_digest": "3" * 64,
        }
    }
    registry = build_case_registry(identities)
    matrix = reconcile_evaluation(
        requested=["case-a"],
        attempts={"case-a": "PASS"},
        f2p={"case-a"},
        p2p=set(),
        case_identities=identities,
        expected_identities=identities,
        case_registry_digest=registry["registry_digest"],
        run_id="run:test",
        scope_digest="4" * 64,
        subject_digest="5" * 64,
        candidate_digest="6" * 64,
    )
    matrix["requested_count"] = 999
    matrix["matrix_digest"] = material_digest(matrix, "matrix_digest")

    with pytest.raises(MatrixBlocked, match="requested_count"):
        verify_matrix_binding(
            matrix,
            run_id="run:test",
            scope_digest="4" * 64,
            subject_digest="5" * 64,
            candidate_digest="6" * 64,
            expected_identities=identities,
            case_registry_digest=registry["registry_digest"],
        )


def test_semantic_finding_cannot_be_counted_as_execution_pass():
    report = {
        "cells": [
            {
                "cell_id": "SKILL:EXCEPTION_PATH:LIFECYCLE",
                "status": "FINDING",
                "binding_digest": "1" * 64,
                "findings": [{"semantic_digest": "2" * 64}],
            }
        ]
    }
    with pytest.raises(MatrixBlocked, match="F2P/P2P not satisfied"):
        build_semantic_evaluation_matrix(
            report,
            tool_digest="3" * 64,
            run_id="run:test",
            scope_digest="4" * 64,
            subject_digest="5" * 64,
            candidate_digest="6" * 64,
        )


def test_snapshot_level_semantic_finding_is_retained_and_anchored():
    report = {
        "cells": [
            {
                "cell_id": "SKILL:EXCEPTION_PATH:LIFECYCLE",
                "category_id": "EXCEPTION_PATH",
                "receipt_digest": "1" * 64,
                "findings": [
                    {
                        "primary_locator": {"path": "."},
                        "semantic_digest": "2" * 64,
                        "defect_class_id": "lifecycle-rollback-unverified",
                    }
                ],
            }
        ]
    }
    subject = SimpleNamespace(
        files=[SimpleNamespace(locator="SKILL.md")],
        tree_digest="3" * 64,
        subject_id="skill:test",
    )
    findings = cli._semantic_risk_findings(report, subject)

    assert len(findings) == 1
    assert findings[0]["affected_refs"] == ["."]
    assert findings[0]["source_id"] == "source:SKILL.md"


def test_semantic_projection_preserves_execution_evidence():
    report = {
        "phase": "VERIFICATION",
        "scope_id": "scope:test",
        "cell_count": 1,
        "finding_count": 1,
        "findings": [{"semantic_digest": "1" * 64}],
        "cells": [
            {
                "cell_id": "SKILL:BOUNDARY:BEHAVIOR",
                "recorded_at": "2026-11-16T00:00:00Z",
                "receipt_digest": "2" * 64,
                "resource_receipt": {
                    "elapsed_seconds": 0.1,
                    "peak_rss_mib": 64.0,
                    "files": 1,
                },
                "process_tree_receipt": {
                    "root_pid": 123,
                    "descendants_empty": True,
                },
                "network_guard_receipt": {
                    "policy": "DENY",
                    "enforced": True,
                },
            }
        ],
    }
    projection = semantic_report_projection(report)
    assert projection["findings"] == report["findings"]
    assert projection["cells"][0]["resource_receipt"]["files"] == 1
    assert "elapsed_seconds" not in projection["cells"][0]["resource_receipt"]
    assert projection["cells"][0]["resource_receipt"]["peak_rss_mib"] == 64.0
    assert "root_pid" not in projection["cells"][0]["process_tree_receipt"]

    forged = __import__("copy").deepcopy(report)
    forged["cells"][0]["network_guard_receipt"]["policy"] = "ALLOW"
    assert semantic_report_projection(forged) != projection

    forged_resource = __import__("copy").deepcopy(report)
    forged_resource["cells"][0]["resource_receipt"]["peak_rss_mib"] = 65536.0
    assert semantic_report_projection(forged_resource) != projection
