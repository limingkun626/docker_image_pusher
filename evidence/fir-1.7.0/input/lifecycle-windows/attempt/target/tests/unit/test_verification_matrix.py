from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import cli
from full_inspection_repair.verification_matrix import (
    MatrixBlocked,
    reconcile_evaluation,
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
        "run_id": "run:test",
        "scope_digest": "4" * 64,
        "subject_digest": "5" * 64,
        "candidate_digest": "6" * 64,
    }
    path = tmp_path / "evaluation.json"
    path.write_text(__import__("json").dumps(evidence), encoding="utf-8")
    assert cli._load_evaluation_matrix(str(path))["status"] == "PASS"

    for missing in (
        "case_identities",
        "run_id",
        "scope_digest",
        "subject_digest",
        "candidate_digest",
    ):
        incomplete = dict(evidence)
        incomplete.pop(missing)
        path.write_text(__import__("json").dumps(incomplete), encoding="utf-8")
        with pytest.raises(MatrixBlocked):
            cli._load_evaluation_matrix(str(path))
