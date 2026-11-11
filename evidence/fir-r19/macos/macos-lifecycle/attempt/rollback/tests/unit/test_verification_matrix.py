from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

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
