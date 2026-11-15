from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.adapters import build_subject
from full_inspection_repair.semantic_matrix import (
    build_cell_receipt,
    compare_semantic_witnesses,
    execute_semantic_matrix,
    normalize_semantic_witness,
    validate_cell_not_applicable_proof,
)
from full_inspection_repair.runtime_registry import load_registry


def _witness(**overrides):
    value = {
        "cell_id": "SKILL:FUNCTIONAL_FAULT:SEMANTIC",
        "defect_class_id": "declared-read-effect",
        "invariant_id": "INV-READ-EFFECT",
        "primary_locator": {"path": "pkg/a.py", "start_byte": 10, "symbol": "run"},
        "normalized_evidence": {"effect": "write"},
        "message": "detector wording",
        "witness_id": "native-1",
    }
    value.update(overrides)
    return value


def test_t_det_01_all_72_cells_get_cell_specific_receipts(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: matrix-demo\n---\n\n# Demo\n", encoding="utf-8"
    )
    report = execute_semantic_matrix(build_subject(tmp_path, "SKILL"))

    assert report["cell_count"] == 72
    assert report["blocked_count"] == 0
    assert report["not_applicable_count"] > 0
    assert len(set(report["receipt_digests"])) == 72
    assert all(item["cell_id"] for item in report["cells"])
    assert all("detector_result" in item and "oracle_result" in item for item in report["cells"])
    assert "findings" in report and isinstance(report["findings"], list)
    exact = next(
        item
        for item in report["cells"]
        if item["terminal_state"] == "COVERED_BY_EXACT_ADAPTER"
    )
    assert exact["detector_result"] is None
    assert exact["failure_code"] != "EXACT_ADAPTER_TARGET_REQUIRED"
    assert exact["status"] == "CLEAN_WITH_PROOF"
    validate_cell_not_applicable_proof(
        exact["not_applicable_proof"],
        cell_id=exact["cell_id"],
        registry_digest=report["runtime_registry_digest"],
    )


def test_t_det_04_message_lines_and_labels_do_not_affect_semantics() -> None:
    detector = _witness()
    oracle = {
        "cellId": detector["cell_id"],
        "defectClassId": detector["defect_class_id"],
        "invariantId": detector["invariant_id"],
        "path": "./pkg/a.py",
        "symbol": "run",
        "evidence": {"effect": "write"},
        "reason": "different wording",
        "witness": "oracle-label",
        "line": 999,
    }

    assert (
        normalize_semantic_witness(detector)["semantic_digest"]
        == normalize_semantic_witness(oracle)["semantic_digest"]
    )
    assert compare_semantic_witnesses([detector], [oracle])["comparison"] == "AGREE"


def test_t_det_05_one_sided_or_contradictory_evidence_blocks() -> None:
    detector = _witness()
    clean = {"status": "CLEAN", "facts": []}
    different = _witness(normalized_evidence={"effect": "delete"})

    assert compare_semantic_witnesses([detector], [clean])["comparison"] == "BLOCKED"
    assert compare_semantic_witnesses([detector], [different])["comparison"] == "DISAGREE"

    binding = load_registry().cell_binding("SKILL:FUNCTIONAL_FAULT:SEMANTIC")
    receipt = build_cell_receipt(
        binding,
        detector_raw={"status": "FINDING", "findings": [detector]},
        oracle_raw={"status": "FINDING", "findings": [different]},
        subject_digest="a" * 64,
    )
    assert receipt["status"] == "BLOCKED"
    assert receipt["failure_code"] == "ORACLE_DISAGREEMENT"
    assert receipt["detector_result"]["result_digest"]
    assert receipt["oracle_result"]["result_digest"]


def test_empty_evidence_from_an_applicable_cell_stays_uncovered() -> None:
    binding = load_registry().cell_binding("SKILL:FUNCTIONAL_FAULT:SEMANTIC")
    binding["_applicability"] = {"applicable": True}
    receipt = build_cell_receipt(
        binding,
        detector_raw={"status": "EMPTY_RESULT", "findings": []},
        oracle_raw={"status": "EMPTY_RESULT", "findings": []},
        subject_digest="a" * 64,
    )

    assert receipt["status"] == "UNCOVERED"
    assert receipt["failure_code"] == "EMPTY_RESULT"
