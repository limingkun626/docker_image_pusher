from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.adapters import build_subject
from full_inspection_repair.detectors import run_default_detectors
from full_inspection_repair.repair import (
    RepairBlocked,
    apply_batch,
    plan_batch,
    preflight_batch,
)


def test_safe_fix_is_applied_only_to_candidate_tree(tmp_path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo",
        encoding="utf-8",
    )
    subject = build_subject(source, "SKILL")
    findings = [
        finding
        for result in run_default_detectors(subject)
        for finding in result.findings
    ]
    batch = plan_batch(findings)
    candidate = tmp_path / "candidate-skill"

    receipt = apply_batch(subject, batch, candidate)

    assert (source / "SKILL.md").read_bytes().endswith(b"# Demo")
    assert (candidate / "SKILL.md").read_bytes().endswith(b"# Demo\n")
    assert receipt["operations"][0]["preimage_sha256"] != receipt["operations"][0]["postimage_sha256"]


def test_human_decision_issue_blocks_preflight_and_leaves_source_untouched(tmp_path):
    source = tmp_path / "source-skill"
    source.mkdir()
    original = "---\nname: source-skill\n---\n\nTODO\n"
    (source / "SKILL.md").write_text(original, encoding="utf-8")
    subject = build_subject(source, "SKILL")
    findings = [
        finding
        for result in run_default_detectors(subject)
        for finding in result.findings
    ]
    batch = plan_batch(findings)

    with pytest.raises(RepairBlocked, match="manual decision"):
        apply_batch(subject, batch, tmp_path / "candidate-skill")

    assert (source / "SKILL.md").read_text(encoding="utf-8") == original


def test_conflicting_operations_block_batch_freeze():
    batch = {
        "operations": [
            {
                "risk_id": "a",
                "operation_type": "APPEND_FINAL_NEWLINE",
                "target": "SKILL.md",
                "requires_manual_decision": False,
            },
            {
                "risk_id": "b",
                "operation_type": "HUMAN_DECISION_REQUIRED",
                "target": "SKILL.md",
                "requires_manual_decision": True,
            },
        ]
    }

    with pytest.raises(RepairBlocked, match="conflict"):
        preflight_batch(batch)


def test_failed_second_operation_removes_candidate_tree(tmp_path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text("text", encoding="utf-8")
    subject = build_subject(source, "SKILL")
    batch = {
        "operations": [
            {
                "risk_id": "a",
                "operation_type": "APPEND_FINAL_NEWLINE",
                "target": "SKILL.md",
                "requires_manual_decision": False,
            },
            {
                "risk_id": "b",
                "operation_type": "APPEND_FINAL_NEWLINE",
                "target": "missing.md",
                "requires_manual_decision": False,
            },
        ]
    }
    candidate = tmp_path / "candidate-skill"

    with pytest.raises(RepairBlocked, match="not a file"):
        apply_batch(subject, batch, candidate)

    assert not candidate.exists()
