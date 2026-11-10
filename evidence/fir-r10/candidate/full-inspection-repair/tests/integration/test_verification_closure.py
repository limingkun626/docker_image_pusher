from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.adapters import build_subject
from full_inspection_repair.contracts import (
    ContractError,
    assert_zero_open_risk,
)
from full_inspection_repair.detectors import run_default_detectors
from full_inspection_repair.repair import apply_batch, plan_batch
from full_inspection_repair.verification import verify_repair


def findings_for(subject):
    return [
        finding
        for result in run_default_detectors(subject)
        for finding in result.findings
    ]


def test_verification_marks_finding_fixed_only_when_rerun_is_clean(tmp_path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo",
        encoding="utf-8",
    )
    subject = build_subject(source, "SKILL")
    original = findings_for(subject)
    batch = plan_batch(original)
    candidate = tmp_path / "candidate" / "source-skill"
    receipt = apply_batch(subject, batch, candidate)
    candidate_subject = build_subject(candidate, "SKILL")
    candidate_results = run_default_detectors(candidate_subject)

    ledger = verify_repair(
        original_findings=original,
        candidate_results=candidate_results,
        candidate_digest=receipt["candidate_digest"],
        scope_digest=subject.tree_digest,
        required_sources=[f"source:{item.locator}" for item in subject.files],
        observed_sources=[
            f"source:{item.locator}" for item in candidate_subject.files
        ],
        expected_detector_ids=[
            result.detector_id for result in candidate_results
        ],
    )

    assert ledger["closed_count"] == 1
    assert ledger["open_count"] == 0
    assert ledger["items"][0]["status"] == "FIXED"
    assert_zero_open_risk(ledger)


def test_verification_keeps_finding_open_when_rerun_still_fails(tmp_path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: wrong-name\n---\n\n# Demo\n",
        encoding="utf-8",
    )
    subject = build_subject(source, "SKILL")
    original = findings_for(subject)
    candidate_results = run_default_detectors(subject)

    ledger = verify_repair(
        original_findings=original,
        candidate_results=candidate_results,
        candidate_digest="b" * 64,
        scope_digest=subject.tree_digest,
        required_sources=[f"source:{item.locator}" for item in subject.files],
        observed_sources=[f"source:{item.locator}" for item in subject.files],
        expected_detector_ids=[
            result.detector_id for result in candidate_results
        ],
    )

    assert ledger["open_count"] == 1
    with pytest.raises(ContractError, match="open findings"):
        assert_zero_open_risk(ledger)
