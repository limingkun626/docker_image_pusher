from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import ContractError
from full_inspection_repair.ledger import build_risk_ledger

DIGEST = "a" * 64


def finding(source_id: str = "source:SKILL.md"):
    return {
        "risk_id": "finding-1",
        "invariant_id": "TEXT-FINAL-NEWLINE-001",
        "defect_class_id": "text.missing_final_newline",
        "taxonomy_category_id": "INCONSISTENCY",
        "subject_id": "skill:demo",
        "source_id": source_id,
        "severity": "Low",
        "message": "missing final newline",
        "mechanism": "writer omitted terminator",
        "affected_refs": ["SKILL.md"],
        "root_cause_id": "root-1",
        "status": "OPEN",
        "evidence_refs": ["source:SKILL.md"],
        "evidence_sha256": DIGEST,
        "closed_by": None,
        "closed_at": None,
        "verification_check": None,
        "residual_risk": None,
    }


def test_builder_keeps_open_low_finding_in_ledger():
    ledger = build_risk_ledger(
        scope_digest=DIGEST,
        required_sources=["source:SKILL.md"],
        findings=[finding()],
        observed_sources=["source:SKILL.md"],
    )

    assert ledger["open_count"] == 1
    assert ledger["closed_count"] == 0
    assert ledger["items"][0]["severity"] == "Low"


def test_builder_rejects_finding_from_unexpected_source():
    with pytest.raises(ContractError, match="unexpected finding source"):
        build_risk_ledger(
            scope_digest=DIGEST,
            required_sources=["source:SKILL.md"],
            findings=[finding("source:notes.txt")],
            observed_sources=["source:SKILL.md", "source:notes.txt"],
        )
