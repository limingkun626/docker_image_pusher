from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import ContractError
from full_inspection_repair.observation import ObservationJournal

DIGEST = "a" * 64


def observation(message: str):
    return {
        "source_run_id": "run-1",
        "source_phase": "CHECK",
        "producer_id": "checker",
        "subject_id": "skill:demo",
        "subject_kind": "SKILL",
        "subject_digest": DIGEST,
        "invariant_id": "INV-001",
        "defect_class_id": "omission.resource",
        "taxonomy_category_id": "OMISSION",
        "fingerprint": "missing-resource",
        "fingerprint_version": "1.0.0",
        "message": message,
        "mechanism": "The manifest omits a referenced executable.",
        "root_cause_hypothesis": None,
        "evidence_refs": ["evidence/finding-1.json"],
        "evidence_sha256": DIGEST,
        "redaction_policy_digest": DIGEST,
        "severity": "Low",
        "analogous_surfaces": [],
        "status": "CONFIRMED",
        "safe_feedback": "Check referenced executables against the manifest.",
        "recorded_at": "2026-11-07T12:00:00Z",
    }


def test_journal_appends_hash_chained_records(tmp_path):
    journal = ObservationJournal(tmp_path / "observations.jsonl")

    first = journal.append(observation("first"))
    second = journal.append(observation("second"))

    assert first["journal_sequence"] == 1
    assert first["previous_record_digest"] is None
    assert second["journal_sequence"] == 2
    assert second["previous_record_digest"] == first["record_digest"]
    assert journal.verify() == 2


def test_journal_detects_message_tampering(tmp_path):
    path = tmp_path / "observations.jsonl"
    journal = ObservationJournal(path)
    journal.append(observation("original"))

    record = json.loads(path.read_text(encoding="utf-8"))
    record["message"] = "tampered"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(ContractError, match="hash chain"):
        journal.verify()
