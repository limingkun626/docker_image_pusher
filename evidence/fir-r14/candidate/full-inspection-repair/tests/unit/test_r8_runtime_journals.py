from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import strict as strict_module
from full_inspection_repair.contracts import ContractError, canonical_digest
from full_inspection_repair.observation import ObservationJournal
from full_inspection_repair.strict import (
    StrictJSONError,
    read_json,
    read_jsonl,
)
from full_inspection_repair.write_ahead import (
    WriteAheadJournal,
    load_journal_checkpoint,
    verify_journal,
    write_journal_checkpoint,
)

DIGEST = "a" * 64


def _append_pair(journal: WriteAheadJournal, event: str) -> None:
    journal.append(
        event_key=event,
        boundary="INTENT",
        phase="runtime",
        action="execute",
        evidence={"step": "intent"},
    )
    journal.append(
        event_key=event,
        boundary="COMPLETION",
        phase="runtime",
        action="execute",
        evidence={"outcome": "completion"},
    )


def _observation(message: str, *, run: str = "run-1", redaction: str = DIGEST):
    return {
        "source_run_id": run,
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
        "redaction_policy_digest": redaction,
        "severity": "Low",
        "analogous_surfaces": [],
        "status": "CONFIRMED",
        "safe_feedback": "Check referenced executables against the manifest.",
        "recorded_at": "2026-11-07T12:00:00Z",
    }


def test_write_ahead_short_write_and_eintr_are_completed(
    tmp_path, monkeypatch
) -> None:
    original = strict_module.os.write
    calls = {"write": 0, "eintr": 0}

    def interrupted_short_write(fd, data):
        if calls["eintr"] == 0:
            calls["eintr"] += 1
            raise InterruptedError
        if calls["write"] == 0:
            calls["write"] += 1
            return original(fd, bytes(data[:3]))
        return original(fd, data)

    monkeypatch.setattr(strict_module.os, "write", interrupted_short_write)
    journal = WriteAheadJournal(tmp_path / "write-ahead.jsonl", subject_digest=DIGEST)
    _append_pair(journal, "detectors")
    journal.close()

    assert calls == {"write": 1, "eintr": 1}
    assert journal.verify()["status"] == "PASS"


def test_write_ahead_fsync_failure_fails_closed(tmp_path, monkeypatch) -> None:
    journal = WriteAheadJournal(tmp_path / "write-ahead.jsonl", subject_digest=DIGEST)
    monkeypatch.setattr(
        strict_module.os,
        "fsync",
        lambda _fd: (_ for _ in ()).throw(OSError("disk unavailable")),
    )

    with pytest.raises(ContractError, match="append failed"):
        journal.append(
            event_key="detectors",
            boundary="INTENT",
            phase="runtime",
            action="execute",
            evidence={},
        )
    journal.close()


def test_write_ahead_pair_identity_is_verified(tmp_path) -> None:
    path = tmp_path / "write-ahead.jsonl"
    journal = WriteAheadJournal(path, subject_digest=DIGEST)
    _append_pair(journal, "detectors")
    journal.close()

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    completion = records[-1]
    completion["phase"] = "other-phase"
    material = dict(completion)
    material.pop("record_digest")
    completion["record_digest"] = canonical_digest(material)
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )

    result = verify_journal(path)
    assert result["status"] == "BLOCKED_JOURNAL"
    assert "pair:2" in result["failures"]


def test_write_ahead_completion_evidence_must_match_intent_parameters(tmp_path) -> None:
    journal = WriteAheadJournal(tmp_path / "write-ahead.jsonl", subject_digest=DIGEST)
    journal.append(
        event_key="detectors",
        boundary="INTENT",
        phase="runtime",
        action="execute",
        evidence={"operation": "write-A"},
    )

    with pytest.raises(ContractError, match="conflicts with intent: operation"):
        journal.append(
            event_key="detectors",
            boundary="COMPLETION",
            phase="runtime",
            action="execute",
            evidence={"operation": "write-Z"},
        )
    journal.close()


def test_write_ahead_completion_must_reference_exact_intent_digest(tmp_path) -> None:
    path = tmp_path / "write-ahead.jsonl"
    journal = WriteAheadJournal(path, subject_digest=DIGEST)
    _append_pair(journal, "detectors")
    journal.close()

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    completion = records[-1]
    completion["intent_digest"] = "0" * 64
    material = dict(completion)
    material.pop("record_digest")
    completion["record_digest"] = canonical_digest(material)
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )

    result = verify_journal(path)
    assert result["status"] == "BLOCKED_JOURNAL"
    assert "intent_reference:2" in result["failures"]


def test_write_ahead_checkpoint_detects_complete_pair_rollback(tmp_path) -> None:
    path = tmp_path / "write-ahead.jsonl"
    journal = WriteAheadJournal(path, subject_digest=DIGEST)
    _append_pair(journal, "first")
    _append_pair(journal, "second")
    checkpoint = journal.checkpoint()
    journal.close()

    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:2]))

    result = journal.verify(checkpoint=checkpoint)
    assert result["status"] == "BLOCKED_JOURNAL"
    assert "high_water:record_count" in result["failures"]
    assert "high_water:head_digest" in result["failures"]


def test_external_checkpoint_is_atomic_and_required_for_truncation(tmp_path) -> None:
    path = tmp_path / "write-ahead.jsonl"
    checkpoint_path = tmp_path / "write-ahead-checkpoint.json"
    journal = WriteAheadJournal(
        path,
        subject_digest=DIGEST,
        source_run_id="run:checkpoint",
    )
    _append_pair(journal, "first")
    _append_pair(journal, "second")
    checkpoint = journal.checkpoint()
    write_journal_checkpoint(checkpoint_path, checkpoint)
    journal.close()

    assert load_journal_checkpoint(checkpoint_path) == checkpoint
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:2]))

    result = verify_journal(
        path,
        checkpoint=load_journal_checkpoint(checkpoint_path),
    )
    assert result["status"] == "BLOCKED_JOURNAL"
    assert "high_water:record_count" in result["failures"]
    with pytest.raises(ContractError, match="already exists"):
        write_journal_checkpoint(checkpoint_path, checkpoint)


def test_write_ahead_missing_final_newline_is_truncated(tmp_path) -> None:
    path = tmp_path / "write-ahead.jsonl"
    journal = WriteAheadJournal(path, subject_digest=DIGEST)
    _append_pair(journal, "detectors")
    journal.close()

    path.write_bytes(path.read_bytes().rstrip(b"\n"))

    result = journal.verify()
    assert result["status"] == "BLOCKED_JOURNAL"
    assert "truncated" in result["failures"]


def test_missing_and_empty_journals_are_not_empty_success(tmp_path) -> None:
    missing = tmp_path / "missing.jsonl"
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")

    assert verify_journal(missing)["status"] == "BLOCKED_JOURNAL"
    assert verify_journal(empty)["status"] == "BLOCKED_JOURNAL"
    with pytest.raises(ContractError, match="missing"):
        ObservationJournal(missing).verify()
    with pytest.raises(ContractError, match="empty"):
        ObservationJournal(empty).verify()


def test_observation_run_and_redaction_provenance_cannot_mix(tmp_path) -> None:
    journal = ObservationJournal(tmp_path / "observations.jsonl")
    journal.append(_observation("first"))

    with pytest.raises(ContractError, match="source_run_id provenance"):
        journal.append(_observation("other run", run="run-2"))
    with pytest.raises(ContractError, match="redaction_policy_digest provenance"):
        journal.append(_observation("other policy", redaction="b" * 64))


def test_observation_checkpoint_detects_record_rollback(tmp_path) -> None:
    path = tmp_path / "observations.jsonl"
    journal = ObservationJournal(path)
    journal.append(_observation("first"))
    journal.append(_observation("second"))
    checkpoint = journal.checkpoint()

    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:1]))

    with pytest.raises(ContractError, match="high_water:record_count"):
        journal.verify(checkpoint=checkpoint)


def test_observation_truncation_and_fsync_failure_fail_closed(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "observations.jsonl"
    journal = ObservationJournal(path)
    journal.append(_observation("first"))
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    with pytest.raises(ContractError, match="truncated"):
        journal.verify()

    other = ObservationJournal(tmp_path / "fsync.jsonl")
    monkeypatch.setattr(
        strict_module.os,
        "fsync",
        lambda _fd: (_ for _ in ()).throw(OSError("disk unavailable")),
    )
    with pytest.raises(ContractError, match="append failed"):
        other.append(_observation("second"))


def test_observation_durable_append_handles_short_writes(
    tmp_path, monkeypatch
) -> None:
    original = strict_module.os.write
    calls = {"count": 0}

    def short_write(fd, data):
        if calls["count"] == 0:
            calls["count"] += 1
            return original(fd, bytes(data[:5]))
        return original(fd, data)

    monkeypatch.setattr(strict_module.os, "write", short_write)
    journal = ObservationJournal(tmp_path / "observations.jsonl")
    journal.append(_observation("first"))

    assert calls["count"] == 1
    assert journal.verify() == 1


def test_json_readers_reject_oversize_before_full_parse(tmp_path) -> None:
    json_path = tmp_path / "large.json"
    jsonl_path = tmp_path / "large.jsonl"
    json_path.write_bytes(b'{"x":"' + b"a" * 2048 + b'"}')
    jsonl_path.write_bytes(b'{"x":"' + b"a" * 2048 + b'"}\n')

    with pytest.raises(StrictJSONError, match="exceeds size policy"):
        read_json(json_path, max_bytes=1024)
    with pytest.raises(StrictJSONError, match="line exceeds size policy"):
        read_jsonl(jsonl_path, max_line_bytes=1024)
