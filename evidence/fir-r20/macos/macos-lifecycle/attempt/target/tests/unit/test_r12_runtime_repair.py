from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import strict as strict_module
from full_inspection_repair.adapters import build_subject
from full_inspection_repair.contracts import ContractError, canonical_digest
from full_inspection_repair.detectors import DetectorResult, run_detectors
from full_inspection_repair.observation import ObservationJournal
from full_inspection_repair.repair import RepairBlocked, apply_batch, plan_batch
from full_inspection_repair.write_ahead import WriteAheadJournal, verify_journal

DIGEST = "a" * 64


def _observation(message: str = "record") -> dict[str, object]:
    return {
        "source_run_id": "run:r12",
        "source_phase": "CHECK",
        "producer_id": "checker",
        "subject_id": "skill:demo",
        "subject_kind": "SKILL",
        "subject_digest": DIGEST,
        "invariant_id": "INV-R12",
        "defect_class_id": "runtime.path",
        "taxonomy_category_id": "VULNERABILITY",
        "fingerprint": "runtime-path",
        "fingerprint_version": "1.0.0",
        "message": message,
        "mechanism": "probe",
        "root_cause_hypothesis": None,
        "evidence_refs": ["evidence/r12.json"],
        "evidence_sha256": DIGEST,
        "redaction_policy_digest": DIGEST,
        "severity": "High",
        "analogous_surfaces": [],
        "status": "CONFIRMED",
        "safe_feedback": "Do not follow links.",
        "recorded_at": "2026-11-11T00:00:00+00:00",
    }


def _directory_alias(real: Path, alias: Path) -> None:
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(alias), str(real)],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        assert completed.returncode == 0, completed.stderr or completed.stdout
    else:
        alias.symlink_to(real, target_is_directory=True)


def _remove_alias(alias: Path) -> None:
    if os.name == "nt":
        alias.rmdir()
    else:
        alias.unlink()


def test_observation_rejects_linked_data_and_lock_paths(tmp_path: Path) -> None:
    victim = tmp_path / "outside.bin"
    victim.write_bytes(b"outside")
    data_link = tmp_path / "observations.jsonl"
    data_link.symlink_to(victim)
    with pytest.raises(ContractError, match="link|reparse"):
        ObservationJournal(data_link).append(_observation())
    assert victim.read_bytes() == b"outside"

    victim.write_bytes(b"")
    lock_link = tmp_path / "lock-target.jsonl.lock"
    lock_link.symlink_to(victim)
    with pytest.raises(ContractError, match="link|reparse"):
        ObservationJournal(tmp_path / "lock-target.jsonl").append(_observation())
    assert victim.read_bytes() == b""


def test_observation_rejects_ancestor_alias_before_writing(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    _directory_alias(real, alias)
    try:
        with pytest.raises(ContractError, match="link|reparse"):
            ObservationJournal(alias / "observations.jsonl").append(_observation())
        assert not (real / "observations.jsonl").exists()
    finally:
        _remove_alias(alias)


@pytest.mark.skipif(os.name != "nt", reason="Windows alternate data streams")
def test_observation_rejects_alternate_data_stream_paths(tmp_path: Path) -> None:
    path = tmp_path / "observations.jsonl:secret"
    with pytest.raises(ContractError, match="alternate data stream"):
        ObservationJournal(path).append(_observation())


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative race")
def test_observation_rejects_final_component_swap_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "observations.jsonl"
    target.write_bytes(b"")
    victim = tmp_path / "victim.bin"
    victim.write_bytes(b"do-not-touch")
    original_open = strict_module.os.open
    swapped = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if (
            not swapped
            and dir_fd is not None
            and path == target.name
            and not flags & os.O_DIRECTORY
        ):
            swapped = True
            target.unlink()
            target.symlink_to(victim)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(strict_module.os, "open", racing_open)
    with pytest.raises(ContractError, match="link|reparse"):
        ObservationJournal(target).append(_observation())
    assert swapped
    assert victim.read_bytes() == b"do-not-touch"


def test_journal_reads_enforce_size_line_and_record_limits(tmp_path: Path) -> None:
    observation = tmp_path / "large-observation.jsonl"
    observation.write_bytes(b"x" * 128)
    with pytest.raises(ContractError, match="size policy"):
        ObservationJournal(observation, max_bytes=64).verify()

    long_line = tmp_path / "long-line.jsonl"
    long_line.write_bytes(b'{"x":"' + b"a" * 128 + b'"}\n')
    with pytest.raises(ContractError, match="line exceeds size policy"):
        ObservationJournal(long_line, max_record_bytes=64).verify()

    many = tmp_path / "many.jsonl"
    many.write_bytes(b"{}\n{}\n{}\n")
    with pytest.raises(ContractError, match="record count"):
        ObservationJournal(many, max_records=2).verify()

    wal = tmp_path / "large-wal.jsonl"
    wal.write_bytes(b"x" * 128)
    assert verify_journal(wal, max_bytes=64)["status"] == "BLOCKED_JOURNAL"


def test_journal_reader_rejects_sparse_file_before_reading(tmp_path: Path) -> None:
    path = tmp_path / "sparse-observation.jsonl"
    with path.open("wb") as handle:
        handle.seek(4096)
        handle.write(b"x")

    with pytest.raises(ContractError, match="size policy"):
        ObservationJournal(path, max_bytes=1024).verify()


def test_wal_completion_binds_exact_intent_evidence(tmp_path: Path) -> None:
    journal = WriteAheadJournal(tmp_path / "wal.jsonl", subject_digest=DIGEST)
    intent = {"operation": "write-A", "parameters": {"path": "candidate"}}
    journal.append(
        event_key="write",
        boundary="INTENT",
        phase="runtime",
        action="execute",
        evidence=intent,
    )
    completion = journal.append(
        event_key="write",
        boundary="COMPLETION",
        phase="runtime",
        action="execute",
        evidence={"outcome": "committed"},
    )
    journal.close()
    assert completion["intent_evidence_sha256"] == canonical_digest(intent)
    assert verify_journal(tmp_path / "wal.jsonl")["status"] == "PASS"


def test_wal_verifier_rejects_missing_intent_evidence_reference(
    tmp_path: Path,
) -> None:
    path = tmp_path / "wal.jsonl"
    journal = WriteAheadJournal(path, subject_digest=DIGEST)
    journal.append(
        event_key="write",
        boundary="INTENT",
        phase="runtime",
        action="execute",
        evidence={"operation": "write-A"},
    )
    journal.append(
        event_key="write",
        boundary="COMPLETION",
        phase="runtime",
        action="execute",
        evidence={"operation": "write-A", "outcome": "done"},
    )
    journal.close()
    records = [json.loads(line) for line in path.read_text().splitlines()]
    records[-1].pop("intent_evidence_sha256")
    records[-1]["record_digest"] = canonical_digest(
        {key: value for key, value in records[-1].items() if key != "record_digest"}
    )
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
    result = verify_journal(path)
    assert result["status"] == "BLOCKED_JOURNAL"
    assert "intent_evidence_reference:2" in result["failures"]


def test_wal_verifier_rejects_substituted_intent_evidence(tmp_path: Path) -> None:
    path = tmp_path / "wal.jsonl"
    journal = WriteAheadJournal(path, subject_digest=DIGEST)
    journal.append(
        event_key="write",
        boundary="INTENT",
        phase="runtime",
        action="execute",
        evidence={"operation": "write-A"},
    )
    journal.append(
        event_key="write",
        boundary="COMPLETION",
        phase="runtime",
        action="execute",
        evidence={"outcome": "committed"},
    )
    journal.close()

    records = [json.loads(line) for line in path.read_text().splitlines()]
    records[0]["evidence"] = {"operation": "write-B"}
    intent_material = {
        key: records[0][key]
        for key in (
            "schema_version",
            "source_run_id",
            "event_key",
            "phase",
            "action",
            "subject_digest",
            "evidence",
        )
    }
    records[0]["intent_digest"] = canonical_digest(intent_material)
    records[0]["record_digest"] = canonical_digest(
        {key: value for key, value in records[0].items() if key != "record_digest"}
    )
    records[1]["previous_digest"] = records[0]["record_digest"]
    records[1]["intent_digest"] = records[0]["intent_digest"]
    records[1]["record_digest"] = canonical_digest(
        {key: value for key, value in records[1].items() if key != "record_digest"}
    )
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )

    result = verify_journal(path)
    assert result["status"] == "BLOCKED_JOURNAL"
    assert "intent_evidence_reference:2" in result["failures"]


@pytest.mark.skipif(os.name != "nt", reason="Windows directory flush")
def test_windows_directory_fsync_uses_flush_and_propagates_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(
        strict_module,
        "_flush_windows_directory",
        lambda path: calls.append(path),
    )
    strict_module.fsync_directory(tmp_path)
    assert calls == [tmp_path]

    def fail(_path: Path) -> None:
        raise OSError("flush unsupported")

    monkeypatch.setattr(strict_module, "_flush_windows_directory", fail)
    with pytest.raises(OSError, match="flush unsupported"):
        strict_module.fsync_directory(tmp_path)


def test_repair_rejects_candidate_root_ancestor_alias(tmp_path: Path) -> None:
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo", encoding="utf-8"
    )
    subject = build_subject(source, "SKILL")
    findings = [
        {
            "risk_id": "newline",
            "invariant_id": "TEXT-FINAL-NEWLINE-001",
            "affected_refs": ["SKILL.md"],
        }
    ]
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    _directory_alias(real, alias)
    try:
        with pytest.raises(RepairBlocked, match="link|reparse"):
            apply_batch(subject, plan_batch(findings), alias / "candidate")
        assert not (real / "candidate").exists()
    finally:
        _remove_alias(alias)


def test_detector_deadlines_start_after_all_workers_are_scheduled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [100.0]
    poll_waits: list[float] = []

    class FakeSend:
        def close(self):
            return None

    class FakeReceive:
        def __init__(self, detector_id: str):
            self.detector_id = detector_id

        def poll(self, remaining):
            poll_waits.append(remaining)
            return True

        def recv(self):
            return DetectorResult(
                self.detector_id,
                "PASS",
                (),
                detector_version="1.0.0",
                taxonomy_category_id="FUNCTIONAL_FAULT",
                evidence_plane="STATIC",
            )

        def close(self):
            return None

    class FakeProcess:
        _counter = 0

        def __init__(self):
            self.index = FakeProcess._counter
            FakeProcess._counter += 1

        def start(self):
            clock[0] += 6.0

        def is_alive(self):
            return False

        def join(self, _timeout=None):
            return None

        def terminate(self):
            return None

        def kill(self):
            return None

        @property
        def exitcode(self):
            return 0

    class FakeContext:
        def Pipe(self, duplex=False):
            detector_id = f"detector-{len(poll_waits)}"
            return FakeReceive(detector_id), FakeSend()

        def Process(self, **_kwargs):
            return FakeProcess()

    monkeypatch.setattr(
        "full_inspection_repair.detectors.multiprocessing.get_context",
        lambda _method: FakeContext(),
    )
    monkeypatch.setattr(
        "full_inspection_repair.detectors.time.monotonic",
        lambda: clock[0],
    )
    result = run_detectors(
        object(),
        (
            ("slow-start", "LATENT_DEFECT", "RUNTIME", lambda _: ()),
            ("fast", "FUNCTIONAL_FAULT", "STATIC", lambda _: ()),
        ),
        timeout_seconds=5.0,
    )
    assert [item.status for item in result] == ["PASS", "PASS"]
    assert poll_waits == [5.0, 5.0]


def test_windows_audit_capability_is_structured(tmp_path: Path) -> None:
    from full_inspection_repair import windows_audit

    capability = windows_audit.audit_capability(tmp_path)
    assert capability["schema_version"] == 1
    assert capability["status"] in {"AVAILABLE", "UNAVAILABLE"}
    assert capability["capability_digest"]
    if capability["status"] == "AVAILABLE":
        for field in (
            "volume",
            "journal_id",
            "first_usn",
            "next_usn",
            "lowest_valid_usn",
            "maximum_usn",
        ):
            assert field in capability


@pytest.mark.skipif(os.name != "nt", reason="Windows USN journal")
def test_windows_audit_start_finish_returns_bound_events(tmp_path: Path) -> None:
    from full_inspection_repair import windows_audit

    capability = windows_audit.audit_capability(tmp_path)
    if capability["status"] != "AVAILABLE":
        pytest.skip(f"USN journal unavailable: {capability.get('reason')}")
    start = windows_audit.start_filesystem_audit(tmp_path)
    probe = tmp_path / "audit-probe.txt"
    probe.write_text("probe\n", encoding="utf-8")
    strict_module.fsync_directory(tmp_path)
    finish = windows_audit.finish_filesystem_audit(start)
    assert finish["status"] == "COMPLETE"
    assert finish["journal_id"] == start["journal_id"]
    assert finish["end_usn"] >= start["start_usn"]
    assert finish["events_digest"]
    assert isinstance(finish["events"], list)


def test_windows_audit_unavailable_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from full_inspection_repair import windows_audit

    def unavailable(_path):
        raise windows_audit.WindowsAuditUnavailable("journal disabled")

    monkeypatch.setattr(windows_audit, "_query_journal", unavailable)
    capability = windows_audit.audit_capability(tmp_path)
    assert capability["status"] == "UNAVAILABLE"
    assert capability["reason"] == "journal disabled"
    with pytest.raises(windows_audit.WindowsAuditUnavailable, match="journal disabled"):
        windows_audit.start_filesystem_audit(tmp_path)


def test_windows_audit_finish_clips_events_to_start_end_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from full_inspection_repair import windows_audit

    start_material = {
        "schema_version": 1,
        "status": "STARTED",
        "started_at": "2026-11-11T00:00:00+00:00",
        "path": str(tmp_path),
        "volume": str(tmp_path.anchor),
        "journal_id": 7,
        "start_usn": 100,
    }
    start = {
        **start_material,
        "start_digest": canonical_digest(start_material),
    }
    journal = {
        "volume": str(tmp_path.anchor),
        "journal_id": 7,
        "lowest_valid_usn": 90,
        "next_usn": 110,
    }
    monkeypatch.setattr(windows_audit, "_query_journal", lambda _path: journal)
    monkeypatch.setattr(
        windows_audit,
        "_read_journal",
        lambda *_args, **_kwargs: [
            {"usn": 100, "file_name": "inside"},
            {"usn": 110, "file_name": "outside-end"},
        ],
    )

    result = windows_audit.finish_filesystem_audit(start)

    assert result["event_count"] == 1
    assert [event["file_name"] for event in result["events"]] == ["inside"]
    assert result["end_usn"] == 110
    assert result["events_digest"] == canonical_digest(result["events"])
