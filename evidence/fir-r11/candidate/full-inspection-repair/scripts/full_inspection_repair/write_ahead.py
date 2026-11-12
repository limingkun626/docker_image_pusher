from __future__ import annotations

import json
import os
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .contracts import ContractError, canonical_digest
from .strict import (
    canonical_bytes,
    fsync_directory,
    fsync_fd,
    strict_loads,
    write_all,
)


def _intent_digest(record: Mapping[str, Any]) -> str:
    return canonical_digest(
        {
            "schema_version": 2,
            "source_run_id": record["source_run_id"],
            "event_key": record["event_key"],
            "phase": record["phase"],
            "action": record["action"],
            "subject_digest": record["subject_digest"],
            "evidence": record["evidence"],
        }
    )


def _shared_evidence_mismatch(intent: object, completion: object) -> str | None:
    if not isinstance(intent, dict) or not isinstance(completion, dict):
        return None
    for key, value in intent.items():
        if key in completion and completion[key] != value:
            return str(key)
    return None


class WriteAheadJournal:
    """Append-only intent/completion Journal for state-changing actions."""

    def __init__(
        self,
        path: str | Path,
        *,
        subject_digest: str,
        source_run_id: str | None = None,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        try:
            self._fd = os.open(self.path, flags, 0o600)
        except FileExistsError as exc:
            raise ContractError(f"journal already exists: {self.path}") from exc
        self.subject_digest = subject_digest
        self.source_run_id = source_run_id or f"run:journal:{uuid.uuid4().hex}"
        self.sequence = 0
        self.previous: str | None = None
        self._open_event: dict[str, Any] | None = None
        self._completed: set[str] = set()
        try:
            fsync_directory(self.path.parent)
        except OSError as exc:
            os.close(self._fd)
            self._fd = None
            raise ContractError(f"journal directory sync failed: {exc}") from exc

    def append(
        self,
        *,
        event_key: str,
        boundary: str,
        phase: str,
        action: str,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        if boundary not in {"INTENT", "COMPLETION"}:
            raise ContractError(f"invalid journal boundary: {boundary}")
        if not event_key or not phase or not action:
            raise ContractError("journal event identity is required")
        if boundary == "INTENT":
            if self._open_event is not None or event_key in self._completed:
                raise ContractError(f"invalid journal intent: {event_key}")
        elif (
            self._open_event is None
            or any(
                self._open_event[field] != value
                for field, value in (
                    ("event_key", event_key),
                    ("phase", phase),
                    ("action", action),
                    ("subject_digest", self.subject_digest),
                )
            )
        ):
            raise ContractError(f"journal completion does not match intent: {event_key}")
        if self._open_event is not None:
            mismatch = _shared_evidence_mismatch(
                self._open_event["evidence"], evidence
            )
            if mismatch is not None:
                raise ContractError(
                    "journal completion evidence conflicts with intent: " + mismatch
                )

        sequence = self.sequence + 1
        record = {
            "schema_version": 2,
            "sequence": sequence,
            "previous_digest": self.previous,
            "source_run_id": self.source_run_id,
            "event_key": event_key,
            "boundary": boundary,
            "phase": phase,
            "action": action,
            "subject_digest": self.subject_digest,
            "evidence": evidence,
        }
        if boundary == "INTENT":
            record["intent_digest"] = _intent_digest(record)
        else:
            record["intent_digest"] = self._open_event["intent_digest"]
        record["record_digest"] = canonical_digest(record)
        data = (
            json.dumps(
                record,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        try:
            write_all(self._fd, data)
            fsync_fd(self._fd)
        except OSError as exc:
            raise ContractError(f"write-ahead append failed: {exc}") from exc

        self.sequence = sequence
        self.previous = record["record_digest"]
        if boundary == "INTENT":
            self._open_event = record
        else:
            self._completed.add(event_key)
            self._open_event = None
        return record

    def checkpoint(self) -> dict[str, Any]:
        result = verify_journal(self.path)
        if result["status"] != "PASS":
            raise ContractError(
                "journal is not checkpointable: " + ", ".join(result["failures"])
            )
        if result["head_digest"] != self.previous:
            raise ContractError("journal in-memory head does not match disk")
        material = {
            "schema_version": 2,
            "record_count": self.sequence,
            "head_digest": self.previous,
            "subject_digest": self.subject_digest,
            "source_run_id": self.source_run_id,
        }
        material["checkpoint_digest"] = canonical_digest(material)
        return material

    def verify(
        self, *, checkpoint: Mapping[str, Any] | None = None
    ) -> dict[str, object]:
        return verify_journal(self.path, checkpoint=checkpoint)

    def close(self) -> None:
        if getattr(self, "_fd", None) is not None:
            os.close(self._fd)
            self._fd = None


def _load_records(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.exists():
        return [], ["resource_missing"]
    raw = path.read_bytes()
    if not raw:
        return [], ["empty_journal"]
    records = []
    failures = []
    if not raw.endswith(b"\n"):
        failures.append("truncated")
    lines = raw.split(b"\n")
    for number, line in enumerate(lines[:-1], start=1):
        if not line:
            failures.append(f"blank_line:{number}")
            continue
        try:
            value = strict_loads(line)
        except ValueError as exc:
            failures.append(f"invalid_json:{number}:{exc}")
            continue
        if not isinstance(value, dict):
            failures.append(f"record_type:{number}")
            continue
        records.append(value)
    return records, failures


def journal_checkpoint(path: str | Path) -> dict[str, Any]:
    result = verify_journal(path)
    if result["status"] != "PASS":
        raise ContractError(
            "journal is not checkpointable: " + ", ".join(result["failures"])
        )
    material = {
        "schema_version": 2,
        "record_count": result["record_count"],
        "head_digest": result["head_digest"],
        "subject_digest": result["subject_digest"],
        "source_run_id": result["source_run_id"],
    }
    material["checkpoint_digest"] = canonical_digest(material)
    return material


def write_journal_checkpoint(
    path: str | Path,
    checkpoint: Mapping[str, Any],
) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise ContractError(f"journal checkpoint already exists: {target}")
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(
        temporary,
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        write_all(fd, canonical_bytes(dict(checkpoint)) + b"\n")
        fsync_fd(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, target)
        fsync_directory(target.parent)
    except Exception as exc:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise ContractError(f"journal checkpoint write failed: {exc}") from exc
        raise


def load_journal_checkpoint(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if not source.exists():
        raise ContractError(f"journal checkpoint missing: {source}")
    value = strict_loads(source.read_bytes(), max_bytes=1024 * 1024)
    if not isinstance(value, dict):
        raise ContractError("journal checkpoint must be a JSON object")
    return value


def verify_journal(
    path: str | Path,
    *,
    checkpoint: Mapping[str, Any] | None = None,
) -> dict[str, object]:
    records, failures = _load_records(Path(path))
    previous = None
    open_record = None
    completed: set[str] = set()
    base_subject = records[0].get("subject_digest") if records else None
    base_run = records[0].get("source_run_id") if records else None
    if records and (not isinstance(base_run, str) or not base_run):
        failures.append("run:0")
    for sequence, record in enumerate(records, start=1):
        material = dict(record)
        declared = material.pop("record_digest", None)
        if record.get("schema_version") != 2:
            failures.append(f"schema:{sequence}")
        if record.get("sequence") != sequence:
            failures.append(f"sequence:{sequence}")
        if record.get("previous_digest") != previous:
            failures.append(f"chain:{sequence}")
        if record.get("subject_digest") != base_subject:
            failures.append(f"subject:{sequence}")
        if record.get("source_run_id") != base_run:
            failures.append(f"run:{sequence}")
        if not isinstance(declared, str) or canonical_digest(material) != declared:
            failures.append(f"digest:{sequence}")
        previous = declared
        event = record.get("event_key")
        if not isinstance(event, str) or not event:
            failures.append(f"event:{sequence}")
            continue
        boundary = record.get("boundary")
        if boundary == "INTENT":
            if open_record is not None or event in completed:
                failures.append(f"pair:{sequence}")
            declared_intent = record.get("intent_digest")
            try:
                expected_intent = _intent_digest(record)
            except (KeyError, TypeError, ValueError):
                expected_intent = None
            if (
                not isinstance(declared_intent, str)
                or declared_intent != expected_intent
            ):
                failures.append(f"intent_digest:{sequence}")
            open_record = record
        elif boundary == "COMPLETION":
            if open_record is None or any(
                open_record.get(field) != record.get(field)
                for field in ("event_key", "phase", "action", "subject_digest")
            ):
                failures.append(f"pair:{sequence}")
            else:
                if record.get("intent_digest") != open_record.get("intent_digest"):
                    failures.append(f"intent_reference:{sequence}")
                mismatch = _shared_evidence_mismatch(
                    open_record.get("evidence"), record.get("evidence")
                )
                if mismatch is not None:
                    failures.append(f"intent_evidence:{sequence}:{mismatch}")
                completed.add(event)
                open_record = None
        else:
            failures.append(f"boundary:{sequence}")
    if open_record is not None:
        failures.append("incomplete")

    subject_digest = base_subject
    if checkpoint is not None:
        material = dict(checkpoint)
        declared_checkpoint = material.pop("checkpoint_digest", None)
        if canonical_digest(material) != declared_checkpoint:
            failures.append("checkpoint_digest")
        if checkpoint.get("schema_version") != 2:
            failures.append("checkpoint:schema")
        expected_count = checkpoint.get("record_count")
        if isinstance(expected_count, int) and len(records) < expected_count:
            failures.append("high_water:record_count")
        elif len(records) != expected_count:
            failures.append("checkpoint:record_count")
        if previous != checkpoint.get("head_digest"):
            failures.append("high_water:head_digest")
        if subject_digest != checkpoint.get("subject_digest"):
            failures.append("checkpoint:subject_digest")
        if base_run != checkpoint.get("source_run_id"):
            failures.append("checkpoint:source_run_id")
    return {
        "status": "PASS" if not failures else "BLOCKED_JOURNAL",
        "record_count": len(records),
        "head_digest": previous,
        "subject_digest": subject_digest,
        "source_run_id": base_run,
        "failures": failures,
    }
