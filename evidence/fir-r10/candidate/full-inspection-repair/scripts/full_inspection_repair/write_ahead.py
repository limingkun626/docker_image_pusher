from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .contracts import ContractError, canonical_digest
from .strict import fsync_directory, fsync_fd, strict_loads, write_all


class WriteAheadJournal:
    """Append-only intent/completion Journal for state-changing actions."""

    def __init__(self, path: str | Path, *, subject_digest: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        try:
            self._fd = os.open(self.path, flags, 0o600)
        except FileExistsError as exc:
            raise ContractError(f"journal already exists: {self.path}") from exc
        self.subject_digest = subject_digest
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

        sequence = self.sequence + 1
        record = {
            "schema_version": 1,
            "sequence": sequence,
            "previous_digest": self.previous,
            "event_key": event_key,
            "boundary": boundary,
            "phase": phase,
            "action": action,
            "subject_digest": self.subject_digest,
            "evidence": evidence,
        }
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
            "schema_version": 1,
            "record_count": self.sequence,
            "head_digest": self.previous,
            "subject_digest": self.subject_digest,
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
        "schema_version": 1,
        "record_count": result["record_count"],
        "head_digest": result["head_digest"],
        "subject_digest": result["subject_digest"],
    }
    material["checkpoint_digest"] = canonical_digest(material)
    return material


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
    for sequence, record in enumerate(records, start=1):
        material = dict(record)
        declared = material.pop("record_digest", None)
        if record.get("schema_version") != 1:
            failures.append(f"schema:{sequence}")
        if record.get("sequence") != sequence:
            failures.append(f"sequence:{sequence}")
        if record.get("previous_digest") != previous:
            failures.append(f"chain:{sequence}")
        if record.get("subject_digest") != base_subject:
            failures.append(f"subject:{sequence}")
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
            open_record = record
        elif boundary == "COMPLETION":
            if open_record is None or any(
                open_record.get(field) != record.get(field)
                for field in ("event_key", "phase", "action", "subject_digest")
            ):
                failures.append(f"pair:{sequence}")
            else:
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
        if checkpoint.get("schema_version") != 1:
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
    return {
        "status": "PASS" if not failures else "BLOCKED_JOURNAL",
        "record_count": len(records),
        "head_digest": previous,
        "subject_digest": subject_digest,
        "failures": failures,
    }
