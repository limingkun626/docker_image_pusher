from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .contracts import ContractError, canonical_digest, validate_contract
from .strict import (
    StrictJSONError,
    fsync_directory,
    fsync_fd,
    strict_loads,
    write_all,
)

RESERVED_APPEND_FIELDS = frozenset(
    {
        "schema_version",
        "observation_id",
        "journal_sequence",
        "previous_record_digest",
        "record_digest",
    }
)
PROVENANCE_FIELDS = ("source_run_id", "redaction_policy_digest")


def _validate_observation(record: dict[str, Any]) -> None:
    try:
        validate_contract("issue-observation", record)
    except KeyError as exc:
        if exc.args != ("$id",):
            raise
        # shortcut: older schemas omit $id, remove when every contract has one
        from jsonschema import Draft202012Validator, FormatChecker

        schema_path = (
            Path(__file__).resolve().parents[2]
            / "contracts"
            / "issue-observation.schema.json"
        )
        schema = strict_loads(schema_path.read_bytes())
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).validate(record)


class ObservationJournal:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _records(self, *, require_nonempty: bool) -> list[dict[str, Any]]:
        if not self.path.exists():
            if require_nonempty:
                raise ContractError(f"observation journal missing: {self.path}")
            return []
        raw = self.path.read_bytes()
        if not raw:
            if require_nonempty:
                raise ContractError(f"observation journal is empty: {self.path}")
            return []
        if not raw.endswith(b"\n"):
            raise ContractError("observation journal is truncated")
        records: list[dict[str, Any]] = []
        lines = raw.split(b"\n")
        for line_number, line in enumerate(lines[:-1], start=1):
            if not line:
                raise ContractError(f"blank observation line at {line_number}")
            try:
                records.append(strict_loads(line))
            except StrictJSONError as exc:
                raise ContractError(
                    f"invalid observation JSON at line {line_number}: {exc}"
                ) from exc
        return records

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        reserved = RESERVED_APPEND_FIELDS.intersection(payload)
        if reserved:
            raise ContractError(
                "observation payload contains reserved fields: "
                + ", ".join(sorted(reserved))
            )
        records = self._records(require_nonempty=False)
        for record in records:
            for field in PROVENANCE_FIELDS:
                if record.get(field) != payload.get(field):
                    raise ContractError(
                        f"observation journal {field} provenance mismatch"
                    )
        previous = records[-1] if records else None
        if previous is None:
            sequence = 1
            previous_digest = None
        elif (
            isinstance(previous.get("journal_sequence"), int)
            and isinstance(previous.get("record_digest"), str)
        ):
            sequence = previous["journal_sequence"] + 1
            previous_digest = previous["record_digest"]
        else:
            raise ContractError("existing observation journal record is malformed")
        record = {
            "schema_version": 2,
            **payload,
            "journal_sequence": sequence,
            "previous_record_digest": previous_digest,
        }
        record["observation_id"] = f"observation:{sequence}:{canonical_digest(record)[:16]}"
        record_digest = canonical_digest(record)
        record["record_digest"] = record_digest
        _validate_observation(record)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()
        flags = (
            os.O_CREAT
            | os.O_APPEND
            | os.O_WRONLY
            | getattr(os, "O_BINARY", 0)
        )
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise ContractError(f"observation append open failed: {exc}") from exc
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
            write_all(fd, data)
            fsync_fd(fd)
            if not existed:
                fsync_directory(self.path.parent)
        except OSError as exc:
            raise ContractError(f"observation append failed: {exc}") from exc
        finally:
            os.close(fd)
        return record

    def checkpoint(self) -> dict[str, Any]:
        records = self._records(require_nonempty=True)
        material = {
            "schema_version": 2,
            "record_count": len(records),
            "head_digest": records[-1]["record_digest"],
            "source_run_id": records[0]["source_run_id"],
            "redaction_policy_digest": records[0]["redaction_policy_digest"],
        }
        material["checkpoint_digest"] = canonical_digest(material)
        return material

    def empty_checkpoint(
        self,
        *,
        source_run_id: str,
        redaction_policy_digest: str,
        create: bool,
    ) -> dict[str, Any]:
        if not source_run_id or not redaction_policy_digest:
            raise ContractError("empty observation checkpoint requires provenance")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if create and not self.path.exists():
            fd = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
                0o600,
            )
            try:
                fsync_fd(fd)
                fsync_directory(self.path.parent)
            finally:
                os.close(fd)
        if not self.path.exists() or self.path.stat().st_size:
            raise ContractError("empty observation checkpoint requires an empty file")
        material = {
            "schema_version": 2,
            "record_count": 0,
            "head_digest": None,
            "source_run_id": source_run_id,
            "redaction_policy_digest": redaction_policy_digest,
        }
        material["checkpoint_digest"] = canonical_digest(material)
        return material

    def verify(self, *, checkpoint: Mapping[str, Any] | None = None) -> int:
        result = verify_observation_journal(self.path, checkpoint=checkpoint)
        if result["status"] != "PASS":
            raise ContractError(
                "hash chain blocked: " + ", ".join(result["failures"])
            )
        return int(result["record_count"])


def verify_observation_journal(
    path: str | Path,
    *,
    checkpoint: Mapping[str, Any] | None = None,
) -> dict[str, object]:
    journal = ObservationJournal(path)
    failures: list[str] = []
    try:
        records = journal._records(require_nonempty=False)
    except ContractError as exc:
        return {
            "status": "BLOCKED_EVIDENCE",
            "record_count": 0,
            "head_digest": None,
            "failures": [str(exc)],
        }
    if not journal.path.exists():
        return {
            "status": "BLOCKED_EVIDENCE",
            "record_count": 0,
            "head_digest": None,
            "failures": [f"observation journal missing: {journal.path}"],
        }
    if not records:
        if checkpoint is None:
            return {
                "status": "BLOCKED_EVIDENCE",
                "record_count": 0,
                "head_digest": None,
                "failures": [f"observation journal is empty: {journal.path}"],
            }
        material = dict(checkpoint)
        declared_checkpoint = material.pop("checkpoint_digest", None)
        if canonical_digest(material) != declared_checkpoint:
            failures.append("checkpoint_digest")
        if (
            checkpoint.get("schema_version") != 2
            or checkpoint.get("record_count") != 0
            or checkpoint.get("head_digest") is not None
            or not checkpoint.get("source_run_id")
            or not checkpoint.get("redaction_policy_digest")
        ):
            failures.append("checkpoint:empty")
        return {
            "status": "PASS" if not failures else "BLOCKED_EVIDENCE",
            "record_count": 0,
            "head_digest": None,
            "failures": failures,
        }

    previous_digest = None
    base = records[0]
    for expected_sequence, record in enumerate(records, start=1):
        try:
            _validate_observation(record)
        except (ContractError, ValueError) as exc:
            failures.append(f"schema:{expected_sequence}:{exc}")
            continue
        if record["journal_sequence"] != expected_sequence:
            failures.append(f"sequence:{expected_sequence}")
        if record["previous_record_digest"] != previous_digest:
            failures.append(f"chain:{expected_sequence}")
        material = dict(record)
        declared = material.pop("record_digest")
        if canonical_digest(material) != declared:
            failures.append(f"digest:{expected_sequence}")
        previous_digest = declared
        identity_material = dict(record)
        identity_material.pop("observation_id", None)
        identity_material.pop("record_digest", None)
        expected_observation = (
            f"observation:{expected_sequence}:{canonical_digest(identity_material)[:16]}"
        )
        if record["observation_id"] != expected_observation:
            failures.append(f"observation_id:{expected_sequence}")
        for field in PROVENANCE_FIELDS:
            if record.get(field) != base.get(field):
                failures.append(f"{field}:{expected_sequence}")

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
        if previous_digest != checkpoint.get("head_digest"):
            failures.append("high_water:head_digest")
        for field in PROVENANCE_FIELDS:
            if base.get(field) != checkpoint.get(field):
                failures.append(f"checkpoint:{field}")
    return {
        "status": "PASS" if not failures else "BLOCKED_EVIDENCE",
        "record_count": len(records),
        "head_digest": previous_digest,
        "failures": failures,
    }
