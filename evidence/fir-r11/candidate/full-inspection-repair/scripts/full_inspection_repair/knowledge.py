from __future__ import annotations

import re
from datetime import UTC, datetime

from .contracts import canonical_digest


class KnowledgeError(ValueError):
    """Raised when learned knowledge cannot be validated or activated."""


def validate_candidate(candidate: dict[str, object]) -> None:
    guard_only = bool(candidate["guard_only"])
    if not guard_only and candidate["samples"] < 20:
        raise KnowledgeError("minimum samples not met")
    if candidate["precision"] < 0.90:
        raise KnowledgeError("precision below threshold")
    if candidate["false_trigger_rate"] > 0.10:
        raise KnowledgeError("false-trigger rate above threshold")
    if not candidate["held_out"]:
        raise KnowledgeError("held-out evidence is required")
    if not candidate["mutation_passed"]:
        raise KnowledgeError("mutation gate failed")
    if not candidate["historical_replay_passed"]:
        raise KnowledgeError("historical replay failed")


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def pack_content_digest(pack: dict[str, object]) -> str:
    material = dict(pack)
    material.pop("pack_digest", None)
    return canonical_digest(material)


def validate_pack(
    pack: dict[str, object], *, require_activation: bool = False
) -> None:
    if pack.get("schema_version") != 1:
        raise KnowledgeError("knowledge pack schema version is unsupported")
    for field in ("pack_id", "pack_version"):
        if not isinstance(pack.get(field), str) or not pack[field]:
            raise KnowledgeError(f"knowledge pack lacks {field}")
    entries = pack.get("entries")
    if not isinstance(entries, list):
        raise KnowledgeError("knowledge pack entries must be a list")
    entry_ids = [
        str(entry.get("knowledge_id", ""))
        for entry in entries
        if isinstance(entry, dict)
    ]
    if len(entry_ids) != len(entries) or not all(entry_ids):
        raise KnowledgeError("knowledge pack entry is missing knowledge_id")
    if len(entry_ids) != len(set(entry_ids)):
        raise KnowledgeError("knowledge pack contains duplicate knowledge_id")
    if not _digest(pack.get("pack_digest")):
        raise KnowledgeError("knowledge pack digest is invalid")
    if pack["pack_digest"] != pack_content_digest(pack):
        raise KnowledgeError("knowledge pack content does not match its digest")
    scope = pack.get("scope")
    if (
        not isinstance(scope, dict)
        or not isinstance(scope.get("target_kinds"), list)
        or not scope["target_kinds"]
        or any(not isinstance(item, str) or not item for item in scope["target_kinds"])
    ):
        raise KnowledgeError("knowledge pack scope is invalid")
    if require_activation:
        if not isinstance(pack.get("reviewed_by"), str) or not pack["reviewed_by"]:
            raise KnowledgeError("knowledge pack reviewer is required")
        if pack.get("shadow_replay_passed") is not True:
            raise KnowledgeError("whole-pack shadow replay is required")
        for field in ("source_evidence_digest", "shadow_replay_digest"):
            if not _digest(pack.get(field)):
                raise KnowledgeError(
                    f"knowledge pack lacks a valid {field}"
                )
    expires_at = pack.get("expires_at")
    if expires_at is not None:
        try:
            expiry = datetime.fromisoformat(str(expires_at))
        except ValueError as exc:
            raise KnowledgeError("knowledge pack expires_at is invalid") from exc
        if expiry <= datetime.now(UTC):
            raise KnowledgeError("knowledge pack is expired")


def default_knowledge_pack(
    *,
    detector_ids: list[str],
    artifact_sha256: str,
    target_kinds: list[str],
) -> dict[str, object]:
    pack: dict[str, object] = {
        "schema_version": 1,
        "pack_id": "default-v0",
        "pack_version": "1.0.0",
        "scope": {"target_kinds": sorted(target_kinds)},
        "entries": [
            {
                "knowledge_id": f"detector:{detector_id}",
                "detector_id": detector_id,
            }
            for detector_id in sorted(detector_ids)
        ],
        "artifact_sha256": artifact_sha256,
        "expires_at": None,
        "reviewed_by": None,
    }
    pack["pack_digest"] = pack_content_digest(pack)
    validate_pack(pack)
    return pack


def load_frozen_pack(
    *,
    run_pack_digest: str,
    requested_pack: dict[str, object],
    target_kinds: list[str],
    expected_detector_ids: list[str] | None = None,
) -> dict[str, object]:
    if not _digest(run_pack_digest):
        raise KnowledgeError("frozen pack digest is invalid")
    validate_pack(requested_pack, require_activation=True)
    if requested_pack["pack_digest"] != run_pack_digest:
        raise KnowledgeError("current run is bound to a different frozen pack")
    pack_kinds = set(requested_pack["scope"]["target_kinds"])
    if not set(target_kinds).issubset(pack_kinds):
        raise KnowledgeError("knowledge pack scope does not cover the frozen run")
    if expected_detector_ids is not None:
        actual = {
            str(entry.get("detector_id"))
            for entry in requested_pack["entries"]
            if isinstance(entry, dict) and entry.get("detector_id")
        }
        if actual != set(expected_detector_ids):
            raise KnowledgeError("knowledge pack detector set is not frozen")
    return dict(requested_pack)


def promote_pack(
    candidate: dict[str, object],
    *,
    pack: dict[str, object],
    producer: str,
    reviewer: str,
) -> dict[str, object]:
    validate_candidate(candidate)
    if producer == reviewer:
        raise KnowledgeError("independent reviewer is required")
    validate_pack(pack, require_activation=True)
    if pack.get("reviewed_by") != reviewer:
        raise KnowledgeError("knowledge pack reviewer identity mismatch")
    evidence_digest = candidate.get("evidence_pack_digest")
    if not _digest(evidence_digest):
        raise KnowledgeError("candidate has no evidence-backed pack digest")
    if pack.get("source_evidence_digest") != evidence_digest:
        raise KnowledgeError("knowledge pack evidence digest is not bound to candidate")
    if pack.get("shadow_replay_passed") is not True:
        raise KnowledgeError("whole-pack shadow replay is required")
    return {
        "schema_version": 1,
        "status": "ACTIVE",
        "pack_id": pack["pack_id"],
        "pack_version": pack["pack_version"],
        "pack_digest": pack["pack_digest"],
        "source_evidence_digest": evidence_digest,
        "candidate_id": candidate["candidate_id"],
        "producer": producer,
        "approved_by": reviewer,
    }
