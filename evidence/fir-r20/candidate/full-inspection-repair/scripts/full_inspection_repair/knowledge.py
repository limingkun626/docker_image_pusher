from __future__ import annotations

import math
import re
from datetime import UTC, datetime

from .contracts import canonical_digest


class KnowledgeError(ValueError):
    """Raised when learned knowledge cannot be validated or activated."""


_ACTIVATION_FIELDS = frozenset(
    {"candidate_digest", "replay_evidence", "evidence_digest"}
)
_PACK_IDENTITY_FIELDS = frozenset(
    {
        "pack_digest",
        "source_evidence_digest",
        "replay_evidence",
        "candidate_digest",
        "review_receipt",
        "reviewed_by",
    }
)
_RECEIPT_KINDS = ("MUTATION", "HISTORICAL_REPLAY", "SHADOW_REPLAY")


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _timestamp(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise KnowledgeError(f"{label} is not an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise KnowledgeError(f"{label} must include a timezone")
    return parsed


def _candidate_snapshot(candidate: dict[str, object]) -> dict[str, object]:
    return {
        key: value for key, value in candidate.items() if key not in _ACTIVATION_FIELDS
    }


def pack_identity_digest(pack: dict[str, object]) -> str:
    return canonical_digest(
        {key: value for key, value in pack.items() if key not in _PACK_IDENTITY_FIELDS}
    )


def _validate_split(
    candidate: dict[str, object],
) -> tuple[set[str], set[str], set[str]]:
    splits: list[set[str]] = []
    for field in ("train_case_ids", "validation_case_ids", "held_out_case_ids"):
        value = candidate.get(field)
        if (
            not isinstance(value, list)
            or not value
            or any(not _nonempty_string(item) for item in value)
            or len(value) != len(set(value))
        ):
            raise KnowledgeError(f"{field} must be a non-empty unique list")
        splits.append(set(value))
    if any(
        left & right
        for index, left in enumerate(splits)
        for right in splits[index + 1 :]
    ):
        raise KnowledgeError("train, validation and held-out cases must be disjoint")
    return splits[0], splits[1], splits[2]


def _result_counters(results: object, label: str) -> dict[str, int]:
    if not isinstance(results, dict) or not results:
        raise KnowledgeError(f"{label} results are required")
    counters = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }
    for case_id, result in results.items():
        if not _nonempty_string(case_id) or not isinstance(result, dict):
            raise KnowledgeError(f"{label} contains an invalid case result")
        expected = result.get("expected")
        observed = result.get("observed")
        if expected not in {"DETECT", "CLEAN"}:
            raise KnowledgeError(f"{label} expected result is invalid")
        if observed not in {"DETECT", "CLEAN"}:
            raise KnowledgeError(
                f"{label} requested case is not resolved with a final result"
            )
        if expected == observed == "DETECT":
            counters["true_positives"] += 1
        elif expected == "CLEAN" and observed == "DETECT":
            counters["false_positives"] += 1
        elif expected == observed == "CLEAN":
            counters["true_negatives"] += 1
        else:
            counters["false_negatives"] += 1
    return counters


def _validate_redaction(receipt: dict[str, object], label: str) -> None:
    redaction = receipt.get("redaction")
    if (
        not isinstance(redaction, dict)
        or redaction.get("status") != "PASS"
        or redaction.get("secret_findings") != 0
        or not _integer(redaction.get("secret_findings"))
        or not _digest(redaction.get("policy_digest"))
    ):
        raise KnowledgeError(f"{label} redaction failed")


def _validate_receipt(
    kind: str,
    receipt: object,
    *,
    candidate_digest: str,
    corpus_digest: str,
    pack_identity: str | None = None,
    pack_id: str | None = None,
    pack_version: str | None = None,
) -> dict[str, int]:
    label = kind.lower().replace("_", " ")
    if not isinstance(receipt, dict):
        raise KnowledgeError(f"{label} receipt is required")
    if receipt.get("schema_version") != 1 or receipt.get("kind") != kind:
        raise KnowledgeError(f"{label} receipt schema is invalid")
    if not _nonempty_string(receipt.get("receipt_id")):
        raise KnowledgeError(f"{label} receipt_id is required")
    declared_digest = receipt.get("receipt_digest")
    material = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    if not _digest(declared_digest) or declared_digest != canonical_digest(material):
        raise KnowledgeError(f"{label} receipt digest mismatch")

    execution = receipt.get("execution")
    if not isinstance(execution, dict):
        raise KnowledgeError(f"{label} execution receipt is required")
    if not _nonempty_string(execution.get("runner_id")):
        raise KnowledgeError(f"{label} execution runner is required")
    command = execution.get("command")
    if (
        not isinstance(command, list)
        or not command
        or any(not _nonempty_string(part) for part in command)
    ):
        raise KnowledgeError(f"{label} execution command is required")
    if execution.get("exit_code") != 0 or not _integer(execution.get("exit_code")):
        raise KnowledgeError(f"{label} execution did not succeed")
    if execution.get("candidate_digest") != candidate_digest:
        raise KnowledgeError(f"{label} execution candidate binding mismatch")
    if execution.get("corpus_digest") != corpus_digest:
        raise KnowledgeError(f"{label} execution corpus binding mismatch")
    if not _digest(execution.get("environment_digest")):
        raise KnowledgeError(f"{label} execution environment is invalid")
    started_at = _timestamp(execution.get("started_at"), f"{label} started_at")
    finished_at = _timestamp(execution.get("finished_at"), f"{label} finished_at")
    if finished_at < started_at:
        raise KnowledgeError(f"{label} execution time range is invalid")

    if pack_identity is not None:
        if execution.get("pack_identity_digest") != pack_identity:
            raise KnowledgeError(f"{label} pack identity is stale")
        if (
            pack_id is not None
            and pack_id != ""
            and execution.get("pack_id") != pack_id
        ):
            raise KnowledgeError(f"{label} receipt pack_id mismatch")
        if (
            pack_version is not None
            and pack_version != ""
            and execution.get("pack_version") != pack_version
        ):
            raise KnowledgeError(f"{label} receipt pack_version mismatch")

    requested = receipt.get("requested_case_ids")
    if (
        not isinstance(requested, list)
        or not requested
        or any(not _nonempty_string(item) for item in requested)
        or len(requested) != len(set(requested))
    ):
        raise KnowledgeError(f"{label} requested cases must be a non-empty unique list")
    requested_set = set(requested)
    baseline_results = receipt.get("baseline_results")
    candidate_results = receipt.get("candidate_results")
    if not isinstance(baseline_results, dict) or set(baseline_results) != requested_set:
        raise KnowledgeError(f"{label} baseline result set is incomplete")
    if (
        not isinstance(candidate_results, dict)
        or set(candidate_results) != requested_set
    ):
        raise KnowledgeError(f"{label} candidate result set is incomplete")

    baseline_counters = _result_counters(baseline_results, f"{label} baseline")
    candidate_counters = _result_counters(candidate_results, f"{label} candidate")
    if receipt.get("baseline_counters") != baseline_counters:
        raise KnowledgeError(f"{label} baseline counters are not computable")
    if receipt.get("candidate_counters") != candidate_counters:
        raise KnowledgeError(f"{label} candidate counters are not computable")
    if candidate_counters["false_positives"] or candidate_counters["false_negatives"]:
        raise KnowledgeError(f"{label} candidate results are not clean")

    _validate_redaction(receipt, label)

    if kind == "SHADOW_REPLAY":
        before = receipt.get("coverage_before")
        after = receipt.get("coverage_after")
        if (
            not isinstance(before, list)
            or not before
            or not isinstance(after, list)
            or not after
            or any(not _nonempty_string(item) for item in before + after)
        ):
            raise KnowledgeError(f"{label} coverage evidence is required")
        if not set(before).issubset(after):
            raise KnowledgeError(f"{label} coverage decreased")
    return candidate_counters


def _validate_candidate_core(
    candidate: dict[str, object],
    candidate_digest: str,
    shadow_counters: dict[str, int],
) -> None:
    if candidate.get("schema_version") != 1:
        raise KnowledgeError("learning candidate schema version is unsupported")
    if not _nonempty_string(candidate.get("candidate_id")):
        raise KnowledgeError("learning candidate_id is required")
    if candidate.get("candidate_type") not in {
        "DETECTOR",
        "GUARD",
        "REGRESSION",
        "NON_APPLICABILITY",
    }:
        raise KnowledgeError("learning candidate_type is invalid")
    if not isinstance(candidate.get("guard_only"), bool):
        raise KnowledgeError("learning candidate guard_only must be boolean")
    _validate_split(candidate)

    samples = sum(shadow_counters.values())
    if not _integer(candidate.get("samples")) or candidate.get("samples") != samples:
        raise KnowledgeError("candidate samples are not computable")
    true_positives = shadow_counters["true_positives"]
    false_positives = shadow_counters["false_positives"]
    true_negatives = shadow_counters["true_negatives"]
    precision_denominator = true_positives + false_positives
    trigger_denominator = false_positives + true_negatives
    if not precision_denominator or not trigger_denominator:
        raise KnowledgeError("candidate classification counters are incomplete")
    precision = true_positives / precision_denominator
    false_trigger_rate = false_positives / trigger_denominator
    if (
        not isinstance(candidate.get("precision"), (int, float))
        or isinstance(candidate.get("precision"), bool)
        or not math.isclose(float(candidate["precision"]), precision, abs_tol=1e-12)
    ):
        raise KnowledgeError("candidate precision is not computable")
    if (
        not isinstance(candidate.get("false_trigger_rate"), (int, float))
        or isinstance(candidate.get("false_trigger_rate"), bool)
        or not math.isclose(
            float(candidate["false_trigger_rate"]),
            false_trigger_rate,
            abs_tol=1e-12,
        )
    ):
        raise KnowledgeError("candidate false-trigger rate is not computable")
    if not bool(candidate.get("guard_only")) and samples < 20:
        raise KnowledgeError("minimum samples not met")
    if precision < 0.90:
        raise KnowledgeError("precision below threshold")
    if false_trigger_rate > 0.10:
        raise KnowledgeError("false-trigger rate above threshold")
    if candidate_digest != canonical_digest(candidate):
        raise KnowledgeError("learning candidate digest mismatch")


def _validate_replay_evidence(
    evidence: object,
    *,
    pack_identity: str | None = None,
    pack_id: str | None = None,
    pack_version: str | None = None,
) -> dict[str, object]:
    if not isinstance(evidence, dict) or evidence.get("schema_version") != 1:
        raise KnowledgeError("executed replay evidence is required")
    corpus_digest = evidence.get("corpus_digest")
    if not _digest(corpus_digest):
        raise KnowledgeError("replay corpus digest is invalid")
    snapshot = evidence.get("candidate")
    if not isinstance(snapshot, dict):
        raise KnowledgeError("replay candidate snapshot is required")
    candidate_digest = canonical_digest(snapshot)
    receipts = evidence.get("receipts")
    if not isinstance(receipts, dict) or set(receipts) != set(_RECEIPT_KINDS):
        raise KnowledgeError(
            "mutation, historical and shadow replay receipts are required"
        )
    receipt_ids: list[str] = []
    shadow_counters: dict[str, int] | None = None
    for kind in _RECEIPT_KINDS:
        receipt = receipts[kind]
        counters = _validate_receipt(
            kind,
            receipt,
            candidate_digest=candidate_digest,
            corpus_digest=str(corpus_digest),
            pack_identity=pack_identity,
            pack_id=pack_id,
            pack_version=pack_version,
        )
        if kind == "SHADOW_REPLAY":
            shadow_counters = counters
        receipt_ids.append(str(receipt["receipt_id"]))
    if len(receipt_ids) != len(set(receipt_ids)):
        raise KnowledgeError("replay receipt IDs must be unique")
    assert shadow_counters is not None
    _validate_candidate_core(snapshot, candidate_digest, shadow_counters)
    return {"candidate": snapshot, "candidate_digest": candidate_digest}


def validate_candidate(candidate: dict[str, object]) -> None:
    evidence = candidate.get("replay_evidence")
    validated = _validate_replay_evidence(evidence)
    snapshot = _candidate_snapshot(candidate)
    if snapshot != validated["candidate"]:
        raise KnowledgeError("candidate content is not bound to replay evidence")
    if candidate.get("candidate_digest") != validated["candidate_digest"]:
        raise KnowledgeError("candidate digest is not bound to replay evidence")
    evidence_digest = candidate.get("evidence_digest")
    if not _digest(evidence_digest) or evidence_digest != canonical_digest(evidence):
        raise KnowledgeError("candidate evidence digest mismatch")


def pack_content_digest(pack: dict[str, object]) -> str:
    material = dict(pack)
    material.pop("pack_digest", None)
    return canonical_digest(material)


def _validate_review_receipt(pack: dict[str, object]) -> None:
    review = pack.get("review_receipt")
    if not isinstance(review, dict):
        raise KnowledgeError("external review receipt is required")
    declared_digest = review.get("review_digest")
    material = {key: value for key, value in review.items() if key != "review_digest"}
    if not _digest(declared_digest) or declared_digest != canonical_digest(material):
        raise KnowledgeError("review receipt digest mismatch")
    if review.get("status") != "APPROVED":
        raise KnowledgeError("review receipt is not approved")
    if review.get("reviewer") != pack.get("reviewed_by"):
        raise KnowledgeError("review receipt reviewer mismatch")
    if review.get("candidate_digest") != pack.get("candidate_digest"):
        raise KnowledgeError("review receipt candidate mismatch")
    if review.get("source_evidence_digest") != pack.get("source_evidence_digest"):
        raise KnowledgeError("review receipt evidence mismatch")
    _timestamp(review.get("reviewed_at"), "reviewed_at")


def _validate_activation(pack: dict[str, object]) -> None:
    if not _nonempty_string(pack.get("reviewed_by")):
        raise KnowledgeError("knowledge pack reviewer is required")
    evidence = pack.get("replay_evidence")
    pack_identity = pack_identity_digest(pack)
    validated = _validate_replay_evidence(
        evidence,
        pack_identity=pack_identity,
        pack_id=str(pack.get("pack_id")),
        pack_version=str(pack.get("pack_version")),
    )
    if pack.get("candidate_digest") != validated["candidate_digest"]:
        raise KnowledgeError("knowledge pack candidate digest mismatch")
    source_evidence_digest = pack.get("source_evidence_digest")
    if not _digest(
        source_evidence_digest
    ) or source_evidence_digest != canonical_digest(evidence):
        raise KnowledgeError("knowledge pack evidence digest mismatch")
    _validate_review_receipt(pack)


def validate_pack(pack: dict[str, object], *, require_activation: bool = False) -> None:
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
        _validate_activation(pack)
    expires_at = pack.get("expires_at")
    if expires_at is not None:
        expiry = _timestamp(expires_at, "knowledge pack expires_at")
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
    if not producer or not reviewer or producer == reviewer:
        raise KnowledgeError("independent reviewer is required")
    validate_pack(pack, require_activation=True)
    if pack.get("reviewed_by") != reviewer:
        raise KnowledgeError("knowledge pack reviewer identity mismatch")
    if pack.get("candidate_digest") != candidate.get("candidate_digest"):
        raise KnowledgeError("knowledge pack is bound to a different candidate")
    if pack.get("replay_evidence") != candidate.get("replay_evidence"):
        raise KnowledgeError("knowledge pack replay evidence mismatch")
    evidence_digest = candidate.get("evidence_digest")
    if not _digest(evidence_digest):
        raise KnowledgeError("candidate has no executed replay evidence digest")
    if pack.get("source_evidence_digest") != evidence_digest:
        raise KnowledgeError("knowledge pack evidence digest is not bound to candidate")
    review = pack.get("review_receipt")
    assert isinstance(review, dict)
    return {
        "schema_version": 1,
        "status": "ACTIVE",
        "pack_id": pack["pack_id"],
        "pack_version": pack["pack_version"],
        "pack_digest": pack["pack_digest"],
        "source_evidence_digest": evidence_digest,
        "candidate_id": candidate["candidate_id"],
        "candidate_digest": candidate["candidate_digest"],
        "producer": producer,
        "approved_by": reviewer,
        "review_digest": review["review_digest"],
    }
