from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import (
    ContractError,
    canonical_digest,
    canonical_json,
    validate_contract,
)

CATEGORIES = (
    "FUNCTIONAL_FAULT",
    "RISK_EXPOSURE",
    "LATENT_DEFECT",
    "VULNERABILITY",
    "OMISSION",
    "INCONSISTENCY",
    "BOUNDARY",
    "EXCEPTION_PATH",
    "OTHER_DECLARED",
)
EVIDENCE_PLANES = (
    "STATIC",
    "CONTRACT",
    "SEMANTIC",
    "BEHAVIOR",
    "RUNTIME",
    "SECURITY",
    "PERFORMANCE",
    "LIFECYCLE",
)


@dataclass(frozen=True)
class DetectorSpec:
    detector_id: str
    detector_version: str
    target_kinds: tuple[str, ...]
    category_id: str
    evidence_plane: str
    oracle_id: str


PROOF_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "policy_id",
        "policy_version",
        "policy_digest",
        "target_kind",
        "category_id",
        "evidence_plane",
        "reason",
        "evidence_refs",
        "evidence_digest",
    }
)
DIGEST_PATTERN = re.compile(r"^[a-f0-9]{64}$")
SYNTHETIC_ID_PREFIXES = ("detector.cell.", "oracle.cell.")
POLICY_PATH = Path(__file__).resolve().parents[2] / "policies" / "taxonomy-policy.json"
POLICY_EVIDENCE_REF = "policy:taxonomy-policy.json:canonical_planes"


def build_not_applicable_proof(
    *,
    policy_id: str,
    policy_version: str,
    policy_digest: str,
    target_kind: str,
    category_id: str,
    evidence_plane: str,
    reason: str,
    evidence_refs: list[str],
) -> str:
    proof: dict[str, object] = {
        "schema_version": 1,
        "kind": "NOT_APPLICABLE",
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "target_kind": target_kind,
        "category_id": category_id,
        "evidence_plane": evidence_plane,
        "reason": reason,
        "evidence_refs": evidence_refs,
    }
    proof["evidence_digest"] = canonical_digest(proof)
    return canonical_json(proof)


def _proof_payload(value: object) -> dict[str, Any]:
    if not isinstance(value, str):
        raise ContractError("not-applicable proof must be canonical JSON")
    try:
        proof = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"not-applicable proof is invalid JSON: {exc}") from exc
    if not isinstance(proof, dict) or set(proof) != PROOF_FIELDS:
        raise ContractError("not-applicable proof has an invalid structure")
    return proof


def _policy_binding() -> tuple[str, str, str]:
    try:
        raw = POLICY_PATH.read_bytes()
        policy = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise ContractError(f"cannot load taxonomy policy: {exc}") from exc
    if not isinstance(policy, dict):
        raise ContractError("taxonomy policy must be a JSON object")
    return (
        str(policy.get("policy_id", "")),
        str(policy.get("policy_version", "")),
        hashlib.sha256(raw).hexdigest(),
    )


def _canonical_planes() -> dict[str, list[str]]:
    try:
        policy = json.loads(POLICY_PATH.read_bytes())
    except (OSError, ValueError) as exc:
        raise ContractError(f"cannot load taxonomy policy: {exc}") from exc
    planes = policy.get("canonical_planes") if isinstance(policy, dict) else None
    if not isinstance(planes, dict):
        raise ContractError("taxonomy policy canonical planes are missing")
    return {
        str(category): [str(plane) for plane in category_planes]
        for category, category_planes in planes.items()
        if isinstance(category_planes, list)
    }


def validate_not_applicable_proof(
    value: object,
    *,
    target_kind: str,
    category_id: str,
    evidence_plane: str,
) -> dict[str, Any]:
    proof = _proof_payload(value)
    if (
        proof["schema_version"] != 1
        or proof["kind"] != "NOT_APPLICABLE"
        or proof["target_kind"] != target_kind
        or proof["category_id"] != category_id
        or proof["evidence_plane"] != evidence_plane
    ):
        raise ContractError("not-applicable proof is bound to the wrong cell")
    for field in ("policy_id", "policy_version", "reason"):
        if not isinstance(proof[field], str) or not proof[field].strip():
            raise ContractError(
                f"not-applicable proof lacks non-empty {field}"
            )
    for field in ("policy_digest", "evidence_digest"):
        if not isinstance(proof[field], str) or not DIGEST_PATTERN.fullmatch(
            proof[field]
        ):
            raise ContractError(f"not-applicable proof has invalid {field}")
    refs = proof["evidence_refs"]
    if (
        not isinstance(refs, list)
        or not refs
        or any(not isinstance(ref, str) or not ref for ref in refs)
    ):
        raise ContractError(
            "not-applicable proof requires non-empty evidence_refs"
        )
    canonical_planes = _canonical_planes()
    for ref in refs:
        if ref == POLICY_EVIDENCE_REF:
            continue
        prefix = "detector-registry:"
        if ref.startswith(prefix):
            parts = ref.removeprefix(prefix).split(":", 1)
            expected_planes = ",".join(canonical_planes.get(parts[0], [])) or "none"
            if len(parts) == 2 and parts[1] == expected_planes:
                continue
        raise ContractError(f"not-applicable proof has dangling evidence: {ref}")
    digest_payload = {key: value for key, value in proof.items() if key != "evidence_digest"}
    if proof["evidence_digest"] != canonical_digest(digest_payload):
        raise ContractError("not-applicable proof evidence digest mismatch")
    return proof


def build_taxonomy_coverage(
    target_kinds: tuple[str, ...] | list[str],
    detectors: list[DetectorSpec] | tuple[DetectorSpec, ...],
    *,
    taxonomy_version: str = "1.0.0",
    not_applicable_proofs: Mapping[
        tuple[str, str, str], str | dict[str, object]
    ]
    | None = None,
) -> dict[str, object]:
    kinds = sorted(set(target_kinds))
    proofs = not_applicable_proofs or {}
    cells: list[dict[str, object]] = []
    for target_kind in kinds:
        for category in CATEGORIES:
            for plane in EVIDENCE_PLANES:
                matches = [
                    detector
                    for detector in detectors
                    if target_kind in detector.target_kinds
                    and detector.category_id == category
                    and detector.evidence_plane == plane
                ]
                detector_ids = sorted({item.detector_id for item in matches})
                oracle_ids = sorted({item.oracle_id for item in matches})
                proof = proofs.get((target_kind, category, plane))
                if isinstance(proof, dict):
                    proof = canonical_json(proof)
                covered = bool(
                    (detector_ids and oracle_ids)
                    or (not detector_ids and not oracle_ids and proof)
                )
                cells.append(
                    {
                        "target_kind": target_kind,
                        "category_id": category,
                        "evidence_plane": plane,
                        "detector_ids": detector_ids,
                        "oracle_ids": oracle_ids,
                        "not_applicable_proof": proof,
                        "status": "COVERED" if covered else "UNCOVERED",
                    }
                )

    coverage: dict[str, object] = {
        "schema_version": 1,
        "taxonomy_id": "inspection-closure.defect-taxonomy",
        "taxonomy_version": taxonomy_version,
        "categories": list(CATEGORIES),
        "target_kinds": kinds,
        "evidence_planes": list(EVIDENCE_PLANES),
        "cells": cells,
    }
    coverage["coverage_digest"] = canonical_digest(coverage)
    return coverage


def assert_taxonomy_complete(
    coverage: dict[str, object], target_kinds: tuple[str, ...] | list[str]
) -> None:
    validate_contract("defect-taxonomy", coverage)
    declared_digest = coverage["coverage_digest"]
    recomputed_digest = canonical_digest(
        {key: value for key, value in coverage.items() if key != "coverage_digest"}
    )
    if declared_digest != recomputed_digest:
        raise ContractError("taxonomy coverage digest mismatch")
    expected = {
        (kind, category, plane)
        for kind in target_kinds
        for category in CATEGORIES
        for plane in EVIDENCE_PLANES
    }
    seen: set[tuple[str, str, str]] = set()
    gaps: list[str] = []
    for cell in coverage["cells"]:
        key = (
            cell["target_kind"],
            cell["category_id"],
            cell["evidence_plane"],
        )
        if key in seen:
            gaps.append(f"duplicate:{key[0]}/{key[1]}/{key[2]}")
            continue
        seen.add(key)
        if cell["status"] != "COVERED":
            gaps.append(f"uncovered:{key[0]}/{key[1]}/{key[2]}")
            continue
        detector_ids = cell["detector_ids"]
        oracle_ids = cell["oracle_ids"]
        proof = cell["not_applicable_proof"]
        has_binding = bool(detector_ids and oracle_ids)
        if has_binding and any(
            item.startswith(SYNTHETIC_ID_PREFIXES)
            for item in (*detector_ids, *oracle_ids)
        ):
            gaps.append(f"synthetic-binding:{key[0]}/{key[1]}/{key[2]}")
            continue
        if has_binding and proof is not None:
            gaps.append(f"ambiguous-proof:{key[0]}/{key[1]}/{key[2]}")
            continue
        if not has_binding and proof is None:
            gaps.append(f"missing-proof:{key[0]}/{key[1]}/{key[2]}")
            continue
        if proof is not None:
            try:
                parsed_proof = validate_not_applicable_proof(
                    proof,
                    target_kind=key[0],
                    category_id=key[1],
                    evidence_plane=key[2],
                )
                policy_id, policy_version, policy_digest = _policy_binding()
                if (
                    parsed_proof["policy_id"] != policy_id
                    or parsed_proof["policy_version"] != policy_version
                    or parsed_proof["policy_digest"] != policy_digest
                    or POLICY_EVIDENCE_REF not in parsed_proof["evidence_refs"]
                ):
                    raise ContractError(
                        "not-applicable proof is not bound to the active policy"
                    )
            except ContractError:
                gaps.append(f"invalid-proof:{key[0]}/{key[1]}/{key[2]}")
    for key in sorted(expected - seen):
        gaps.append(f"missing:{key[0]}/{key[1]}/{key[2]}")
    if gaps:
        raise ContractError("taxonomy coverage incomplete: " + ", ".join(gaps[:8]))
