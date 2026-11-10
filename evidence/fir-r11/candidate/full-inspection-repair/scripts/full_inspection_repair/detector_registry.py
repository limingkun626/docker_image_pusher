from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .contracts import canonical_digest
from .detectors import DEFAULT_DETECTORS
from .taxonomy import (
    CATEGORIES,
    EVIDENCE_PLANES,
    DetectorSpec,
    build_not_applicable_proof,
    build_taxonomy_coverage,
)

POLICY_PATH = Path(__file__).resolve().parents[2] / "policies" / "taxonomy-policy.json"
ALL_TARGET_KINDS = ("SKILL", "PLAN", "ARTICLE", "PROJECT", "OTHER")
SKILL_ONLY_DETECTORS = frozenset({"skill.frontmatter-name", "skill.entrypoint"})
CANONICAL_DETECTOR_BINDINGS = {
    "skill.frontmatter-name": ("INCONSISTENCY", "CONTRACT"),
    "text.placeholder": ("OMISSION", "SEMANTIC"),
    "text.final-newline": ("INCONSISTENCY", "STATIC"),
    "skill.entrypoint": ("OMISSION", "STATIC"),
    "text.empty": ("FUNCTIONAL_FAULT", "STATIC"),
    "file.oversized": ("RISK_EXPOSURE", "PERFORMANCE"),
    "text.latent-marker": ("LATENT_DEFECT", "SEMANTIC"),
    "security.dangerous-pattern": ("VULNERABILITY", "SECURITY"),
    "text.boundary": ("BOUNDARY", "STATIC"),
    "python.exception-swallow": ("EXCEPTION_PATH", "BEHAVIOR"),
}
DETECTOR_VERSION = "1.0.0"


def _policy() -> tuple[dict[str, object], str]:
    raw = POLICY_PATH.read_bytes()
    policy = json.loads(raw)
    if not isinstance(policy, dict):
        raise TypeError("taxonomy policy must be a JSON object")
    return policy, hashlib.sha256(raw).hexdigest()


def detector_specs(target_kind: str) -> tuple[DetectorSpec, ...]:
    actual = {
        detector_id: (category_id, evidence_plane)
        for detector_id, category_id, evidence_plane, _detector in DEFAULT_DETECTORS
    }
    missing = sorted(set(CANONICAL_DETECTOR_BINDINGS) - set(actual))
    if missing:
        raise ValueError(
            "canonical detector missing from executable registry: "
            + ", ".join(missing)
        )
    mismatched = sorted(
        detector_id
        for detector_id, binding in actual.items()
        if CANONICAL_DETECTOR_BINDINGS.get(detector_id) != binding
    )
    if mismatched:
        raise ValueError(
            "canonical detector binding changed: " + ", ".join(mismatched)
        )
    specs: list[DetectorSpec] = []
    for detector_id, category_id, evidence_plane, _detector in DEFAULT_DETECTORS:
        if detector_id in SKILL_ONLY_DETECTORS and target_kind != "SKILL":
            continue
        specs.append(
            DetectorSpec(
                detector_id=detector_id,
                detector_version=DETECTOR_VERSION,
                target_kinds=(target_kind,),
                category_id=category_id,
                evidence_plane=evidence_plane,
                oracle_id=f"oracle.{detector_id}",
            )
        )
    return tuple(specs)


def default_taxonomy_coverage(target_kind: str) -> dict[str, object]:
    kind = target_kind.upper()
    if kind not in ALL_TARGET_KINDS:
        raise ValueError(f"unsupported target kind: {target_kind}")
    policy, policy_digest = _policy()
    if (
        policy.get("schema_version") != 1
        or not str(policy.get("policy_id", "")).strip()
        or not str(policy.get("policy_version", "")).strip()
        or not isinstance(policy.get("not_applicable_rule"), dict)
    ):
        raise ValueError("taxonomy policy metadata is incomplete")
    canonical_planes = policy.get("canonical_planes")
    if not isinstance(canonical_planes, dict):
        raise TypeError("taxonomy policy canonical_planes must be an object")
    if set(canonical_planes) != set(CATEGORIES):
        raise ValueError(
            "taxonomy policy canonical_planes must declare every category exactly once"
        )
    unknown_categories = set(canonical_planes) - set(CATEGORIES)
    if unknown_categories:
        raise ValueError(
            "taxonomy policy has unknown categories: "
            + ", ".join(sorted(unknown_categories))
        )
    for category, planes in canonical_planes.items():
        if not isinstance(planes, list) or any(
            plane not in EVIDENCE_PLANES for plane in planes
        ):
            raise ValueError(
                f"taxonomy policy has invalid canonical planes for {category}"
            )
    specs = detector_specs(kind)
    bound_cells = {
        (item.category_id, item.evidence_plane) for item in specs
    }
    proofs: dict[tuple[str, str, str], str] = {}
    for category in CATEGORIES:
        canonical = list(canonical_planes.get(category, []))
        for plane in EVIDENCE_PLANES:
            if (category, plane) in bound_cells:
                continue
            if category == "OTHER_DECLARED":
                reason = (
                    "No unclassified defect class is declared in the frozen "
                    "detector registry."
                )
            else:
                reason = (
                    f"The {category} category has no detector binding in the "
                    f"noncanonical {plane} plane; canonical planes are "
                    f"{','.join(canonical)}."
                )
            proofs[(kind, category, plane)] = build_not_applicable_proof(
                policy_id=str(policy.get("policy_id", "")),
                policy_version=str(policy.get("policy_version", "")),
                policy_digest=policy_digest,
                target_kind=kind,
                category_id=category,
                evidence_plane=plane,
                reason=reason,
                evidence_refs=[
                    "policy:taxonomy-policy.json:canonical_planes",
                    f"detector-registry:{category}:{','.join(canonical) or 'none'}",
                ],
            )
    coverage = build_taxonomy_coverage(
        (kind,),
        specs,
        taxonomy_version="1.1.0",
        not_applicable_proofs=proofs,
    )
    coverage["coverage_digest"] = canonical_digest(
        {key: value for key, value in coverage.items() if key != "coverage_digest"}
    )
    return coverage
