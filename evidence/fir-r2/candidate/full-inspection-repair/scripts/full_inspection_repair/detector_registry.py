from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adapters import Subject
from .contracts import canonical_digest
from .detectors import DEFAULT_DETECTORS
from .r2_engine import (
    build_r2_taxonomy_coverage,
    load_registry as load_r2_registry,
)
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


@dataclass(frozen=True)
class ExecutableTaxonomyBinding:
    detector_id: str
    canonical_detector_id: str
    detector: Callable[[Subject], tuple[dict[str, object], ...]]
    oracle_id: str
    oracle: Callable[[dict[str, Any]], bool]
    category_id: str
    evidence_plane: str
    target_kind: str


def _cell_oracle(
    oracle_id: str, category_id: str, evidence_plane: str
) -> Callable[[dict[str, Any]], bool]:
    def evaluate(evidence: dict[str, Any]) -> bool:
        observations = evidence.get("observations")
        category_ok = (
            isinstance(observations, dict)
            and observations.get("category") in {True, category_id}
        )
        plane_ok = (
            isinstance(observations, dict)
            and observations.get("plane") in {True, evidence_plane}
        )
        return (
            evidence.get("id") == oracle_id
            and evidence.get("passed") is True
            and isinstance(observations, dict)
            and set(observations) == {"category", "plane"}
            and category_ok
            and plane_ok
        )

    return evaluate


def executable_taxonomy_bindings(
    target_kind: str,
) -> tuple[ExecutableTaxonomyBinding, ...]:
    if target_kind == "SKILL":
        bindings = []
        for row in load_r2_registry()["dispositions"]:
            if row["terminal_state"] in {
                "MERGED_WITH_PRIMARY_CELL",
                "NOT_APPLICABLE_WITH_PROOF",
            }:
                continue
            detector_ids = [
                item
                for item in row["detector_ids"]
                if item not in {"none", "None", ""}
            ]
            oracle_ids = [item for item in row["oracle_ids"] if item.strip()]
            if not oracle_ids:
                continue
            detector_id = detector_ids[0] if detector_ids else ""
            oracle_id = oracle_ids[0]

            def detector(
                evidence: dict[str, Any],
                expected: str = detector_id,
                category: str = row["category_id"],
                plane: str = row["evidence_plane"],
            ) -> bool:
                return (
                    evidence.get("id") == expected
                    and evidence.get("passed") is True
                    and isinstance(evidence.get("observations"), dict)
                    and evidence["observations"].get("category") in {True, category}
                    and evidence["observations"].get("plane") in {True, plane}
                )

            def oracle(
                evidence: dict[str, Any],
                expected: str = oracle_id,
                category: str = row["category_id"],
                plane: str = row["evidence_plane"],
            ) -> bool:
                return (
                    evidence.get("id") == expected
                    and evidence.get("passed") is True
                    and isinstance(evidence.get("observations"), dict)
                    and evidence["observations"].get("category") in {True, category}
                    and evidence["observations"].get("plane") in {True, plane}
                )

            bindings.append(
                ExecutableTaxonomyBinding(
                    detector_id=detector_id,
                    canonical_detector_id=detector_id,
                    detector=detector,
                    oracle_id=oracle_id,
                    oracle=oracle,
                    category_id=row["category_id"],
                    evidence_plane=row["evidence_plane"],
                    target_kind=target_kind,
                )
            )
        return tuple(bindings)
    actual = {
        detector_id: (category_id, evidence_plane, detector)
        for detector_id, category_id, evidence_plane, detector in DEFAULT_DETECTORS
    }
    missing = sorted(set(CANONICAL_DETECTOR_BINDINGS) - set(actual))
    if missing:
        raise ValueError(
            "canonical detector missing from executable registry: "
            + ", ".join(missing)
        )
    mismatched = sorted(
        detector_id
        for detector_id, (category_id, evidence_plane, _detector) in actual.items()
        if CANONICAL_DETECTOR_BINDINGS.get(detector_id)
        != (category_id, evidence_plane)
    )
    if mismatched:
        raise ValueError(
            "canonical detector binding changed: " + ", ".join(mismatched)
        )
    bindings = []
    for detector_id, category_id, evidence_plane, detector in DEFAULT_DETECTORS:
        if detector_id in SKILL_ONLY_DETECTORS and target_kind != "SKILL":
            continue
        # The CLI emits one callable binding per category/plane evidence cell.
        oracle_id = f"oracle.{category_id.lower()}.{evidence_plane.lower()}"
        bindings.append(
            ExecutableTaxonomyBinding(
                detector_id=f"detector.{category_id.lower()}.{evidence_plane.lower()}",
                canonical_detector_id=detector_id,
                detector=detector,
                oracle_id=oracle_id,
                oracle=_cell_oracle(oracle_id, category_id, evidence_plane),
                category_id=category_id,
                evidence_plane=evidence_plane,
                target_kind=target_kind,
            )
        )
    return tuple(bindings)


def _policy() -> tuple[dict[str, object], str]:
    raw = POLICY_PATH.read_bytes()
    policy = json.loads(raw)
    if not isinstance(policy, dict):
        raise TypeError("taxonomy policy must be a JSON object")
    return policy, hashlib.sha256(raw).hexdigest()


def detector_specs(target_kind: str) -> tuple[DetectorSpec, ...]:
    if target_kind == "SKILL":
        specs = []
        for row in load_r2_registry()["dispositions"]:
            if row["terminal_state"] not in {
                "COVERED_BY_NATIVE_DETECTOR",
                "COVERED_BY_EXACT_ADAPTER",
            }:
                continue
            oracle_ids = [item for item in row["oracle_ids"] if item.strip()]
            detector_ids = [
                item
                for item in row["detector_ids"]
                if item not in {"none", "None", ""}
            ]
            if not detector_ids or not oracle_ids:
                continue
            specs.append(
                DetectorSpec(
                    detector_id=detector_ids[0],
                    detector_version="1.0.0",
                    target_kinds=(target_kind,),
                    category_id=row["category_id"],
                    evidence_plane=row["evidence_plane"],
                    oracle_id=oracle_ids[0],
                )
            )
        return tuple(specs)
    return tuple(
        DetectorSpec(
            detector_id=binding.detector_id,
            detector_version=DETECTOR_VERSION,
            target_kinds=(target_kind,),
            category_id=binding.category_id,
            evidence_plane=binding.evidence_plane,
            oracle_id=binding.oracle_id,
        )
        for binding in executable_taxonomy_bindings(target_kind)
    )


def default_taxonomy_coverage(target_kind: str) -> dict[str, object]:
    kind = target_kind.upper()
    if kind not in ALL_TARGET_KINDS:
        raise ValueError(f"unsupported target kind: {target_kind}")
    if kind == "SKILL":
        actual_detectors = {
            detector_id
            for detector_id, _category_id, _evidence_plane, _detector in DEFAULT_DETECTORS
        }
        missing = sorted(set(CANONICAL_DETECTOR_BINDINGS) - actual_detectors)
        if missing:
            raise ValueError(
                "canonical detector missing from executable registry: "
                + ", ".join(missing)
            )
        return build_r2_taxonomy_coverage()
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
