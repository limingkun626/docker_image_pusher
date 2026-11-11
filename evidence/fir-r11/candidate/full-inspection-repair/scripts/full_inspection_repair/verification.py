from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime

from .contracts import canonical_digest, validate_contract
from .detectors import DEFAULT_DETECTORS, DetectorResult
from .ledger import build_risk_ledger


class VerificationBlocked(ValueError):
    """Raised when verification cannot establish a trustworthy outcome."""


def _expected_specs() -> dict[str, tuple[str, str, str]]:
    return {
        detector_id: ("1.0.0", category, plane)
        for detector_id, category, plane, _detector in DEFAULT_DETECTORS
    }


def reconcile_detector_results(
    candidate_results: Iterable[DetectorResult],
    expected_detector_ids: Iterable[str],
) -> list[DetectorResult]:
    expected = list(expected_detector_ids)
    if not expected:
        raise VerificationBlocked("expected detector set is empty")
    if len(expected) != len(set(expected)):
        raise VerificationBlocked("expected detector set contains duplicates")
    specs = _expected_specs()
    unknown = sorted(set(expected) - set(specs))
    if unknown:
        raise VerificationBlocked(
            "unknown detector in expected set: " + ", ".join(unknown)
        )
    results = list(candidate_results)
    if not results:
        raise VerificationBlocked("candidate detector set is empty")
    actual = [result.detector_id for result in results]
    duplicates = sorted(
        detector_id for detector_id in set(actual) if actual.count(detector_id) > 1
    )
    if duplicates:
        raise VerificationBlocked("duplicate detector results: " + ", ".join(duplicates))
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    if missing:
        raise VerificationBlocked("missing detector results: " + ", ".join(missing))
    if unexpected:
        raise VerificationBlocked("unexpected detector results: " + ", ".join(unexpected))
    for result in results:
        if result.status not in {"PASS", "FINDINGS"}:
            raise VerificationBlocked(f"detector {result.detector_id} is {result.status}")
        if result.error is not None:
            raise VerificationBlocked(
                f"detector {result.detector_id} carries an error"
            )
        if result.status == "PASS" and result.findings:
            raise VerificationBlocked(
                f"detector {result.detector_id} reports PASS with findings"
            )
        if result.status == "FINDINGS" and not result.findings:
            raise VerificationBlocked(
                f"detector {result.detector_id} reports findings without evidence"
            )
        version, category, plane = specs[result.detector_id]
        if (
            result.detector_version != version
            or result.taxonomy_category_id != category
            or result.evidence_plane != plane
        ):
            raise VerificationBlocked(
                f"detector {result.detector_id} identity does not match frozen spec"
            )
    return results


def _finding_key(finding: dict[str, object]) -> tuple[str, str]:
    refs = finding["affected_refs"]
    target = str(refs[0]) if refs else ""
    return str(finding["invariant_id"]), target


def verify_repair(
    *,
    original_findings: list[dict[str, object]],
    candidate_results: tuple[DetectorResult, ...],
    candidate_digest: str,
    scope_digest: str,
    required_sources: list[str],
    observed_sources: list[str] | None = None,
    present_sources: list[str] | None = None,
    source_inventory: list[dict[str, object]] | None = None,
    expected_detector_ids: Iterable[str] | None = None,
    closed_at: str | None = None,
) -> dict[str, object]:
    if not re.fullmatch(r"[a-f0-9]{64}", candidate_digest):
        raise VerificationBlocked("candidate digest is invalid")
    if expected_detector_ids is None:
        raise VerificationBlocked("expected detector set is required")
    expected = list(expected_detector_ids)
    candidate_results = tuple(
        reconcile_detector_results(candidate_results, expected)
    )
    candidate_findings = [
        finding for result in candidate_results for finding in result.findings
    ]
    normalised_candidate_findings: list[dict[str, object]] = []
    for finding in candidate_findings:
        item = {"schema_version": 1, **finding}
        validate_contract("finding", item)
        normalised_candidate_findings.append(item)
    candidate_findings = normalised_candidate_findings
    remaining = {_finding_key(finding) for finding in candidate_findings}
    timestamp = closed_at or datetime.now(UTC).replace(microsecond=0).isoformat()
    detector_set_digest = canonical_digest(sorted(expected))
    verified: list[dict[str, object]] = []
    for original in original_findings:
        item = dict(original)
        if _finding_key(original) in remaining:
            item["status"] = "OPEN"
        else:
            item.update(
                {
                    "status": "FIXED",
                    "closed_by": candidate_digest,
                    "closed_at": timestamp,
                    "verification_check": (
                        f"rerun:{detector_set_digest[:16]}:{original['invariant_id']}:"
                        f"{_finding_key(original)[1]}"
                    ),
                    "evidence_refs": [f"candidate:{candidate_digest}"],
                    "evidence_sha256": candidate_digest,
                }
            )
        verified.append(item)
    original_risk_ids = {str(item["risk_id"]) for item in original_findings}
    for finding in candidate_findings:
        if str(finding["risk_id"]) not in original_risk_ids:
            item = dict(finding)
            item["status"] = "OPEN"
            item["closed_by"] = None
            item["closed_at"] = None
            item["verification_check"] = None
            item["residual_risk"] = None
            verified.append(item)
    if observed_sources is None:
        observed_sources = present_sources
    if observed_sources is None:
        observed_sources = list(required_sources)
    return build_risk_ledger(
        scope_digest=scope_digest,
        required_sources=required_sources,
        findings=verified,
        observed_sources=observed_sources,
        present_sources=present_sources,
        source_inventory=source_inventory,
    )
