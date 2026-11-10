from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timezone

from .contracts import validate_contract
from .detectors import DetectorResult
from .ledger import build_risk_ledger


class VerificationBlocked(ValueError):
    """Raised when verification cannot establish a trustworthy outcome."""


def reconcile_detector_results(
    candidate_results: Iterable[DetectorResult],
    expected_detector_ids: Iterable[str],
) -> list[DetectorResult]:
    expected = list(expected_detector_ids)
    if not expected:
        raise VerificationBlocked("expected detector set is empty")
    if len(expected) != len(set(expected)):
        raise VerificationBlocked("expected detector set contains duplicates")
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
    expected_detector_ids: Iterable[str] | None = None,
    closed_at: str | None = None,
) -> dict[str, object]:
    if not re.fullmatch(r"[a-f0-9]{64}", candidate_digest):
        raise VerificationBlocked("candidate digest is invalid")
    if expected_detector_ids is None:
        expected = [result.detector_id for result in candidate_results]
        if not expected:
            raise VerificationBlocked("candidate detector set is empty")
    else:
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
    timestamp = closed_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
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
                        f"rerun:{original['invariant_id']}:"
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
    )
