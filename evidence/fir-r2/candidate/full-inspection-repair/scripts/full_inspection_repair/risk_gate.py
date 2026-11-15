from __future__ import annotations

from typing import Any

from .contracts import CLOSED_FINDING_STATUSES, canonical_digest

CLOSED_STATUSES = CLOSED_FINDING_STATUSES

REQUIRED_DOMAINS = {
    "platform_support.windows_install": "VERIFIED",
    "platform_support.linux_install": "VERIFIED",
    "platform_support.macos_install": "VERIFIED",
    "durability.software_atomicity": "VERIFIED",
    "durability.physical_power_loss": "VERIFIED",
    "trust.non_producer_review": "VERIFIED",
    "trust.external_trust_root": "VERIFIED",
    "trust.external_reviewer_signature": "VERIFIED",
    "evaluator.verifier_identity_frozen": "VERIFIED",
    "evaluator.tamper_input_matrix": "VERIFIED",
    "evaluator.structured_blocked_receipt": "VERIFIED",
    "lifecycle.staging_install": "VERIFIED",
    "lifecycle.readback": "VERIFIED",
    "lifecycle.atomic_activation": "VERIFIED",
    "lifecycle.rollback_retained": "VERIFIED",
    "lifecycle.post_activation_smoke": "VERIFIED",
}


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _domain_value(domains: dict[str, Any], dotted: str) -> str:
    current: Any = domains
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return "MISSING"
        current = current.get(part, "MISSING")
    if isinstance(current, dict):
        return str(current.get("status", "MISSING"))
    return str(current)


def _finding_id(item: dict[str, Any]) -> str:
    return str(
        item.get(
            "finding_id",
            item.get("risk_id", item.get("issue_id", "UNKNOWN")),
        )
    )


def _record_digest(value: dict[str, Any], field: str) -> str | None:
    declared = value.get(field)
    material = dict(value)
    material.pop(field, None)
    return declared if declared == canonical_digest(material) else None


def assess_release_gate(
    *,
    findings: list[dict[str, Any]],
    review: dict[str, Any],
    domains: dict[str, Any],
    coverage: dict[str, Any],
    matrix: dict[str, Any],
    expected_candidate_digest: str,
    expected_scope_digest: str | None = None,
    expected_verification_digest: str | None = None,
    require_evidence_binding: bool = False,
) -> dict[str, Any]:
    """Recompute the release gate from raw evidence.

    A caller-supplied ``review["risk_gate"]`` is intentionally ignored.
    """

    blockers: list[str] = []
    if not _valid_digest(expected_candidate_digest):
        blockers.append("CANDIDATE_DIGEST_INVALID")
    if expected_scope_digest is not None and not _valid_digest(expected_scope_digest):
        blockers.append("SCOPE_DIGEST_INVALID")
    if expected_verification_digest is not None and not _valid_digest(
        expected_verification_digest
    ):
        blockers.append("VERIFICATION_DIGEST_INVALID")

    matrix_digest = _record_digest(matrix, "matrix_digest")
    coverage_digest = _record_digest(coverage, "coverage_digest")
    domains_digest = canonical_digest(domains)
    findings_digest = canonical_digest(findings)

    if matrix_digest is None:
        blockers.append("MATRIX_DIGEST")
    if coverage_digest is None:
        blockers.append("COVERAGE_DIGEST")
    if matrix.get("candidate_digest") != expected_candidate_digest:
        blockers.append("MATRIX_CANDIDATE_MISMATCH")
    if review.get("candidate_digest") != expected_candidate_digest:
        blockers.append("REVIEW_CANDIDATE_MISMATCH")
    if matrix_digest != review.get("matrix_digest"):
        blockers.append("REVIEW_MATRIX_MISMATCH")

    scope_digest = review.get("scope_digest")
    verification_digest = review.get("verification_digest")
    evaluator_digest = review.get("evaluator_digest")
    ledger_digest = review.get("ledger_digest")
    for name, value in (
        ("SCOPE", scope_digest),
        ("VERIFICATION", verification_digest),
        ("EVALUATOR", evaluator_digest),
        ("LEDGER", ledger_digest),
    ):
        if not _valid_digest(value):
            blockers.append(f"{name}_DIGEST_INVALID")
    if (
        expected_scope_digest is not None
        and matrix.get("scope_digest") != expected_scope_digest
    ):
        blockers.append("MATRIX_SCOPE_MISMATCH")
    if matrix.get("scope_digest") != scope_digest:
        blockers.append("MATRIX_REVIEW_SCOPE_MISMATCH")
    if expected_verification_digest is not None and (
        matrix.get("verification_digest") != expected_verification_digest
    ):
        blockers.append("MATRIX_VERIFICATION_MISMATCH")
    if matrix.get("verification_digest") != verification_digest:
        blockers.append("MATRIX_REVIEW_VERIFICATION_MISMATCH")
    if matrix.get("evaluator_digest") != evaluator_digest:
        blockers.append("MATRIX_EVALUATOR_MISMATCH")
    if matrix.get("coverage_digest") != coverage_digest:
        blockers.append("MATRIX_COVERAGE_MISMATCH")
    if matrix.get("domains_digest") != domains_digest:
        blockers.append("MATRIX_DOMAINS_MISMATCH")
    if matrix.get("status") != "PASS" or matrix.get("failed_count") != 0:
        blockers.append("FULL_MATRIX")
    if matrix.get("failures") or matrix.get("failed_checks") or matrix.get("skipped"):
        blockers.append("FULL_MATRIX_RAW")
    if require_evidence_binding:
        checks = matrix.get("checks")
        requested_cases = matrix.get("requested_cases")
        if not isinstance(checks, list) or not checks:
            blockers.append("MATRIX_CHECKS_MISSING")
        if not isinstance(requested_cases, list) or not requested_cases:
            blockers.append("MATRIX_REQUESTED_CASES_MISSING")
        if isinstance(checks, list) and isinstance(requested_cases, list):
            check_ids = [str(item.get("check_id")) for item in checks]
            if len(check_ids) != len(set(check_ids)):
                blockers.append("MATRIX_CHECK_DUPLICATE")
            if set(check_ids) != {str(item) for item in requested_cases}:
                blockers.append("MATRIX_REQUESTED_CASE_MISMATCH")
            for item in checks:
                receipt = item.get("receipt")
                if (
                    item.get("status") != "PASS"
                    or item.get("candidate_digest") != expected_candidate_digest
                    or not _valid_digest(item.get("receipt_sha256"))
                    or not item.get("runner")
                    or not item.get("environment")
                    or not isinstance(receipt, dict)
                    or canonical_digest(receipt) != item.get("receipt_sha256")
                ):
                    blockers.append(
                        f"MATRIX_CHECK_UNBOUND:{item.get('check_id', 'UNKNOWN')}"
                    )

    nonterminal = [
        _finding_id(item)
        for item in findings
        if item.get("status") not in CLOSED_STATUSES
    ]
    if nonterminal:
        blockers.append("NONTERMINAL_FINDINGS:" + ",".join(map(str, nonterminal)))
    if any(_finding_id(item) == "UNKNOWN" for item in findings):
        blockers.append("FINDING_WITHOUT_ID")
    canonical_findings = all("risk_id" in item for item in findings)
    if canonical_findings:
        for item in findings:
            if (
                not item.get("evidence_refs")
                or not item.get("verification_check")
                or not item.get("closed_at")
            ):
                blockers.append(f"FINDING_CLOSURE_UNBOUND:{_finding_id(item)}")
    else:
        if any(not item.get("impact") for item in findings):
            blockers.append("FINDING_WITHOUT_IMPACT")
        if any(not item.get("impact_proof") for item in findings):
            blockers.append("FINDING_WITHOUT_IMPACT_PROOF")
        if any(not item.get("verification_evidence") for item in findings):
            blockers.append("FINDING_WITHOUT_VERIFICATION")
    if require_evidence_binding:
        for item in findings:
            finding_id = _finding_id(item)
            if (
                not item.get("evidence_refs")
                or not _valid_digest(item.get("evidence_sha256"))
                or item.get("closed_by") != expected_candidate_digest
            ):
                blockers.append(f"FINDING_EVIDENCE_UNBOUND:{finding_id}")

    for field in (
        "limitations",
        "unverified_claims",
        "not_run",
        "non_blocking_observations",
        "residual_risks",
        "accepted_risks",
        "deferred_risks",
        "informational",
        "skipped",
        "waivers",
        "exemptions",
    ):
        value = review.get(field)
        if value not in (None, [], {}):
            blockers.append(f"REVIEW_FIELD:{field}")
    if review.get("open_count") != 0:
        blockers.append("REVIEW_OPEN_COUNT")
    if review.get("verdict") != "PASS":
        blockers.append("REVIEW_VERDICT")

    ledger_projection = [
        (
            _finding_id(item),
            item.get("status"),
        )
        for item in findings
    ]
    review_findings = review.get("findings", [])
    review_projection = [
        (_finding_id(item), item.get("status"))
        for item in review_findings
    ]
    ledger_ids = [finding_id for finding_id, _ in ledger_projection]
    review_ids = [finding_id for finding_id, _ in review_projection]
    if (
        len(set(ledger_ids)) != len(ledger_ids)
        or len(set(review_ids)) != len(review_ids)
        or dict(review_projection) != dict(ledger_projection)
    ):
        blockers.append("REVIEW_LEDGER_PROJECTION_DEFECT")
    if any(item.get("status") not in CLOSED_STATUSES for item in review_findings):
        blockers.append("REVIEW_OPEN_FINDING")
    if review.get("findings_digest") not in (None, findings_digest):
        blockers.append("REVIEW_FINDINGS_DIGEST")

    for field, expected in REQUIRED_DOMAINS.items():
        actual = _domain_value(domains, field)
        if actual != expected:
            blockers.append(f"DOMAIN:{field}:{actual}")
        if require_evidence_binding:
            entry = domains
            for part in field.split("."):
                entry = entry.get(part, {}) if isinstance(entry, dict) else {}
            if (
                not isinstance(entry, dict)
                or not _valid_digest(entry.get("receipt_sha256"))
                or entry.get("scope_digest") != scope_digest
                or not entry.get("runner")
                or not entry.get("environment")
                or not isinstance(entry.get("receipt"), dict)
                or canonical_digest(entry["receipt"])
                != entry.get("receipt_sha256")
            ):
                blockers.append(f"DOMAIN_EVIDENCE_UNBOUND:{field}")

    if coverage.get("uncovered_count") != 0:
        blockers.append("COVERAGE_UNCOVERED")
    if coverage.get("gap_count") != 0:
        blockers.append("COVERAGE_GAP")
    if coverage.get("uncovered"):
        blockers.append("COVERAGE_UNCOVERED_RAW")
    if coverage.get("gaps"):
        blockers.append("COVERAGE_GAP_RAW")
    if coverage.get("uncovered_count") != len(coverage.get("uncovered", [])):
        blockers.append("COVERAGE_UNCOVERED_COUNT")
    if coverage.get("gap_count") != len(coverage.get("gaps", [])):
        blockers.append("COVERAGE_GAP_COUNT")
    for field in (
        "codepoint_count",
        "line_count",
        "unit_count",
        "punctuation_count",
        "file_count",
    ):
        if coverage.get(field, 0) <= 0:
            blockers.append(f"COVERAGE_EMPTY:{field}")

    if review.get("review_digest") is not None and (
        _record_digest(review, "review_digest") is None
    ):
        blockers.append("REVIEW_DIGEST")

    result: dict[str, Any] = {
        "schema_version": 2,
        "status": "PASS" if not blockers else "BLOCKED",
        "release_ready": not blockers,
        "state": (
            "CLOSED_FOR_DECLARED_UNIVERSE"
            if not blockers
            else "BLOCKED_INDEPENDENT_REVIEW"
        ),
        "blockers": blockers,
        "blocker_count": len(blockers),
        "finding_count": len(findings),
        "nonterminal_finding_count": len(nonterminal),
        "scope_digest": scope_digest,
        "candidate_digest": expected_candidate_digest,
        "verification_digest": verification_digest,
        "ledger_digest": ledger_digest,
        "evaluator_digest": evaluator_digest,
        "coverage_digest": coverage_digest,
        "domains_digest": domains_digest,
        "findings_digest": findings_digest,
        "matrix_digest": matrix_digest,
        "review_binding_digest": canonical_digest(review),
    }
    result["gate_digest"] = canonical_digest(result)
    return result
