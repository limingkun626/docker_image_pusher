from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from .contracts import material_digest

ALLOWED_STATUSES = frozenset(
    {"PASS", "FAIL", "TIMEOUT", "INFRA_ERROR", "UNSCORED", "MISSING"}
)


class MatrixBlocked(ValueError):
    """Raised when verification evidence cannot produce a trustworthy result."""

    def __init__(self, message: str, code: str = "BLOCKED_VERIFICATION") -> None:
        super().__init__(message)
        self.code = code


def build_case_registry(
    case_identities: Mapping[str, Mapping[str, str]],
) -> dict[str, object]:
    if not isinstance(case_identities, Mapping) or not case_identities:
        raise MatrixBlocked("frozen evaluation case registry is empty")
    cases: dict[str, dict[str, str]] = {}
    for case_id, identity in case_identities.items():
        if not isinstance(case_id, str) or not case_id or not isinstance(identity, Mapping):
            raise MatrixBlocked("frozen evaluation case identity is invalid")
        case: dict[str, str] = {}
        for field in ("fixture_digest", "runner_digest", "tool_digest"):
            value = identity.get(field)
            if not _digest(value):
                raise MatrixBlocked(
                    f"{case_id} has invalid {field}", "BLOCKED_EVIDENCE"
                )
            case[field] = str(value)
        cases[case_id] = case
    registry: dict[str, object] = {
        "schema_version": 1,
        "cases": cases,
    }
    registry["registry_digest"] = material_digest(registry, "registry_digest")
    return registry


def validate_case_registry(registry: object) -> dict[str, object]:
    if not isinstance(registry, dict):
        raise MatrixBlocked("frozen evaluation case registry is missing")
    if set(registry) != {"schema_version", "cases", "registry_digest"}:
        raise MatrixBlocked("frozen evaluation case registry is incomplete")
    if registry.get("schema_version") != 1:
        raise MatrixBlocked("frozen evaluation case registry version mismatch")
    if registry.get("registry_digest") != material_digest(
        registry, "registry_digest"
    ):
        raise MatrixBlocked(
            "frozen evaluation case registry digest mismatch",
            "BLOCKED_EVIDENCE",
        )
    cases = registry.get("cases")
    if not isinstance(cases, dict) or not cases:
        raise MatrixBlocked("frozen evaluation case registry is empty")
    normalized = build_case_registry(cases)
    if normalized["cases"] != cases:
        raise MatrixBlocked("frozen evaluation case registry cases were replaced")
    return registry


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _check_case_identities(
    requested: list[str],
    case_identities: Mapping[str, Mapping[str, str]] | None,
    expected_identities: Mapping[str, Mapping[str, str]] | None,
) -> None:
    if case_identities is None:
        if expected_identities is not None:
            raise MatrixBlocked("case identity evidence is missing")
        return
    if set(case_identities) != set(requested):
        raise MatrixBlocked("case identity set does not match requested cases")
    for case_id in requested:
        identity = case_identities[case_id]
        for field in ("fixture_digest", "runner_digest", "tool_digest"):
            if not _digest(identity.get(field)):
                raise MatrixBlocked(
                    f"{case_id} has invalid {field}", "BLOCKED_EVIDENCE"
                )
        if expected_identities is not None:
            expected = expected_identities.get(case_id)
            if expected is None:
                raise MatrixBlocked(
                    f"{case_id} has no expected identity", "BLOCKED_EVIDENCE"
                )
            for field in ("fixture_digest", "runner_digest", "tool_digest"):
                if identity.get(field) != expected.get(field):
                    raise MatrixBlocked(
                        f"{case_id} {field} was substituted",
                        "BLOCKED_EVIDENCE",
                    )


def reconcile_evaluation(
    *,
    requested: list[str],
    attempts: Mapping[str, str],
    f2p: set[str],
    p2p: set[str],
    case_identities: Mapping[str, Mapping[str, str]] | None = None,
    expected_identities: Mapping[str, Mapping[str, str]] | None = None,
    case_registry_digest: str | None = None,
    run_id: str | None = None,
    scope_digest: str | None = None,
    subject_digest: str | None = None,
    candidate_digest: str | None = None,
) -> dict[str, object]:
    if not requested:
        raise MatrixBlocked("requested evaluation set is empty")
    if len(requested) != len(set(requested)):
        raise MatrixBlocked("requested evaluation set contains duplicates")
    if f2p & p2p:
        raise MatrixBlocked("F2P and P2P sets overlap")
    invalid = sorted(set(attempts.values()) - ALLOWED_STATUSES)
    if invalid:
        raise MatrixBlocked("invalid evaluation status: " + ", ".join(invalid))
    missing = sorted(set(requested) - set(attempts))
    if missing:
        raise MatrixBlocked("missing requested cases: " + ", ".join(missing))
    unexpected = sorted(set(attempts) - set(requested))
    if unexpected:
        raise MatrixBlocked("unexpected attempted cases: " + ", ".join(unexpected))
    _check_case_identities(requested, case_identities, expected_identities)
    if expected_identities is not None and not _digest(case_registry_digest):
        raise MatrixBlocked(
            "frozen evaluation case registry digest is missing",
            "BLOCKED_EVIDENCE",
        )

    statuses = [attempts[case_id] for case_id in requested]
    required = f2p | p2p
    undeclared_required = sorted(required - set(requested))
    if undeclared_required:
        raise MatrixBlocked(
            "required cases were not requested: " + ", ".join(undeclared_required)
        )
    required_unscored = sorted(
        case_id for case_id in required if attempts[case_id] == "UNSCORED"
    )
    if required_unscored:
        raise MatrixBlocked(
            "required cases are unscored: " + ", ".join(required_unscored)
        )
    infrastructure = sorted(
        case_id
        for case_id in requested
        if attempts[case_id] in {"TIMEOUT", "INFRA_ERROR", "MISSING"}
    )
    if infrastructure:
        raise MatrixBlocked(
            "infrastructure, timeout or missing cases: "
            + ", ".join(infrastructure)
        )
    if all(
        status in {"UNSCORED", "TIMEOUT", "INFRA_ERROR", "MISSING"}
        for status in statuses
    ):
        raise MatrixBlocked("evaluation is inconclusive")
    failing_required = sorted(
        case_id for case_id in required if attempts[case_id] != "PASS"
    )
    if failing_required:
        raise MatrixBlocked(
            "F2P/P2P not satisfied: " + ", ".join(failing_required)
        )
    failed = sorted(case_id for case_id in requested if attempts[case_id] == "FAIL")
    if failed:
        raise MatrixBlocked("requested cases failed: " + ", ".join(failed))

    counts = Counter(statuses)
    report: dict[str, object] = {
        "schema_version": 2,
        "status": "PASS",
        "requested_count": len(requested),
        "passed_count": counts["PASS"],
        "unscored_count": counts["UNSCORED"],
        "failed_count": 0,
        "f2p": sorted(f2p),
        "p2p": sorted(p2p),
        "required_failures": 0,
        "six_state": {
            status: counts[status] for status in sorted(ALLOWED_STATUSES)
        },
        "case_statuses": {
            case_id: attempts[case_id] for case_id in requested
        },
        "case_identities": dict(case_identities or {}),
        "case_registry_digest": case_registry_digest,
    }
    bindings = {
        "run_id": run_id,
        "scope_digest": scope_digest,
        "subject_digest": subject_digest,
        "candidate_digest": candidate_digest,
    }
    if any(value is not None for value in bindings.values()):
        if not all(value is not None for value in bindings.values()):
            raise MatrixBlocked("matrix binding is incomplete", "BLOCKED_EVIDENCE")
        if len({scope_digest, subject_digest, candidate_digest}) != 3:
            raise MatrixBlocked(
                "matrix scope, subject and candidate are not distinct",
                "BLOCKED_EVIDENCE",
            )
        report.update(bindings)
    report["matrix_digest"] = material_digest(report, "matrix_digest")
    return report


def verify_matrix_binding(
    matrix: Mapping[str, Any],
    *,
    run_id: str,
    scope_digest: str,
    subject_digest: str,
    candidate_digest: str,
    expected_identities: Mapping[str, Mapping[str, str]] | None = None,
    case_registry_digest: str | None = None,
) -> None:
    expected = {
        "run_id": run_id,
        "scope_digest": scope_digest,
        "subject_digest": subject_digest,
        "candidate_digest": candidate_digest,
    }
    for field, value in expected.items():
        if matrix.get(field) != value:
            raise MatrixBlocked(f"matrix {field} mismatch", "BLOCKED_EVIDENCE")
    if matrix.get("status") != "PASS":
        raise MatrixBlocked("matrix is not PASS")
    if matrix.get("required_failures") != 0:
        raise MatrixBlocked("matrix has required failures")
    if matrix.get("matrix_digest") != material_digest(dict(matrix), "matrix_digest"):
        raise MatrixBlocked("matrix digest mismatch", "BLOCKED_EVIDENCE")
    identities = matrix.get("case_identities")
    if not isinstance(identities, dict) or not identities:
        raise MatrixBlocked("matrix fixture/runner/tool identities are missing")
    case_statuses = matrix.get("case_statuses")
    six_state = matrix.get("six_state")
    if (
        not isinstance(case_statuses, dict)
        or set(case_statuses) != set(identities)
        or not isinstance(six_state, dict)
        or set(six_state) != ALLOWED_STATUSES
    ):
        raise MatrixBlocked(
            "matrix case statuses or six-state counts are incomplete",
            "BLOCKED_EVIDENCE",
        )
    invalid_statuses = sorted(
        case_id
        for case_id, status in case_statuses.items()
        if status not in ALLOWED_STATUSES
    )
    if invalid_statuses:
        raise MatrixBlocked(
            "matrix case statuses are invalid: " + ", ".join(invalid_statuses),
            "BLOCKED_EVIDENCE",
        )
    counts = Counter(case_statuses.values())
    expected_counts = {status: counts[status] for status in ALLOWED_STATUSES}
    if six_state != expected_counts:
        raise MatrixBlocked(
            "matrix six-state counts do not match case statuses",
            "BLOCKED_EVIDENCE",
        )
    if matrix.get("requested_count") != len(case_statuses):
        raise MatrixBlocked(
            "matrix requested_count does not match case statuses",
            "BLOCKED_EVIDENCE",
        )
    if matrix.get("passed_count") != counts["PASS"]:
        raise MatrixBlocked(
            "matrix passed_count does not match case statuses",
            "BLOCKED_EVIDENCE",
        )
    if matrix.get("failed_count") != counts["FAIL"]:
        raise MatrixBlocked(
            "matrix failed_count does not match case statuses",
            "BLOCKED_EVIDENCE",
        )
    required_cases = set(matrix.get("f2p", [])) | set(matrix.get("p2p", []))
    if not required_cases.issubset(identities):
        raise MatrixBlocked(
            "matrix required cases are outside the frozen case set",
            "BLOCKED_EVIDENCE",
        )
    if any(case_statuses[case_id] != "PASS" for case_id in required_cases):
        raise MatrixBlocked(
            "matrix required case is not PASS",
            "BLOCKED_EVIDENCE",
        )
    if expected_identities is not None:
        if not _digest(case_registry_digest):
            raise MatrixBlocked(
                "matrix lacks a frozen case registry digest",
                "BLOCKED_EVIDENCE",
            )
        if matrix.get("case_registry_digest") != case_registry_digest:
            raise MatrixBlocked(
                "matrix case registry digest mismatch",
                "BLOCKED_EVIDENCE",
            )
        for case_id, identity in identities.items():
            expected_identity = expected_identities.get(case_id)
            if expected_identity is None:
                raise MatrixBlocked(
                    f"{case_id} is not in the frozen case set", "BLOCKED_EVIDENCE"
                )
            for field in ("fixture_digest", "runner_digest", "tool_digest"):
                if identity.get(field) != expected_identity.get(field):
                    raise MatrixBlocked(
                        f"{case_id} {field} was substituted", "BLOCKED_EVIDENCE"
                    )
