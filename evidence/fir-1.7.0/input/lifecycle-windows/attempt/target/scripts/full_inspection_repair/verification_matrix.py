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
        "case_identities": dict(case_identities or {}),
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
    if expected_identities is not None:
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
