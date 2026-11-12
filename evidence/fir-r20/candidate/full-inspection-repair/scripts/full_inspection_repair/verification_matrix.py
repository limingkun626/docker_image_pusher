from __future__ import annotations

ALLOWED_STATUSES = frozenset(
    {"PASS", "FAIL", "TIMEOUT", "INFRA_ERROR", "UNSCORED", "MISSING"}
)


class MatrixBlocked(ValueError):
    """Raised when verification evidence cannot produce a trustworthy result."""


def reconcile_evaluation(
    *,
    requested: list[str],
    attempts: dict[str, str],
    f2p: set[str],
    p2p: set[str],
) -> dict[str, object]:
    if not requested:
        raise MatrixBlocked("requested evaluation set is empty")
    invalid = sorted(set(attempts.values()) - ALLOWED_STATUSES)
    if invalid:
        raise MatrixBlocked("invalid evaluation status: " + ", ".join(invalid))
    missing = sorted(set(requested) - set(attempts))
    if missing:
        raise MatrixBlocked("missing requested cases: " + ", ".join(missing))
    unexpected = sorted(set(attempts) - set(requested))
    if unexpected:
        raise MatrixBlocked("unexpected attempted cases: " + ", ".join(unexpected))

    statuses = [attempts[case_id] for case_id in requested]
    unscored = sorted(
        case_id for case_id in requested if attempts[case_id] == "UNSCORED"
    )
    if unscored:
        raise MatrixBlocked("unscored requested cases: " + ", ".join(unscored))
    if all(
        status in {"UNSCORED", "TIMEOUT", "INFRA_ERROR", "MISSING"}
        for status in statuses
    ):
        raise MatrixBlocked("evaluation is inconclusive")
    infrastructure = sorted(
        case_id
        for case_id in requested
        if attempts[case_id] in {"TIMEOUT", "INFRA_ERROR", "MISSING"}
    )
    if infrastructure:
        raise MatrixBlocked("infrastructure or timeout cases: " + ", ".join(infrastructure))

    required = f2p | p2p
    undeclared_required = sorted(required - set(requested))
    if undeclared_required:
        raise MatrixBlocked(
            "required cases were not requested: " + ", ".join(undeclared_required)
        )
    failing_required = sorted(case_id for case_id in required if attempts.get(case_id) != "PASS")
    if failing_required:
        raise MatrixBlocked("F2P/P2P not satisfied: " + ", ".join(failing_required))
    failed = sorted(case_id for case_id in requested if attempts[case_id] == "FAIL")
    if failed:
        raise MatrixBlocked("requested cases failed: " + ", ".join(failed))

    return {
        "schema_version": 1,
        "status": "PASS",
        "requested_count": len(requested),
        "passed_count": sum(status == "PASS" for status in statuses),
        "unscored_count": sum(status == "UNSCORED" for status in statuses),
        "failed_count": 0,
        "f2p": sorted(f2p),
        "p2p": sorted(p2p),
    }
