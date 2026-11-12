from __future__ import annotations

TERMINAL_STATES = frozenset(
    {
        "CLOSED_FOR_DECLARED_UNIVERSE",
        "BLOCKED_SCOPE",
        "BLOCKED_ADAPTER",
        "BLOCKED_TAXONOMY",
        "BLOCKED_STALE_INPUT",
        "BLOCKED_DETECTOR",
        "BLOCKED_EVIDENCE",
        "BLOCKED_REPAIR_PLAN",
        "BLOCKED_REPAIR_CONFLICT",
        "BLOCKED_VERIFICATION",
        "BLOCKED_INDEPENDENT_REVIEW",
    }
)

_TRANSITIONS = {
    ("INTAKE", "freeze_scope"): "SCOPE_FROZEN",
    ("SCOPE_FROZEN", "census"): "SUBJECT_CENSUS",
    ("SUBJECT_CENSUS", "discover"): "ISSUE_DISCOVERY",
    ("ISSUE_DISCOVERY", "impact"): "IMPACT_CLOSURE",
    ("IMPACT_CLOSURE", "plan"): "BATCH_PLANNED",
    ("BATCH_PLANNED", "preflight"): "PREFLIGHT_VERIFIED",
    ("PREFLIGHT_VERIFIED", "build_candidate"): "CANDIDATE_BUILT",
    ("CANDIDATE_BUILT", "verify"): "FULL_VERIFICATION",
    ("FULL_VERIFICATION", "review"): "INDEPENDENT_REVIEW",
    ("INDEPENDENT_REVIEW", "close"): "CLOSED_FOR_DECLARED_UNIVERSE",
}


class TransitionError(ValueError):
    """Raised when a state transition is not explicitly allowed."""


def advance(current: str, event: str) -> str:
    if current in TERMINAL_STATES:
        raise TransitionError(f"terminal state cannot transition: {current}")
    blocked = {
        "input_drift": "BLOCKED_STALE_INPUT",
        "adapter_failed": "BLOCKED_ADAPTER",
        "taxonomy_gap": "BLOCKED_TAXONOMY",
        "detector_failed": "BLOCKED_DETECTOR",
        "evidence_failed": "BLOCKED_EVIDENCE",
        "evaluation_failed": "BLOCKED_VERIFICATION",
        "repair_plan_failed": "BLOCKED_REPAIR_PLAN",
    }
    if event in blocked:
        return blocked[event]
    if event == "verification_failed":
        if current != "FULL_VERIFICATION":
            raise TransitionError("verification_failed is valid only in FULL_VERIFICATION")
        return "BLOCKED_VERIFICATION"
    try:
        return _TRANSITIONS[(current, event)]
    except KeyError as exc:
        raise TransitionError(f"illegal transition: {current} --{event}-->") from exc
