from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.state_machine import (
    TERMINAL_STATES,
    TransitionError,
    advance,
)


def test_happy_path_advances_in_order():
    states = ["INTAKE"]
    events = [
        "freeze_scope",
        "census",
        "discover",
        "impact",
        "plan",
        "preflight",
        "build_candidate",
        "verify",
        "review",
        "close",
    ]

    for event in events:
        states.append(advance(states[-1], event))

    assert states == [
        "INTAKE",
        "SCOPE_FROZEN",
        "SUBJECT_CENSUS",
        "ISSUE_DISCOVERY",
        "IMPACT_CLOSURE",
        "BATCH_PLANNED",
        "PREFLIGHT_VERIFIED",
        "CANDIDATE_BUILT",
        "FULL_VERIFICATION",
        "INDEPENDENT_REVIEW",
        "CLOSED_FOR_DECLARED_UNIVERSE",
    ]


def test_input_drift_is_terminal_and_cannot_return_to_scope_frozen():
    blocked = advance("SUBJECT_CENSUS", "input_drift")

    assert blocked == "BLOCKED_STALE_INPUT"
    assert blocked in TERMINAL_STATES
    with pytest.raises(TransitionError):
        advance(blocked, "freeze_scope")


def test_taxonomy_gap_is_terminal():
    blocked = advance("SCOPE_FROZEN", "taxonomy_gap")

    assert blocked == "BLOCKED_TAXONOMY"
    assert blocked in TERMINAL_STATES


def test_adapter_failure_is_the_documented_terminal_state():
    blocked = advance("SCOPE_FROZEN", "adapter_failed")

    assert blocked == "BLOCKED_ADAPTER"
    assert blocked in TERMINAL_STATES


def test_verification_failure_is_terminal():
    blocked = advance("FULL_VERIFICATION", "verification_failed")

    assert blocked == "BLOCKED_VERIFICATION"
    assert blocked in TERMINAL_STATES


def test_no_automatic_edge_from_verification_back_to_repair_or_discovery():
    for event in ("reopen", "repair", "rediscover"):
        with pytest.raises(TransitionError):
            advance("FULL_VERIFICATION", event)
