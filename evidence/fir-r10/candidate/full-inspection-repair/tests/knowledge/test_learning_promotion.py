from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.knowledge import (
    KnowledgeError,
    load_frozen_pack,
    pack_content_digest,
    promote_pack,
    validate_candidate,
)


def candidate(**overrides):
    value = {
        "candidate_id": "candidate-1",
        "evidence_pack_digest": "c" * 64,
        "samples": 20,
        "precision": 0.95,
        "false_trigger_rate": 0.05,
        "held_out": True,
        "mutation_passed": True,
        "historical_replay_passed": True,
        "guard_only": False,
    }
    value.update(overrides)
    return value


def pack(**overrides):
    value = {
        "schema_version": 1,
        "pack_id": "pack-1",
        "pack_version": "1.0.0",
        "entries": [{"knowledge_id": "knowledge-1", "detector_id": "probe"}],
        "scope": {"target_kinds": ["SKILL"]},
        "source_evidence_digest": "c" * 64,
        "shadow_replay_passed": True,
        "expires_at": None,
    }
    value.update(overrides)
    value["pack_digest"] = pack_content_digest(value)
    return value


def test_low_precision_candidate_is_rejected():
    with pytest.raises(KnowledgeError, match="precision"):
        validate_candidate(candidate(precision=0.89))


def test_source_run_cannot_hot_load_a_new_pack():
    value = pack()
    with pytest.raises(KnowledgeError, match="frozen pack"):
        load_frozen_pack(
            run_pack_digest="a" * 64,
            requested_pack=value,
        )


def test_independent_review_is_required_for_promotion():
    with pytest.raises(KnowledgeError, match="independent"):
        promote_pack(
            candidate(),
            pack=pack(),
            producer="agent-a",
            reviewer="agent-a",
        )


def test_valid_candidate_can_be_promoted():
    active = promote_pack(
        candidate(),
        pack=pack(),
        producer="agent-a",
        reviewer="agent-b",
    )

    assert active["status"] == "ACTIVE"
    assert active["source_evidence_digest"] == "c" * 64
