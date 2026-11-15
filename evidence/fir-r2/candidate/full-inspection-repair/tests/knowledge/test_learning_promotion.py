from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.knowledge import (
    KnowledgeError,
    load_frozen_pack,
    pack_content_digest,
    promote_pack,
    validate_candidate,
)

CORPUS_DIGEST = "a" * 64
ENVIRONMENT_DIGEST = "b" * 64
POLICY_DIGEST = "c" * 64


def _counters(results: dict[str, dict[str, str]]) -> dict[str, int]:
    counters = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }
    for result in results.values():
        expected = result["expected"]
        observed = result["observed"]
        if expected == "DETECT" and observed == "DETECT":
            counters["true_positives"] += 1
        elif expected == "CLEAN" and observed == "DETECT":
            counters["false_positives"] += 1
        elif expected == "CLEAN" and observed == "CLEAN":
            counters["true_negatives"] += 1
        elif expected == "DETECT" and observed == "CLEAN":
            counters["false_negatives"] += 1
    return counters


def _case_results(
    *, baseline: bool = False
) -> tuple[list[str], dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    case_ids = [f"case-{index:02d}" for index in range(20)]
    baseline_results = {}
    candidate_results = {}
    for index, case_id in enumerate(case_ids):
        expected = "DETECT" if index < 18 else "CLEAN"
        baseline_observed = (
            "CLEAN"
            if baseline and expected == "DETECT"
            else "DETECT"
            if baseline and expected == "CLEAN"
            else expected
        )
        baseline_results[case_id] = {
            "expected": expected,
            "observed": baseline_observed,
        }
        candidate_results[case_id] = {
            "expected": expected,
            "observed": expected,
        }
    return case_ids, baseline_results, candidate_results


def _receipt(
    kind: str,
    *,
    candidate_digest: str,
    pack_identity: str,
) -> dict[str, object]:
    case_ids, baseline_results, candidate_results = _case_results(baseline=True)
    receipt: dict[str, object] = {
        "schema_version": 1,
        "receipt_id": f"receipt-{kind.lower()}",
        "kind": kind,
        "execution": {
            "runner_id": "knowledge-replay",
            "command": ["python", "replay.py", kind.lower()],
            "exit_code": 0,
            "started_at": "2026-11-11T00:00:00Z",
            "finished_at": "2026-11-11T00:01:00Z",
            "candidate_digest": candidate_digest,
            "corpus_digest": CORPUS_DIGEST,
            "environment_digest": ENVIRONMENT_DIGEST,
            "pack_identity_digest": pack_identity,
            "pack_id": "pack-1",
            "pack_version": "1.0.0",
        },
        "requested_case_ids": case_ids,
        "baseline_results": baseline_results,
        "candidate_results": candidate_results,
        "baseline_counters": _counters(baseline_results),
        "candidate_counters": _counters(candidate_results),
        "redaction": {
            "status": "PASS",
            "secret_findings": 0,
            "policy_digest": POLICY_DIGEST,
        },
        "coverage_before": ["static", "behavior"],
        "coverage_after": ["static", "behavior", "security"],
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt


def pack_core() -> dict[str, object]:
    return {
        "schema_version": 1,
        "pack_id": "pack-1",
        "pack_version": "1.0.0",
        "entries": [{"knowledge_id": "knowledge-1", "detector_id": "probe"}],
        "scope": {"target_kinds": ["SKILL"]},
        "expires_at": None,
    }


def _pack_identity(value: dict[str, object]) -> str:
    return canonical_digest(value)


def candidate(
    pack_identity: str,
    **overrides: object,
) -> dict[str, object]:
    core: dict[str, object] = {
        "schema_version": 1,
        "candidate_id": "candidate-1",
        "candidate_type": "DETECTOR",
        "guard_only": False,
        "samples": 20,
        "precision": 1.0,
        "false_trigger_rate": 0.0,
        "train_case_ids": ["train-1"],
        "validation_case_ids": ["validation-1"],
        "held_out_case_ids": ["held-out-1"],
    }
    core.update(overrides)
    candidate_digest = canonical_digest(core)
    replay_evidence: dict[str, object] = {
        "schema_version": 1,
        "corpus_digest": CORPUS_DIGEST,
        "candidate": core,
        "receipts": {
            kind: _receipt(
                kind,
                candidate_digest=candidate_digest,
                pack_identity=pack_identity,
            )
            for kind in ("MUTATION", "HISTORICAL_REPLAY", "SHADOW_REPLAY")
        },
    }
    return {
        **core,
        "candidate_digest": candidate_digest,
        "replay_evidence": replay_evidence,
        "evidence_digest": canonical_digest(replay_evidence),
    }


def _resign_receipt(receipt: dict[str, object]) -> None:
    receipt["baseline_counters"] = _counters(receipt["baseline_results"])
    receipt["candidate_counters"] = _counters(receipt["candidate_results"])
    receipt["receipt_digest"] = canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )


def _resign_evidence(value: dict[str, object]) -> dict[str, object]:
    receipts = value["replay_evidence"]["receipts"]
    for kind, receipt in receipts.items():
        receipt["kind"] = kind
        _resign_receipt(receipt)
    value["evidence_digest"] = canonical_digest(value["replay_evidence"])
    return value


def pack(
    value: dict[str, object],
    core_value: dict[str, object] | None = None,
    **overrides: object,
) -> dict[str, object]:
    core = copy.deepcopy(core_value) if core_value is not None else pack_core()
    core.update(overrides)
    result: dict[str, object] = {
        **core,
        "candidate_digest": value["candidate_digest"],
        "source_evidence_digest": value["evidence_digest"],
        "replay_evidence": copy.deepcopy(value["replay_evidence"]),
        "reviewed_by": "reviewer-1",
    }
    review: dict[str, object] = {
        "schema_version": 1,
        "reviewer": "reviewer-1",
        "status": "APPROVED",
        "candidate_digest": value["candidate_digest"],
        "source_evidence_digest": value["evidence_digest"],
        "reviewed_at": "2026-11-11T00:02:00Z",
    }
    review["review_digest"] = canonical_digest(review)
    result["review_receipt"] = review
    result["pack_digest"] = pack_content_digest(result)
    return result


def _defaults(
    core_value: dict[str, object] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    core = copy.deepcopy(core_value) if core_value is not None else pack_core()
    identity = _pack_identity(core)
    value = candidate(identity)
    return value, pack(value, core_value=core)


def test_boolean_and_hash_only_candidate_cannot_be_promoted():
    value, frozen_pack = _defaults()
    legacy = {
        "candidate_id": "legacy",
        "evidence_pack_digest": frozen_pack["source_evidence_digest"],
        "samples": 20,
        "precision": 0.95,
        "false_trigger_rate": 0.05,
        "held_out": True,
        "mutation_passed": True,
        "historical_replay_passed": True,
        "guard_only": False,
    }

    with pytest.raises(KnowledgeError, match="executed replay"):
        promote_pack(
            legacy,
            pack=frozen_pack,
            producer="agent-a",
            reviewer="reviewer-1",
        )

    assert value["candidate_digest"] != ""


def test_boolean_only_frozen_pack_cannot_be_loaded():
    pack_value = {
        "schema_version": 1,
        "pack_id": "legacy-pack",
        "pack_version": "1.0.0",
        "entries": [{"knowledge_id": "knowledge-1", "detector_id": "probe"}],
        "scope": {"target_kinds": ["SKILL"]},
        "source_evidence_digest": "d" * 64,
        "shadow_replay_passed": True,
        "shadow_replay_digest": "e" * 64,
        "reviewed_by": "reviewer-1",
        "expires_at": None,
    }
    pack_value["pack_digest"] = pack_content_digest(pack_value)

    with pytest.raises(KnowledgeError, match="executed replay"):
        load_frozen_pack(
            run_pack_digest=str(pack_value["pack_digest"]),
            requested_pack=pack_value,
            target_kinds=["SKILL"],
        )


def test_nonempty_disjoint_split_is_required():
    identity = _pack_identity(pack_core())
    overlap = candidate(identity, held_out_case_ids=["train-1"])

    with pytest.raises(KnowledgeError, match="disjoint"):
        validate_candidate(overlap)

    empty = candidate(identity, validation_case_ids=[])
    with pytest.raises(KnowledgeError, match="non-empty"):
        validate_candidate(empty)


def test_candidate_metrics_are_computed_not_trusted():
    identity = _pack_identity(pack_core())
    forged = candidate(identity, precision=0.99)

    with pytest.raises(KnowledgeError, match="precision is not computable"):
        validate_candidate(forged)


def test_receipt_digest_and_execution_binding_are_verified():
    value, frozen_pack = _defaults()
    receipt = value["replay_evidence"]["receipts"]["MUTATION"]
    receipt["candidate_results"]["case-00"]["observed"] = "CLEAN"
    _resign_evidence(value)
    frozen_pack = pack(value)
    frozen_pack["replay_evidence"]["receipts"]["MUTATION"]["execution"][
        "candidate_digest"
    ] = "f" * 64
    frozen_pack["pack_digest"] = pack_content_digest(frozen_pack)

    with pytest.raises(KnowledgeError, match="receipt digest|execution"):
        load_frozen_pack(
            run_pack_digest=str(frozen_pack["pack_digest"]),
            requested_pack=frozen_pack,
            target_kinds=["SKILL"],
        )


def test_unresolved_requested_case_blocks_promotion():
    value, _ = _defaults()
    receipt = value["replay_evidence"]["receipts"]["SHADOW_REPLAY"]
    receipt["candidate_results"]["case-00"]["observed"] = "UNSCORED"
    _resign_evidence(value)

    with pytest.raises(KnowledgeError, match="resolved"):
        promote_pack(
            value,
            pack=pack(value),
            producer="agent-a",
            reviewer="reviewer-1",
        )


def test_coverage_decrease_blocks_promotion():
    value, _ = _defaults()
    receipt = value["replay_evidence"]["receipts"]["SHADOW_REPLAY"]
    receipt["coverage_after"] = ["static"]
    _resign_evidence(value)

    with pytest.raises(KnowledgeError, match="coverage"):
        promote_pack(
            value,
            pack=pack(value),
            producer="agent-a",
            reviewer="reviewer-1",
        )


def test_redaction_failure_blocks_promotion():
    value, _ = _defaults()
    receipt = value["replay_evidence"]["receipts"]["HISTORICAL_REPLAY"]
    receipt["redaction"]["status"] = "FAIL"
    receipt["redaction"]["secret_findings"] = 1
    _resign_evidence(value)

    with pytest.raises(KnowledgeError, match="redaction"):
        promote_pack(
            value,
            pack=pack(value),
            producer="agent-a",
            reviewer="reviewer-1",
        )


def test_stale_pack_identity_blocks_frozen_load():
    value, _ = _defaults()
    stale = pack(value, pack_id="pack-2")

    with pytest.raises(KnowledgeError, match="pack identity"):
        load_frozen_pack(
            run_pack_digest=str(stale["pack_digest"]),
            requested_pack=stale,
            target_kinds=["SKILL"],
        )


def test_review_receipt_is_bound_to_external_reviewer():
    _, frozen_pack = _defaults()
    review = frozen_pack["review_receipt"]
    review["reviewer"] = "reviewer-2"
    review["review_digest"] = canonical_digest(
        {key: item for key, item in review.items() if key != "review_digest"}
    )
    frozen_pack["pack_digest"] = pack_content_digest(frozen_pack)

    with pytest.raises(KnowledgeError, match="review receipt"):
        load_frozen_pack(
            run_pack_digest=str(frozen_pack["pack_digest"]),
            requested_pack=frozen_pack,
            target_kinds=["SKILL"],
        )


def test_valid_replay_receipts_can_be_promoted_and_loaded():
    value, frozen_pack = _defaults()

    active = promote_pack(
        value,
        pack=frozen_pack,
        producer="agent-a",
        reviewer="reviewer-1",
    )
    loaded = load_frozen_pack(
        run_pack_digest=str(frozen_pack["pack_digest"]),
        requested_pack=frozen_pack,
        target_kinds=["SKILL"],
    )

    assert active["status"] == "ACTIVE"
    assert active["source_evidence_digest"] == value["evidence_digest"]
    assert loaded["pack_digest"] == frozen_pack["pack_digest"]


def test_frozen_pack_accepts_rfc3339_z_timestamp():
    core = pack_core()
    core["expires_at"] = "2999-01-01T00:00:00Z"
    value, frozen_pack = _defaults(core)

    loaded = load_frozen_pack(
        run_pack_digest=str(frozen_pack["pack_digest"]),
        requested_pack=frozen_pack,
        target_kinds=["SKILL"],
    )

    assert loaded["pack_digest"] == frozen_pack["pack_digest"]
    assert value["candidate_id"] == "candidate-1"
