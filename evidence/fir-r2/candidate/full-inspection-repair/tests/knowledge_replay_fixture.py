from __future__ import annotations

from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.knowledge import pack_content_digest

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
        if expected == observed == "DETECT":
            counters["true_positives"] += 1
        elif expected == "CLEAN" and observed == "DETECT":
            counters["false_positives"] += 1
        elif expected == observed == "CLEAN":
            counters["true_negatives"] += 1
        else:
            counters["false_negatives"] += 1
    return counters


def _cases() -> tuple[list[str], dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    case_ids = [f"case-{index:02d}" for index in range(20)]
    baseline = {}
    candidate = {}
    for index, case_id in enumerate(case_ids):
        expected = "DETECT" if index < 18 else "CLEAN"
        baseline[case_id] = {
            "expected": expected,
            "observed": "CLEAN" if expected == "DETECT" else "DETECT",
        }
        candidate[case_id] = {"expected": expected, "observed": expected}
    return case_ids, baseline, candidate


def _receipt(
    kind: str, *, candidate_digest: str, pack_identity: str
) -> dict[str, object]:
    case_ids, baseline, candidate = _cases()
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
        "baseline_results": baseline,
        "candidate_results": candidate,
        "baseline_counters": _counters(baseline),
        "candidate_counters": _counters(candidate),
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


def _pack_core() -> dict[str, object]:
    return {
        "schema_version": 1,
        "pack_id": "pack-1",
        "pack_version": "1.0.0",
        "entries": [{"knowledge_id": "knowledge-1", "detector_id": "probe"}],
        "scope": {"target_kinds": ["SKILL"]},
        "expires_at": None,
    }


def _candidate(identity: str) -> dict[str, object]:
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
    candidate_digest = canonical_digest(core)
    replay = {
        "schema_version": 1,
        "corpus_digest": CORPUS_DIGEST,
        "candidate": core,
        "receipts": {
            kind: _receipt(
                kind,
                candidate_digest=candidate_digest,
                pack_identity=identity,
            )
            for kind in ("MUTATION", "HISTORICAL_REPLAY", "SHADOW_REPLAY")
        },
    }
    return {
        **core,
        "candidate_digest": candidate_digest,
        "replay_evidence": replay,
        "evidence_digest": canonical_digest(replay),
    }


def valid_knowledge_pack() -> tuple[dict[str, object], dict[str, object]]:
    core = _pack_core()
    identity = canonical_digest(core)
    candidate = _candidate(identity)
    review = {
        "schema_version": 1,
        "reviewer": "reviewer-1",
        "status": "APPROVED",
        "candidate_digest": candidate["candidate_digest"],
        "source_evidence_digest": candidate["evidence_digest"],
        "reviewed_at": "2026-11-11T00:02:00Z",
    }
    review["review_digest"] = canonical_digest(review)
    pack: dict[str, object] = {
        **core,
        "candidate_digest": candidate["candidate_digest"],
        "source_evidence_digest": candidate["evidence_digest"],
        "replay_evidence": candidate["replay_evidence"],
        "reviewed_by": "reviewer-1",
        "review_receipt": review,
    }
    pack["pack_digest"] = pack_content_digest(pack)
    return candidate, pack


def resign_pack(pack: dict[str, object]) -> dict[str, object]:
    result = dict(pack)
    result.pop("pack_digest", None)
    result["pack_digest"] = pack_content_digest(result)
    return result
