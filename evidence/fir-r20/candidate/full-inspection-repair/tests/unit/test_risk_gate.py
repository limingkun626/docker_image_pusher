from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.coverage import build_complete_coverage
from full_inspection_repair.risk_gate import REQUIRED_DOMAINS, assess_release_gate

CANDIDATE = "c" * 64
SCOPE = "b" * 64
VERIFICATION = "d" * 64
EVALUATOR = "f" * 64
LEDGER = "e" * 64


def domains() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for dotted, status in REQUIRED_DOMAINS.items():
        group, key = dotted.split(".")
        result.setdefault(group, {})[key] = status
    return result


def finding() -> dict[str, object]:
    return {
        "finding_id": "F-1",
        "status": "FIXED",
        "impact": "NO_OBSERVED_EFFECT",
        "impact_proof": "negative-control.json",
        "verification_evidence": "test-risk-gate",
    }


def review() -> dict[str, object]:
    return {
        "verdict": "PASS",
        "open_count": 0,
        "residual_risks": [],
        "limitations": [],
        "unverified_claims": [],
        "not_run": [],
        "non_blocking_observations": [],
        "findings": [finding()],
        "scope_digest": SCOPE,
        "candidate_digest": CANDIDATE,
        "verification_digest": VERIFICATION,
        "ledger_digest": LEDGER,
        "evaluator_digest": EVALUATOR,
    }


def matrix(value_review: dict[str, object] | None = None) -> dict[str, object]:
    coverage = build_complete_coverage({"SKILL.md": b"# Demo.\n"})
    value_review = value_review or review()
    result: dict[str, object] = {
        "schema_version": 1,
        "status": "PASS",
        "failed_count": 0,
        "scope_digest": SCOPE,
        "candidate_digest": CANDIDATE,
        "verification_digest": VERIFICATION,
        "evaluator_digest": EVALUATOR,
        "coverage_digest": coverage["coverage_digest"],
        "domains_digest": canonical_digest(domains()),
    }
    result["matrix_digest"] = canonical_digest(result)
    value_review["matrix_digest"] = result["matrix_digest"]
    return result


def gate_inputs() -> dict[str, object]:
    value_review = review()
    value_matrix = matrix(value_review)
    return {
        "findings": [finding()],
        "review": value_review,
        "domains": domains(),
        "coverage": build_complete_coverage({"SKILL.md": b"# Demo.\n"}),
        "matrix": value_matrix,
        "expected_candidate_digest": CANDIDATE,
        "expected_scope_digest": SCOPE,
        "expected_verification_digest": VERIFICATION,
    }


def test_complete_gate_passes_only_with_all_domains_closed() -> None:
    gate = assess_release_gate(**gate_inputs())

    assert gate["status"] == "PASS"
    assert gate["release_ready"] is True
    assert gate["blockers"] == []


def test_platform_support_requires_all_released_platforms() -> None:
    platform_domains = {
        name for name in REQUIRED_DOMAINS if name.startswith("platform_support.")
    }

    assert platform_domains == {
        "platform_support.windows_install",
        "platform_support.linux_install",
        "platform_support.macos_install",
    }


def test_caller_supplied_pass_gate_is_ignored() -> None:
    inputs = gate_inputs()
    inputs["findings"][0]["status"] = "OPEN"
    inputs["review"]["findings"][0]["status"] = "OPEN"
    inputs["review"]["risk_gate"] = {
        "status": "PASS",
        "release_ready": True,
        "gate_digest": "f" * 64,
    }

    gate = assess_release_gate(**inputs)

    assert gate["release_ready"] is False
    assert any(item.startswith("NONTERMINAL_FINDINGS:") for item in gate["blockers"])


def test_review_limitations_cannot_be_hidden_by_empty_residual_list() -> None:
    inputs = gate_inputs()
    inputs["review"]["limitations"] = ["POSIX not run"]
    gate = assess_release_gate(**inputs)

    assert gate["release_ready"] is False
    assert "REVIEW_FIELD:limitations" in gate["blockers"]


def test_unsupported_claims_and_forged_coverage_counts_are_blocked() -> None:
    inputs = gate_inputs()
    inputs["review"]["accepted_risks"] = [{"finding_id": "F-1"}]
    inputs["coverage"]["uncovered"] = [{"path": "SKILL.md"}]

    gate = assess_release_gate(**inputs)

    assert "REVIEW_FIELD:accepted_risks" in gate["blockers"]
    assert "COVERAGE_UNCOVERED_RAW" in gate["blockers"]
    assert "COVERAGE_UNCOVERED_COUNT" in gate["blockers"]


def test_review_ledger_projection_must_be_exact() -> None:
    inputs = gate_inputs()
    inputs["review"]["findings"] = []
    gate = assess_release_gate(**inputs)

    assert "REVIEW_LEDGER_PROJECTION_DEFECT" in gate["blockers"]


def test_missing_trust_root_blocks_release() -> None:
    inputs = gate_inputs()
    inputs["domains"]["trust"]["external_trust_root"] = "UNVERIFIED"
    gate = assess_release_gate(**inputs)

    assert gate["release_ready"] is False
    assert "DOMAIN:trust.external_trust_root:UNVERIFIED" in gate["blockers"]


def test_review_status_substitution_is_rejected() -> None:
    inputs = gate_inputs()
    inputs["review"]["findings"][0]["status"] = "FALSE_POSITIVE_WITH_PROOF"
    gate = assess_release_gate(**inputs)

    assert gate["release_ready"] is False
    assert "REVIEW_LEDGER_PROJECTION_DEFECT" in gate["blockers"]


def test_matrix_and_review_must_bind_the_expected_candidate() -> None:
    inputs = gate_inputs()
    inputs["review"]["candidate_digest"] = "a" * 64
    inputs["matrix"]["candidate_digest"] = "a" * 64
    gate = assess_release_gate(**inputs)

    assert gate["release_ready"] is False
    assert "MATRIX_CANDIDATE_MISMATCH" in gate["blockers"]
    assert "REVIEW_CANDIDATE_MISMATCH" in gate["blockers"]


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("review_candidate", "REVIEW_CANDIDATE_MISMATCH"),
        ("matrix_digest", "MATRIX_DIGEST"),
        ("scope_digest", "MATRIX_SCOPE_MISMATCH"),
        ("verification_digest", "MATRIX_VERIFICATION_MISMATCH"),
        ("evaluator_digest", "MATRIX_EVALUATOR_MISMATCH"),
        ("coverage_digest", "MATRIX_COVERAGE_MISMATCH"),
        ("domains_digest", "MATRIX_DOMAINS_MISMATCH"),
        ("findings_status", "REVIEW_LEDGER_PROJECTION_DEFECT"),
    ],
)
def test_eight_raw_evaluator_tamper_cases(case: str, expected: str) -> None:
    inputs = copy.deepcopy(gate_inputs())
    if case == "review_candidate":
        inputs["review"]["candidate_digest"] = "a" * 64
    elif case == "matrix_digest":
        inputs["matrix"]["matrix_digest"] = "a" * 64
    elif case == "scope_digest":
        inputs["matrix"]["scope_digest"] = "a" * 64
    elif case == "verification_digest":
        inputs["matrix"]["verification_digest"] = "a" * 64
    elif case == "evaluator_digest":
        inputs["matrix"]["evaluator_digest"] = "a" * 64
    elif case == "coverage_digest":
        inputs["matrix"]["coverage_digest"] = "a" * 64
    elif case == "domains_digest":
        inputs["matrix"]["domains_digest"] = "a" * 64
    elif case == "findings_status":
        inputs["review"]["findings"][0]["status"] = "OPEN"

    gate = assess_release_gate(**inputs)

    assert gate["release_ready"] is False
    assert expected in gate["blockers"]
