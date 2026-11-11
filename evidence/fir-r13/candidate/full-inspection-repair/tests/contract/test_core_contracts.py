from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import (
    ContractError,
    assert_zero_open_risk,
    canonical_digest,
    schema_digest,
    validate_contract,
    validate_risk_ledger_consistency,
)

DIGEST = "a" * 64


def valid_finding(**overrides):
    finding = {
        "schema_version": 1,
        "risk_id": "finding-1",
        "invariant_id": "INV-001",
        "defect_class_id": "omission.resource",
        "taxonomy_category_id": "OMISSION",
        "subject_id": "skill:demo",
        "source_id": "source-1",
        "severity": "Low",
        "message": "A required script is absent.",
        "mechanism": "The manifest omits a referenced executable.",
        "affected_refs": ["scripts/run.py"],
        "root_cause_id": "root-1",
        "status": "OPEN",
        "evidence_refs": ["evidence/finding-1.json"],
        "evidence_sha256": DIGEST,
        "closed_by": None,
        "closed_at": None,
        "verification_check": None,
        "residual_risk": None,
    }
    finding.update(overrides)
    return finding


def valid_ledger(**overrides):
    ledger = {
        "schema_version": 1,
        "scope_digest": DIGEST,
        "finding_schema_digest": schema_digest("finding"),
        "risk_ledger_schema_digest": schema_digest("risk-ledger"),
        "required_sources": ["source-1"],
        "required_sources_digest": canonical_digest(["source-1"]),
        "observed_sources": ["source-1"],
        "items": [valid_finding()],
        "open_count": 1,
        "closed_count": 0,
        "missing_sources": [],
        "unexpected_sources": [],
        "residual_risks": [],
        "unresolved_ids": [],
    }
    ledger.update(overrides)
    ledger["ledger_digest"] = canonical_digest(ledger)
    return ledger


def test_canonical_digest_is_stable_across_key_order():
    left = {"b": [2, 1], "a": {"y": True, "x": None}}
    right = {"a": {"x": None, "y": True}, "b": [2, 1]}

    assert canonical_digest(left) == canonical_digest(right)


def test_finding_requires_declared_taxonomy_category():
    finding = valid_finding()
    finding.pop("taxonomy_category_id")

    with pytest.raises(ContractError, match="taxonomy_category_id"):
        validate_contract("finding", finding)


def test_issue_observation_requires_tri_state_and_hash_chain_fields():
    observation = {
        "schema_version": 2,
        "observation_id": "observation-1",
        "journal_sequence": 1,
        "previous_record_digest": None,
        "record_digest": DIGEST,
        "source_run_id": "run-1",
        "source_phase": "CHECK",
        "producer_id": "checker",
        "subject_id": "skill:demo",
        "subject_kind": "SKILL",
        "subject_digest": DIGEST,
        "invariant_id": "INV-001",
        "defect_class_id": "omission.resource",
        "taxonomy_category_id": "OMISSION",
        "fingerprint": "missing-resource",
        "fingerprint_version": "1.0.0",
        "message": "A required script is absent.",
        "mechanism": "The manifest omits a referenced executable.",
        "root_cause_hypothesis": None,
        "evidence_refs": ["evidence/finding-1.json"],
        "evidence_sha256": DIGEST,
        "redaction_policy_digest": DIGEST,
        "severity": "Low",
        "analogous_surfaces": [],
        "status": "CONFIRMED",
        "safe_feedback": "Check referenced executables against the manifest.",
        "recorded_at": "2026-11-07T12:00:00Z",
    }
    observation["source_phase"] = "REVIEW"
    validate_contract("issue-observation", observation)
    observation["confirmed"] = True
    observation.pop("status")

    with pytest.raises(ContractError, match="status|confirmed"):
        validate_contract("issue-observation", observation)


def test_defect_taxonomy_requires_every_named_category():
    taxonomy = {
        "schema_version": 1,
        "taxonomy_id": "inspection-closure.defect-taxonomy",
        "taxonomy_version": "1.0.0",
        "categories": ["FUNCTIONAL_FAULT", "OMISSION"],
        "target_kinds": ["SKILL"],
        "evidence_planes": ["STATIC"],
        "cells": [
            {
                "target_kind": "SKILL",
                "category_id": "OMISSION",
                "evidence_plane": "STATIC",
                "detector_ids": ["detector.omission"],
                "oracle_ids": ["oracle.manifest"],
                "not_applicable_proof": None,
                "status": "COVERED",
            }
        ],
        "coverage_digest": DIGEST,
    }

    with pytest.raises(ContractError, match="missing taxonomy categories"):
        validate_contract("defect-taxonomy", taxonomy)


def test_risk_ledger_rejects_inconsistent_open_count():
    material = valid_ledger()
    material["open_count"] = 0
    ledger = valid_ledger(
        open_count=0,
        ledger_digest=canonical_digest(
            {key: value for key, value in material.items() if key != "ledger_digest"}
        ),
    )

    with pytest.raises(ContractError, match="open_count"):
        validate_risk_ledger_consistency(ledger)


def test_zero_open_risk_rejects_open_low_even_without_residual_risk():
    ledger = valid_ledger()
    ledger["items"][0]["severity"] = "Low"
    ledger["residual_risks"] = []

    with pytest.raises(ContractError, match="open findings"):
        assert_zero_open_risk(ledger)


def test_zero_open_risk_accepts_only_evidence_backed_closure():
    closed = valid_finding(
        status="FIXED",
        closed_by=DIGEST,
        closed_at="2026-11-07T12:01:00Z",
        verification_check="test:manifest",
        evidence_refs=[f"candidate:{DIGEST}"],
    )
    ledger = valid_ledger(items=[closed], open_count=0, closed_count=1)

    assert_zero_open_risk(copy.deepcopy(ledger))
