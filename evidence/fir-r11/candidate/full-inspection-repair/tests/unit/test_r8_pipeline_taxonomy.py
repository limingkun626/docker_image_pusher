from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import ContractError, canonical_digest
from full_inspection_repair.detector_registry import (
    POLICY_PATH,
    default_taxonomy_coverage,
)
from full_inspection_repair.taxonomy import (
    assert_taxonomy_complete,
    validate_not_applicable_proof,
)
from full_inspection_repair.taxonomy_qualification import qualify_taxonomy


def _context(coverage: dict[str, object]) -> dict[str, object]:
    evidence = {}
    for cell in coverage["cells"]:
        classifier = str(cell["category_id"])
        plane = str(cell["evidence_plane"])
        detector_ids = list(cell["detector_ids"])
        oracle_ids = list(cell["oracle_ids"])
        evidence[f"{classifier}:{plane}"] = {
            "subject_digest": "a" * 64,
            "detector": {
                "id": detector_ids[0] if detector_ids else "policy-proof",
                "passed": bool(detector_ids),
                "observations": {"category": classifier, "plane": plane},
            },
            "oracle": {
                "id": oracle_ids[0] if oracle_ids else "policy-proof",
                "passed": bool(oracle_ids),
                "observations": {"category": classifier, "plane": plane},
            },
        }
    return {"tree_digest": "a" * 64, "cell_evidence": evidence}


def test_default_taxonomy_uses_real_bindings_and_policy_bound_proofs() -> None:
    coverage = default_taxonomy_coverage("SKILL")
    policy_digest = hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest()
    synthetic = []
    proof_count = 0
    for cell in coverage["cells"]:
        identifiers = [*cell["detector_ids"], *cell["oracle_ids"]]
        synthetic.extend(
            identifier
            for identifier in identifiers
            if identifier.startswith(("detector.cell.", "oracle.cell."))
        )
        if cell["not_applicable_proof"]:
            proof_count += 1
            proof = validate_not_applicable_proof(
                cell["not_applicable_proof"],
                target_kind=cell["target_kind"],
                category_id=cell["category_id"],
                evidence_plane=cell["evidence_plane"],
            )
            assert proof["policy_digest"] == policy_digest
            assert proof["evidence_refs"]

    assert synthetic == []
    assert proof_count > 0
    assert all(cell["status"] == "COVERED" for cell in coverage["cells"])
    assert_taxonomy_complete(coverage, ("SKILL",))


def test_taxonomy_qualification_binds_declared_ids() -> None:
    coverage = default_taxonomy_coverage("SKILL")
    context = _context(coverage)

    report = qualify_taxonomy(coverage, context)

    assert report["all_passed"] is True
    assert report["control_count"] == 720
    assert report["qualified_count"] == 72
    for cell, qualified in zip(coverage["cells"], report["cells"]):
        expected_detector = (
            cell["detector_ids"][0] if cell["detector_ids"] else "NOT_APPLICABLE"
        )
        assert qualified["detector_id"] == expected_detector
        assert qualified["detector_ids"] == cell["detector_ids"]
        assert qualified["binding_digest"]

    tampered = copy.deepcopy(context)
    bound_cell = next(
        cell for cell in coverage["cells"] if cell["detector_ids"]
    )
    cell_id = f"{bound_cell['category_id']}:{bound_cell['evidence_plane']}"
    tampered["cell_evidence"][cell_id]["detector"]["id"] = "rogue.detector"

    report = qualify_taxonomy(coverage, tampered)

    failed = next(
        cell for cell in report["cells"] if cell["cell_id"] == f"SKILL:{cell_id}"
    )
    assert failed["qualified"] is False
    assert report["all_passed"] is False


def test_not_applicable_proof_must_stay_bound_to_its_cell() -> None:
    coverage = default_taxonomy_coverage("SKILL")
    proof_cell = next(
        cell for cell in coverage["cells"] if cell["not_applicable_proof"]
    )
    proof = json.loads(proof_cell["not_applicable_proof"])
    proof["category_id"] = "VULNERABILITY"
    proof_cell["not_applicable_proof"] = json.dumps(
        proof, sort_keys=True, separators=(",", ":")
    )
    coverage["coverage_digest"] = canonical_digest(
        {key: value for key, value in coverage.items() if key != "coverage_digest"}
    )

    with pytest.raises(ContractError, match="taxonomy coverage incomplete"):
        assert_taxonomy_complete(coverage, ("SKILL",))


def test_not_applicable_proof_must_stay_bound_to_active_policy() -> None:
    coverage = default_taxonomy_coverage("SKILL")
    proof_cell = next(
        cell for cell in coverage["cells"] if cell["not_applicable_proof"]
    )
    proof = json.loads(proof_cell["not_applicable_proof"])
    proof["policy_digest"] = "0" * 64
    proof.pop("evidence_digest")
    proof["evidence_digest"] = canonical_digest(proof)
    proof_cell["not_applicable_proof"] = json.dumps(
        proof, sort_keys=True, separators=(",", ":")
    )
    coverage["coverage_digest"] = canonical_digest(
        {key: value for key, value in coverage.items() if key != "coverage_digest"}
    )

    with pytest.raises(ContractError, match="taxonomy coverage incomplete"):
        assert_taxonomy_complete(coverage, ("SKILL",))
