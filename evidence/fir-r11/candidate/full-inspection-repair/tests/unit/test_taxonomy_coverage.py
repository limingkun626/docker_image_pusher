from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import (
    ContractError,
    validate_contract,
)
from full_inspection_repair.taxonomy import (
    CATEGORIES,
    EVIDENCE_PLANES,
    DetectorSpec,
    assert_taxonomy_complete,
    build_taxonomy_coverage,
)


def complete_skill_detectors():
    return [
        DetectorSpec(
            detector_id=f"detector.{category}.{plane}".lower(),
            detector_version="1.0.0",
            target_kinds=("SKILL",),
            category_id=category,
            evidence_plane=plane,
            oracle_id=f"oracle.{category}.{plane}".lower(),
        )
        for category in CATEGORIES
        for plane in EVIDENCE_PLANES
    ]


def test_taxonomy_builds_the_full_required_cross_product():
    coverage = build_taxonomy_coverage(("SKILL",), complete_skill_detectors())

    assert len(coverage["cells"]) == len(CATEGORIES) * len(EVIDENCE_PLANES)
    assert all(cell["status"] == "COVERED" for cell in coverage["cells"])
    validate_contract("defect-taxonomy", coverage)
    assert_taxonomy_complete(coverage, ("SKILL",))


def test_missing_taxonomy_cell_is_blocked():
    detectors = complete_skill_detectors()
    removed = detectors.pop()
    coverage = build_taxonomy_coverage(("SKILL",), detectors)

    missing = next(
        cell for cell in coverage["cells"] if cell["status"] == "UNCOVERED"
    )
    assert missing["category_id"] == removed.category_id
    assert missing["evidence_plane"] == removed.evidence_plane

    with pytest.raises(ContractError, match="taxonomy coverage"):
        assert_taxonomy_complete(coverage, ("SKILL",))
