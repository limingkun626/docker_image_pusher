from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.detector_registry import default_taxonomy_coverage
from full_inspection_repair.taxonomy import (
    assert_taxonomy_complete,
    validate_not_applicable_proof,
)


def test_default_skill_taxonomy_is_complete():
    coverage = default_taxonomy_coverage("SKILL")

    assert_taxonomy_complete(coverage, ("SKILL",))
    assert any(cell["detector_ids"] for cell in coverage["cells"])
    assert len(coverage["cells"]) == 72
    assert all(cell["status"] == "COVERED" for cell in coverage["cells"])
    for cell in coverage["cells"]:
        if cell["detector_ids"]:
            assert cell["oracle_ids"]
            assert not any(
                item.startswith(("detector.cell.", "oracle.cell."))
                for item in (*cell["detector_ids"], *cell["oracle_ids"])
            )
        else:
            validate_not_applicable_proof(
                cell["not_applicable_proof"],
                target_kind=cell["target_kind"],
                category_id=cell["category_id"],
                evidence_plane=cell["evidence_plane"],
            )
