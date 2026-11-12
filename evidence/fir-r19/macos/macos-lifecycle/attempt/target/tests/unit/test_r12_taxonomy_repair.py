from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import detector_registry
from full_inspection_repair.adapters import build_required_sources, build_subject
from full_inspection_repair.contracts import ContractError
from full_inspection_repair.coverage import build_complete_coverage
from full_inspection_repair.detector_registry import default_taxonomy_coverage
from full_inspection_repair.impact import assert_impact_closed, build_impact_graph
from full_inspection_repair.taxonomy import DetectorSpec, build_taxonomy_coverage
from full_inspection_repair.taxonomy_qualification import qualify_taxonomy


def test_cache_files_are_enumerated_and_projected(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: cache-subject\n---\n", encoding="utf-8"
    )
    for directory in ("__pycache__", ".pytest_cache", ".ruff_cache"):
        (tmp_path / directory).mkdir()
    (tmp_path / "__pycache__" / "cached.pyc").write_bytes(b"\x00cache")
    (tmp_path / ".pytest_cache" / "state").write_bytes(b"\x00pytest")
    (tmp_path / ".ruff_cache" / "state").write_bytes(b"\x00ruff")

    subject = build_subject(tmp_path, "SKILL")
    sources = build_required_sources(subject)
    coverage = build_complete_coverage(
        {item.locator: item.content for item in subject.files}
    )

    expected = {
        ".pytest_cache/state",
        ".ruff_cache/state",
        "SKILL.md",
        "__pycache__/cached.pyc",
    }
    assert {item.locator for item in subject.files} == expected
    assert {item["locator"] for item in sources} == expected
    assert {item["path"] for item in coverage["binary_files"]} == {
        ".pytest_cache/state",
        ".ruff_cache/state",
        "__pycache__/cached.pyc",
    }
    assert all(
        item["projection"] == "raw-byte-hash-no-text-interpretation"
        for item in coverage["binary_files"]
    )


def test_taxonomy_bindings_are_executable_and_independent() -> None:
    bindings = detector_registry.executable_taxonomy_bindings("SKILL")
    coverage = default_taxonomy_coverage("SKILL")
    by_detector = {item.detector_id: item for item in bindings}

    bound_cells = [cell for cell in coverage["cells"] if cell["detector_ids"]]
    assert bound_cells
    for cell in bound_cells:
        for detector_id in cell["detector_ids"]:
            binding = by_detector[detector_id]
            assert callable(binding.detector)
            assert callable(binding.oracle)
            assert binding.detector is not binding.oracle
            assert detector_id == binding.detector_id
            assert cell["oracle_ids"] == [binding.oracle_id]
            evidence = {
                "id": binding.oracle_id,
                "passed": True,
                "observations": {
                    "category": binding.category_id,
                    "plane": binding.evidence_plane,
                },
            }
            assert binding.oracle(evidence) is True
            assert binding.oracle({**evidence, "id": "forged.oracle"}) is False


def test_qualification_rejects_legacy_alias_for_unbound_declared_ids() -> None:
    spec = DetectorSpec(
        detector_id="text.empty",
        detector_version="1.0.0",
        target_kinds=("SKILL",),
        category_id="FUNCTIONAL_FAULT",
        evidence_plane="STATIC",
        oracle_id="oracle.text.empty",
    )
    coverage = build_taxonomy_coverage(("SKILL",), (spec,))
    context = {
        "tree_digest": "a" * 64,
        "cell_evidence": {
            "FUNCTIONAL_FAULT:STATIC": {
                "subject_digest": "a" * 64,
                "detector": {
                    "id": "detector.functional_fault.static",
                    "passed": True,
                },
                "oracle": {
                    "id": "oracle.functional_fault.static",
                    "passed": True,
                },
            }
        },
    }

    report = qualify_taxonomy(coverage, context)
    target = next(
        item
        for item in report["cells"]
        if item["cell_id"] == "SKILL:FUNCTIONAL_FAULT:STATIC"
    )

    assert target["qualified"] is False


def test_qualification_requires_target_kind_qualified_evidence_key() -> None:
    coverage = default_taxonomy_coverage("SKILL")
    cell = next(item for item in coverage["cells"] if item["detector_ids"])
    legacy_evidence = {
        f"{cell['category_id']}:{cell['evidence_plane']}": {
            "subject_digest": "a" * 64,
            "detector": {
                "id": cell["detector_ids"][0],
                "passed": True,
                "observations": {
                    "category": cell["category_id"],
                    "plane": cell["evidence_plane"],
                },
            },
            "oracle": {
                "id": cell["oracle_ids"][0],
                "passed": True,
                "observations": {
                    "category": cell["category_id"],
                    "plane": cell["evidence_plane"],
                },
            },
        }
    }

    report = qualify_taxonomy(
        coverage,
        {
            "tree_digest": "a" * 64,
            "target_kinds": ["SKILL"],
            "cell_evidence": legacy_evidence,
        },
    )

    target = next(
        item
        for item in report["cells"]
        if item["cell_id"]
        == f"SKILL:{cell['category_id']}:{cell['evidence_plane']}"
    )
    assert target["qualified"] is False


def test_missing_markdown_link_is_an_explicit_unresolved_node(
    tmp_path: Path,
) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: link-subject\n---\n\n"
        "[missing](references/missing.md)\n",
        encoding="utf-8",
    )
    subject = build_subject(tmp_path, "SKILL")

    graph = build_impact_graph(subject, [])

    unresolved = [
        node for node in graph["nodes"] if node["kind"] == "UNRESOLVED_REFERENCE"
    ]
    assert len(unresolved) == 1
    assert unresolved[0]["locator"] == "references/missing.md"
    assert {
        "from": "file:SKILL.md",
        "to": unresolved[0]["id"],
        "kind": "UNRESOLVED_REFERENCE",
    } in graph["edges"]
    with pytest.raises(ContractError, match="unresolved reference"):
        assert_impact_closed(graph)
