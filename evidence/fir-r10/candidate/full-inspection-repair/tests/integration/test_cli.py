from __future__ import annotations

import json
import sys
from importlib.machinery import PathFinder
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.cli import main
from full_inspection_repair.observation import ObservationJournal
from full_inspection_repair.taxonomy import (
    CATEGORIES,
    EVIDENCE_PLANES,
    DetectorSpec,
    build_taxonomy_coverage,
)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_scripts_path_does_not_shadow_stdlib_inspect():
    spec = PathFinder.find_spec("inspect", [str(ROOT / "scripts")])

    assert spec is None


def write_taxonomy(path: Path) -> Path:
    specs = [
        DetectorSpec(
            detector_id=f"fixture.{category}.{plane}".lower(),
            detector_version="1.0.0",
            target_kinds=("SKILL",),
            category_id=category,
            evidence_plane=plane,
            oracle_id=f"fixture-oracle.{category}.{plane}".lower(),
        )
        for category in CATEGORIES
        for plane in EVIDENCE_PLANES
    ]
    coverage = build_taxonomy_coverage(("SKILL",), specs)
    path.write_text(json.dumps(coverage), encoding="utf-8")
    return path


def test_check_writes_issue_ledger_and_observation_journal(tmp_path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\nTODO\n",
        encoding="utf-8",
    )
    output = tmp_path / "check-run"
    taxonomy = write_taxonomy(tmp_path / "taxonomy.json")

    exit_code = main(
        [
            "check",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(output),
            "--taxonomy",
            str(taxonomy),
        ]
    )

    assert exit_code == 0
    summary = read_json(output / "summary.json")
    ledger = read_json(output / "risk-ledger.json")
    assert summary["status"] == "CHECKED"
    assert ledger["open_count"] == 1
    assert (output / "impact-graph.json").exists()
    assert ObservationJournal(output / "observations.jsonl").verify() == 1


def test_repair_builds_candidate_without_modifying_source(tmp_path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo",
        encoding="utf-8",
    )
    output = tmp_path / "repair-run"
    candidate = tmp_path / "candidate" / "source-skill"
    taxonomy = write_taxonomy(tmp_path / "taxonomy.json")

    exit_code = main(
        [
            "repair",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(output),
            "--candidate",
            str(candidate),
            "--taxonomy",
            str(taxonomy),
        ]
    )

    assert exit_code == 0
    summary = read_json(output / "summary.json")
    assert summary["status"] == "REPAIRED_CANDIDATE"
    assert (source / "SKILL.md").read_bytes().endswith(b"# Demo")
    assert (candidate / "SKILL.md").read_bytes().endswith(b"# Demo\n")


def test_repair_blocks_manual_decision_before_creating_candidate(tmp_path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\nTODO\n",
        encoding="utf-8",
    )
    output = tmp_path / "repair-run"
    candidate = tmp_path / "candidate" / "source-skill"
    taxonomy = write_taxonomy(tmp_path / "taxonomy.json")

    exit_code = main(
        [
            "repair",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(output),
            "--candidate",
            str(candidate),
            "--taxonomy",
            str(taxonomy),
        ]
    )

    assert exit_code == 2
    summary = read_json(output / "summary.json")
    assert summary["status"] == "BLOCKED_REPAIR_PLAN"
    assert not candidate.exists()
