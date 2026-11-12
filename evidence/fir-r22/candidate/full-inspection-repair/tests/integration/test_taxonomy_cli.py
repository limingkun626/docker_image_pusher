from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.cli import main
from full_inspection_repair.taxonomy import assert_taxonomy_complete


def test_build_taxonomy_cli_writes_complete_coverage(tmp_path):
    output = tmp_path / "taxonomy.json"

    exit_code = main(
        [
            "build-taxonomy",
            "--kind",
            "SKILL",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    coverage = json.loads(output.read_text(encoding="utf-8"))
    assert_taxonomy_complete(coverage, ("SKILL",))


@pytest.mark.parametrize("kind", ["PLAN", "ARTICLE", "PROJECT", "OTHER"])
def test_build_taxonomy_cli_covers_every_target_kind(tmp_path, kind):
    output = tmp_path / f"{kind.lower()}-taxonomy.json"

    exit_code = main(
        ["build-taxonomy", "--kind", kind, "--output", str(output)]
    )

    assert exit_code == 0
    coverage = json.loads(output.read_text(encoding="utf-8"))
    assert_taxonomy_complete(coverage, (kind,))


def test_check_uses_default_taxonomy_when_not_supplied(tmp_path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\nTODO\n",
        encoding="utf-8",
    )
    output = tmp_path / "check-run"

    exit_code = main(
        ["check", "--target", str(source), "--kind", "SKILL", "--output", str(output)]
    )

    assert exit_code == 0
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "CHECKED"
