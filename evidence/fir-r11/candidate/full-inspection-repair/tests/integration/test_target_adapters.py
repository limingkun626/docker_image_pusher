from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.adapters import (
    AdapterError,
    build_required_sources,
    build_subject,
)
from full_inspection_repair.cli import main
from full_inspection_repair.contracts import validate_contract


def test_skill_subject_inventory_is_complete_and_excludes_runtime_caches(tmp_path):
    (tmp_path / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    (tmp_path / "references").mkdir()
    (tmp_path / "references" / "guide.md").write_text("guide\n", encoding="utf-8")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "cached.pyc").write_bytes(b"cache")

    subject = build_subject(tmp_path, "SKILL")
    sources = build_required_sources(subject)

    assert [item.locator for item in subject.files] == [
        "SKILL.md",
        "references/guide.md",
    ]
    assert [item["source_id"] for item in sources] == [
        "source:SKILL.md",
        "source:references/guide.md",
    ]
    for source in sources:
        validate_contract("required-source", source)
    assert subject.tree_digest != "0" * 64


def test_unknown_target_kind_is_rejected(tmp_path):
    (tmp_path / "thing.txt").write_text("content\n", encoding="utf-8")

    with pytest.raises(AdapterError, match="unsupported target kind"):
        build_subject(tmp_path, "UNKNOWN")


@pytest.mark.parametrize("kind", ["PLAN", "ARTICLE", "PROJECT", "OTHER"])
def test_unreleased_target_adapter_cannot_build_required_sources(tmp_path, kind):
    (tmp_path / "content.md").write_text("# Content\n", encoding="utf-8")

    subject = build_subject(tmp_path, kind)

    with pytest.raises(AdapterError, match="no released target-specific adapter"):
        build_required_sources(subject)


def test_check_blocks_unreleased_adapter_without_test_rewrite(tmp_path):
    source = tmp_path / "plan"
    source.mkdir()
    (source / "plan.md").write_text("# Plan\n", encoding="utf-8")
    output = tmp_path / "run"

    exit_code = main(
        ["check", "--target", str(source), "--kind", "PLAN", "--output", str(output)]
    )

    assert exit_code == 2
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "BLOCKED_ADAPTER"


def test_missing_skill_source_is_schema_valid_and_blocks_observation(tmp_path):
    (tmp_path / "references").mkdir()
    (tmp_path / "references" / "guide.md").write_text("guide\n", encoding="utf-8")

    subject = build_subject(tmp_path, "SKILL")
    sources = build_required_sources(subject)
    missing = next(item for item in sources if item["locator"] == "SKILL.md")

    validate_contract("required-source", missing)
    assert missing["applicability"] == "REQUIRED_MISSING"
    assert missing["source_id"] not in {
        f"source:{item.locator}" for item in subject.files
    }
