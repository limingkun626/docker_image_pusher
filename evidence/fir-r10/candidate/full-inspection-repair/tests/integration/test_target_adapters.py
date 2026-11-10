from __future__ import annotations

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
    assert subject.tree_digest != "0" * 64


def test_unknown_target_kind_is_rejected(tmp_path):
    (tmp_path / "thing.txt").write_text("content\n", encoding="utf-8")

    with pytest.raises(AdapterError, match="unsupported target kind"):
        build_subject(tmp_path, "UNKNOWN")
