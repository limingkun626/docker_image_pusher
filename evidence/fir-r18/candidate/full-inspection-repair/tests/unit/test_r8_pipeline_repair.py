from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import repair as repair_module
from full_inspection_repair.adapters import build_subject
from full_inspection_repair.repair import RepairBlocked, apply_batch


def _batch() -> dict[str, object]:
    return {
        "operations": [
            {
                "risk_id": "r8-newline",
                "operation_type": "APPEND_FINAL_NEWLINE",
                "target": "SKILL.md",
                "requires_manual_decision": False,
            }
        ],
        "batch_digest": "fixed-batch",
    }


def _source(tmp_path: Path):
    root = tmp_path / "source-skill"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo",
        encoding="utf-8",
    )
    return root, build_subject(root, "SKILL")


def test_repair_rejects_source_drift_before_copy(tmp_path: Path) -> None:
    source, subject = _source(tmp_path)
    candidate = tmp_path / "candidate"
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Changed",
        encoding="utf-8",
    )

    with pytest.raises(RepairBlocked, match="frozen source bytes changed"):
        apply_batch(subject, _batch(), candidate)

    assert not candidate.exists()


def test_repair_rechecks_frozen_source_before_accepting_candidate(
    tmp_path: Path, monkeypatch
) -> None:
    source, subject = _source(tmp_path)
    candidate = tmp_path / "candidate"
    real_copytree = repair_module.shutil.copytree

    def drifting_copy(src, dst, *args, **kwargs):
        result = real_copytree(src, dst, *args, **kwargs)
        (source / "SKILL.md").write_text(
            "---\nname: source-skill\n---\n\n# Drifted",
            encoding="utf-8",
        )
        return result

    monkeypatch.setattr(repair_module.shutil, "copytree", drifting_copy)

    with pytest.raises(RepairBlocked, match="post-copy acceptance"):
        apply_batch(subject, _batch(), candidate)

    assert not candidate.exists()
