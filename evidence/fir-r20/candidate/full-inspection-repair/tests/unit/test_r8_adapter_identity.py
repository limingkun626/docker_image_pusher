from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.adapters import AdapterError, build_subject


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink-root fixture")
def test_adapter_rejects_symlink_root_before_reading_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(AdapterError, match="protected target snapshot failed"):
        build_subject(link, "SKILL")
