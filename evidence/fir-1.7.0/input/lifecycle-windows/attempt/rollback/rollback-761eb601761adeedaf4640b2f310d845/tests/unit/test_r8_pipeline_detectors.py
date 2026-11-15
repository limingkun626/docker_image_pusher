from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.adapters import build_subject
from full_inspection_repair.detectors import (
    detect_skill_frontmatter_name,
    run_default_detectors,
    run_detectors,
)


def _slow_detector(subject):
    time.sleep(10.0)
    return ()


def _fast_detector(subject):
    return ()


def _subject(tmp_path: Path, text: str):
    root = tmp_path / "demo-skill"
    root.mkdir()
    (root / "SKILL.md").write_text(text, encoding="utf-8")
    return build_subject(root, "SKILL")


def test_detector_deadline_blocks_hung_worker_and_continues(tmp_path: Path) -> None:
    subject = _subject(
        tmp_path,
        "---\nname: demo-skill\n---\n\n# Demo\n",
    )

    results = run_detectors(
        subject,
        (
            ("slow", "LATENT_DEFECT", "RUNTIME", _slow_detector),
            ("fast", "FUNCTIONAL_FAULT", "STATIC", _fast_detector),
        ),
        timeout_seconds=5.0,
    )

    assert results[0].status == "BLOCKED"
    assert "DeadlineExceeded" in str(results[0].error)
    assert results[1].status == "PASS"


def test_all_marker_occurrences_are_preserved(tmp_path: Path) -> None:
    subject = _subject(
        tmp_path,
        "---\nname: demo-skill\n---\n\nTODO one\nTODO two\nFIXME\nHACK\n",
    )
    (subject.root / "code.py").write_text(
        "eval('1 + 1')\n"
        "eval('2 + 2')\n",
        encoding="utf-8",
    )
    subject = build_subject(subject.root, "SKILL")

    findings = [
        finding
        for result in run_default_detectors(subject)
        for finding in result.findings
    ]

    assert sum(
        item["invariant_id"] == "CONTENT-PLACEHOLDER-001" for item in findings
    ) == 2
    assert sum(
        item["invariant_id"] == "CONTENT-LATENT-MARKER-001" for item in findings
    ) == 2
    assert sum(
        item["invariant_id"] == "SECURITY-DANGEROUS-PATTERN-001"
        for item in findings
    ) == 2


@pytest.mark.parametrize(
    "text",
    (
        "# no frontmatter\n",
        "---\nname: demo-skill\n",
        "---\nname: [unterminated\n---\n",
        "---\nname: 42\n---\n",
        "---\ndescription: no name\n---\n",
    ),
)
def test_missing_or_malformed_skill_frontmatter_is_finding(
    tmp_path: Path, text: str
) -> None:
    subject = _subject(tmp_path, text)

    findings = detect_skill_frontmatter_name(subject)

    assert findings
    assert all(
        finding["defect_class_id"].startswith("skill.frontmatter.")
        for finding in findings
    )
