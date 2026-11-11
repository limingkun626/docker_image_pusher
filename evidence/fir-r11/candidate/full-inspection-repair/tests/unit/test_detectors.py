from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.adapters import SourceFile, build_subject
from full_inspection_repair.detectors import run_default_detectors


def test_default_detectors_collect_all_basic_skill_issues(tmp_path):
    skill_root = tmp_path / "demo-skill"
    skill_root.mkdir()
    (skill_root / "SKILL.md").write_text(
        "---\nname: wrong-name\n---\n\n# Demo\nTODO",
        encoding="utf-8",
    )
    subject = build_subject(skill_root, "SKILL")

    results = run_default_detectors(subject)
    findings = [finding for result in results for finding in result.findings]

    assert {result.detector_id for result in results if result.status == "FINDINGS"} == {
        "skill.frontmatter-name",
        "text.final-newline",
        "text.placeholder",
    }
    assert all(finding["taxonomy_category_id"] for finding in findings)
    assert all(finding["severity"] for finding in findings)


def test_generic_detectors_cover_remaining_taxonomy_categories(tmp_path):
    skill_root = tmp_path / "demo-skill"
    skill_root.mkdir()
    (skill_root / "SKILL.md").write_text(
        "---\nname: demo-skill\n---\n\nFIXME\n",
        encoding="utf-8",
    )
    (skill_root / "empty.md").write_text("", encoding="utf-8")
    (skill_root / "bad.txt").write_bytes(b"\xff\xfe")
    (skill_root / "code.py").write_text(
        "def run(user_input):\n"
        "    try:\n"
        "        eval(user_input)\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8",
    )
    subject = build_subject(skill_root, "SKILL")
    subject = replace(
        subject,
        files=(
            *subject.files,
            SourceFile(
                locator="large.log",
                absolute_path=skill_root / "large.log",
                size=1024 * 1024 + 1,
                sha256="0" * 64,
                content=b"",
                metadata={},
            ),
        ),
    )

    results = run_default_detectors(subject)
    categories = {
        finding["taxonomy_category_id"]
        for result in results
        for finding in result.findings
    }

    assert {
        "FUNCTIONAL_FAULT",
        "RISK_EXPOSURE",
        "LATENT_DEFECT",
        "VULNERABILITY",
        "BOUNDARY",
        "EXCEPTION_PATH",
    }.issubset(categories)


def test_python_scanner_ignores_literal_pattern_examples(tmp_path):
    skill_root = tmp_path / "demo-skill"
    skill_root.mkdir()
    (skill_root / "SKILL.md").write_text(
        "---\nname: demo-skill\n---\n\n# Demo\n",
        encoding="utf-8",
    )
    (skill_root / "safe.py").write_text(
        "EXAMPLES = ['eval(', 'BEGIN PRIVATE KEY', 'FIXME', 'TODO']\n",
        encoding="utf-8",
    )
    subject = build_subject(skill_root, "SKILL")

    results = run_default_detectors(subject)
    findings = [finding for result in results for finding in result.findings]

    assert findings == []
