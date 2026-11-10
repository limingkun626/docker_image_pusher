from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.coverage import (
    build_complete_coverage,
    verify_complete_coverage,
)


def test_cr_only_and_mixed_newline_evidence_is_exact() -> None:
    report = build_complete_coverage({"SKILL.md": b"One, two.\rThree, four!\r\n"})
    record = report["files"][0]

    assert record["newline_style"] == "MIXED"
    assert record["line_count"] == 2
    assert {item["line"] for item in report["punctuation"]} == {1, 2}
    assert record["sentence_covered_codepoints"] == record["codepoint_count"]
    assert report["gap_count"] == 0

    cr_only = build_complete_coverage({"SKILL.md": b"One.\rTwo.\r"})
    assert cr_only["files"][0]["newline_style"] == "CR"
    assert cr_only["files"][0]["line_count"] == 2
    units = cr_only["files"][0]["sentence_units"]
    assert units[0]["codepoint_start"] == 0
    assert units[0]["codepoint_end_exclusive"] == 4
    assert units[2]["codepoint_start"] == 5


def test_cjk_terminal_punctuation_creates_sentence_units_without_spaces() -> None:
    report = build_complete_coverage(
        {"SKILL.md": "第一句。第二句！第三句？".encode()}
    )
    units = report["files"][0]["sentence_units"]

    assert len(units) == 3
    assert [unit["codepoint_end_exclusive"] for unit in units] == [4, 8, 12]
    assert report["files"][0]["sentence_covered_codepoints"] == 12


def test_coverage_schema_version_is_bound_to_the_digest() -> None:
    content = {"SKILL.md": b"# Demo.\n"}
    report = build_complete_coverage(content)
    tampered = copy.deepcopy(report)
    tampered["schema_version"] = 2

    assert "schema_version" in verify_complete_coverage(content, tampered)
