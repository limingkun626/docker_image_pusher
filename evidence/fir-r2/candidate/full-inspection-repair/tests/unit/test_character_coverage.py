from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.coverage import (
    build_complete_coverage,
    verify_complete_coverage,
)


def test_every_text_range_and_punctuation_is_accounted_for() -> None:
    content = {
        "SKILL.md": b"# Demo\nUse a, b; c: d.\n",
        "scripts/demo.py": b"def run():\n    return {'x': 1}\n",
    }
    report = build_complete_coverage(content)
    assert report["uncovered_count"] == 0
    assert report["gap_count"] == 0
    assert report["punctuation_count"] > 0
    assert {item["path"] for item in report["punctuation_runs"]} == {
        "SKILL.md",
        "scripts/demo.py",
    }
    assert verify_complete_coverage(content, report) == []


def test_punctuation_mutation_changes_coverage_digest() -> None:
    first = build_complete_coverage({"SKILL.md": b"Use a,b.\n"})
    second = build_complete_coverage({"SKILL.md": b"Use a;b.\n"})

    assert first["coverage_digest"] != second["coverage_digest"]
    assert first["punctuation_runs"] != second["punctuation_runs"]


@pytest.mark.parametrize(
    "before,after",
    [
        ("a,b", "a,b."),
        ("a,b", "a;b"),
        ("'x'", '"x"'),
        ("[x]", "(x)"),
        ("a:\nb", "a:\tb"),
        ("a.\n", "a."),
        ('{"a":1}', '{"a"=1}'),
        ("a\\u200bb", "a\u200bb"),
    ],
)
def test_punctuation_and_invisible_mutations_are_detected(
    before: str, after: str
) -> None:
    first = build_complete_coverage({"SKILL.md": before.encode("utf-8")})
    second = build_complete_coverage({"SKILL.md": after.encode("utf-8")})

    assert first["coverage_digest"] != second["coverage_digest"]


def test_all_unit_views_partition_each_text_file() -> None:
    content = b"# Head, clause; tail.\n\nSecond paragraph!\r\n"
    report = build_complete_coverage({"SKILL.md": content})
    record = report["files"][0]

    for field in (
        "unit_covered_codepoints",
        "sentence_covered_codepoints",
        "paragraph_covered_codepoints",
        "clause_covered_codepoints",
    ):
        assert record[field] == record["codepoint_count"]
    assert record["newline_style"] == "MIXED"
    assert report["gap_count"] == 0


def test_coverage_tamper_is_detected() -> None:
    content = {"SKILL.md": b"# Demo, value.\n"}
    report = build_complete_coverage(content)
    tampered = copy.deepcopy(report)
    tampered["punctuation_runs"][0]["sha256"] = "0" * 64

    assert "punctuation_runs" in verify_complete_coverage(content, tampered)


def test_invalid_utf8_text_is_uncovered() -> None:
    report = build_complete_coverage({"bad.md": b"\xff\xfe"})

    assert report["uncovered_count"] == 1
    assert report["uncovered"][0]["path"] == "bad.md"


def test_binary_file_has_explicit_projection() -> None:
    report = build_complete_coverage({"asset.bin": b"\x00\x01\x02"})

    assert report["binary_file_count"] == 1
    assert report["binary_files"][0]["projection"] == (
        "raw-byte-hash-no-text-interpretation"
    )
