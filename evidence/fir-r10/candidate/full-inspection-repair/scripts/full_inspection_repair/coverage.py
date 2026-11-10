from __future__ import annotations

import hashlib
import re
import unicodedata
from pathlib import PurePosixPath
from typing import Any

from .contracts import canonical_digest

TEXT_SUFFIXES = frozenset(
    {
        ".md",
        ".txt",
        ".py",
        ".json",
        ".jsonl",
        ".yaml",
        ".yml",
        ".toml",
        ".xml",
        ".html",
        ".css",
        ".js",
        ".ts",
        ".ps1",
        ".sh",
        ".cfg",
        ".ini",
    }
)
ZERO_SHA256 = "0" * 64


class CoverageError(ValueError):
    """Raised when any repository range lacks reproducible coverage."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _context(text: str, index: int, radius: int = 16) -> str:
    return text[max(0, index - radius) : index + radius + 1]


def _line_starts(text: str) -> list[int]:
    starts = [0]
    starts.extend(match.end() for match in re.finditer(r"\r\n|\r|\n", text))
    return starts


def _physical_lines(content: bytes) -> list[bytes]:
    lines = []
    start = 0
    for match in re.finditer(rb"\r\n|\r|\n", content):
        lines.append(content[start : match.end()])
        start = match.end()
    if start < len(content):
        lines.append(content[start:])
    return lines


def _newline_style(content: bytes) -> str:
    styles = set(re.findall(rb"\r\n|\r|\n", content))
    if not styles:
        return "NONE"
    if len(styles) > 1:
        return "MIXED"
    return {b"\r\n": "CRLF", b"\r": "CR", b"\n": "LF"}[styles.pop()]


def _locate(line_starts: list[int], codepoint_index: int) -> tuple[int, int]:
    low = 0
    high = len(line_starts)
    while low + 1 < high:
        middle = (low + high) // 2
        if line_starts[middle] <= codepoint_index:
            low = middle
        else:
            high = middle
    return low + 1, codepoint_index - line_starts[low] + 1


def _unit_rows(
    *,
    path: str,
    text: str,
    byte_offsets: list[int],
    kind: str,
    boundaries: list[tuple[int, int]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cursor = 0
    for _start, end in [*boundaries, (len(text), len(text))]:
        if end <= cursor:
            continue
        rows.append(
            {
                "path": path,
                "unit_number": len(rows) + 1,
                "kind": kind,
                "codepoint_start": cursor,
                "codepoint_end_exclusive": end,
                "byte_start": byte_offsets[cursor],
                "byte_end_exclusive": byte_offsets[end],
                "sha256": _sha(text[cursor:end].encode("utf-8")),
            }
        )
        cursor = end
    return rows


def _boundary_rows(text: str, pattern: str) -> list[tuple[int, int]]:
    return [(0, match.end()) for match in re.finditer(pattern, text)]


def _is_binary(path: str, content: bytes) -> bool:
    suffix = PurePosixPath(path).suffix.casefold()
    if b"\x00" in content:
        return True
    if suffix in TEXT_SUFFIXES:
        try:
            content.decode("utf-8", errors="strict")
            return False
        except UnicodeDecodeError as exc:
            raise CoverageError(
                f"declared text file is not valid UTF-8: {path}: byte {exc.start}"
            ) from exc
    try:
        content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return True
    return False


def _text_evidence(path: str, content: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    text = content.decode("utf-8", errors="strict")
    line_starts = _line_starts(text)
    byte_offsets = [0]
    total = 0
    for character in text:
        total += len(character.encode("utf-8"))
        byte_offsets.append(total)
    if total != len(content):
        raise CoverageError(f"byte/codepoint accounting mismatch: {path}")

    categories = [unicodedata.category(character) for character in text]
    spans: list[dict[str, Any]] = []
    start = 0
    while start < len(text):
        category = categories[start]
        end = start + 1
        while end < len(text) and categories[end] == category:
            end += 1
        spans.append(
            {
                "category": category,
                "codepoint_start": start,
                "codepoint_end_exclusive": end,
                "codepoint_count": end - start,
                "byte_start": byte_offsets[start],
                "byte_end_exclusive": byte_offsets[end],
                "sha256": _sha(text[start:end].encode("utf-8")),
            }
        )
        start = end

    punctuation: list[dict[str, Any]] = []
    whitespace_control: list[dict[str, Any]] = []
    for index, character in enumerate(text):
        category = categories[index]
        line, column = _locate(line_starts, index)
        record = {
            "path": path,
            "codepoint_index": index,
            "byte_offset": byte_offsets[index],
            "line": line,
            "column": column,
            "codepoint": f"U+{ord(character):04X}",
            "character": character,
            "category": category,
            "context_sha256": canonical_digest(_context(text, index)),
        }
        if category.startswith("P"):
            punctuation.append(record)
        if character.isspace() or category.startswith("C"):
            whitespace_control.append(record)

    lines = []
    physical = _physical_lines(content)
    codepoint_cursor = 0
    byte_cursor = 0
    for number, raw_line in enumerate(physical, start=1):
        decoded = raw_line.decode("utf-8", errors="strict")
        count = len(decoded)
        lines.append(
            {
                "line": number,
                "byte_start": byte_cursor,
                "byte_length": len(raw_line),
                "codepoint_start": codepoint_cursor,
                "codepoint_count": count,
                "sha256": _sha(raw_line),
            }
        )
        codepoint_cursor += count
        byte_cursor += len(raw_line)

    units = _unit_rows(
        path=path,
        text=text,
        byte_offsets=byte_offsets,
        kind="SYNTAX_LINE",
        boundaries=[
            (0, line["codepoint_start"] + line["codepoint_count"])
            for line in lines
        ],
    )
    prose = PurePosixPath(path).suffix.casefold() in {".md", ".txt"}
    sentence_units = (
        _unit_rows(
            path=path,
            text=text,
            byte_offsets=byte_offsets,
            kind="SENTENCE",
            boundaries=_boundary_rows(
                text,
                r"[。！？]+[”’」』】）)]*|[.!?]+[”’\"')\]]*(?=\s|$|[^\x00-\x7F])|[\r\n]+",
            ),
        )
        if prose
        else []
    )
    paragraph_units = (
        _unit_rows(
            path=path,
            text=text,
            byte_offsets=byte_offsets,
            kind="PARAGRAPH",
            boundaries=_boundary_rows(
                text, r"(?:\r\n|\r|\n)[ \t]*(?:\r\n|\r|\n)+"
            ),
        )
        if prose
        else []
    )
    clause_units = (
        _unit_rows(
            path=path,
            text=text,
            byte_offsets=byte_offsets,
            kind="CLAUSE",
            boundaries=_boundary_rows(text, r"[,;:，；：]+"),
        )
        if prose
        else []
    )

    file_record = {
        "path": path,
        "kind": "TEXT",
        "bytes": len(content),
        "raw_sha256": _sha(content),
        "codepoint_count": len(text),
        "line_count": len(physical),
        "empty_line_count": sum(not line.rstrip(b"\r\n").strip() for line in physical),
        "bom": content.startswith(b"\xef\xbb\xbf"),
        "newline_style": _newline_style(content),
        "final_terminator": content.endswith((b"\n", b"\r")),
        "punctuation_count": len(punctuation),
        "whitespace_control_count": len(whitespace_control),
        "codepoint_spans": spans,
        "lines": lines,
        "units": units,
        "prose": prose,
        "sentence_units": sentence_units,
        "paragraph_units": paragraph_units,
        "clause_units": clause_units,
        "whitespace_control": whitespace_control,
        "unit_covered_codepoints": sum(
            item["codepoint_end_exclusive"] - item["codepoint_start"]
            for item in units
        ),
        "sentence_covered_codepoints": sum(
            item["codepoint_end_exclusive"] - item["codepoint_start"]
            for item in sentence_units
        ),
        "paragraph_covered_codepoints": sum(
            item["codepoint_end_exclusive"] - item["codepoint_start"]
            for item in paragraph_units
        ),
        "clause_covered_codepoints": sum(
            item["codepoint_end_exclusive"] - item["codepoint_start"]
            for item in clause_units
        ),
    }
    return file_record, punctuation


def build_complete_coverage(content: dict[str, bytes]) -> dict[str, Any]:
    files = []
    punctuation_rows = []
    binary_rows = []
    uncovered = []
    for path in sorted(content):
        data = content[path]
        try:
            if _is_binary(path, data):
                binary_rows.append(
                    {
                        "path": path,
                        "kind": "BINARY_OR_OPAQUE",
                        "bytes": len(data),
                        "sha256": _sha(data),
                        "projection": "raw-byte-hash-no-text-interpretation",
                    }
                )
            else:
                record, punctuation = _text_evidence(path, data)
                files.append(record)
                punctuation_rows.extend(punctuation)
        except (CoverageError, UnicodeDecodeError) as exc:
            uncovered.append({"path": path, "error": f"{type(exc).__name__}:{exc}"})

    gaps = []
    for record in files:
        cursor = 0
        byte_cursor = 0
        for span in record["codepoint_spans"]:
            if (
                span["codepoint_start"] != cursor
                or span["byte_start"] != byte_cursor
            ):
                gaps.append(
                    {
                        "path": record["path"],
                        "codepoint_expected": cursor,
                        "codepoint_actual": span["codepoint_start"],
                        "byte_expected": byte_cursor,
                        "byte_actual": span["byte_start"],
                    }
                )
            cursor = span["codepoint_end_exclusive"]
            byte_cursor = span["byte_end_exclusive"]
        if cursor != record["codepoint_count"] or byte_cursor != record["bytes"]:
            gaps.append(
                {
                    "path": record["path"],
                    "codepoint_end": cursor,
                    "byte_end": byte_cursor,
                }
            )
        unit_fields = ["unit_covered_codepoints"]
        if record["prose"]:
            unit_fields.extend(
                [
                    "sentence_covered_codepoints",
                    "paragraph_covered_codepoints",
                    "clause_covered_codepoints",
                ]
            )
        for field in unit_fields:
            if record[field] != record["codepoint_count"]:
                gaps.append(
                    {
                        "path": record["path"],
                        "unit_view": field,
                        "expected_codepoints": record["codepoint_count"],
                        "covered_codepoints": record[field],
                    }
                )

    report: dict[str, Any] = {
        "schema_version": 1,
        "files": files,
        "binary_files": binary_rows,
        "punctuation": punctuation_rows,
        "whitespace_control": [
            item for record in files for item in record["whitespace_control"]
        ],
        "uncovered": uncovered,
        "gaps": gaps,
        "file_count": len(files) + len(binary_rows),
        "text_file_count": len(files),
        "binary_file_count": len(binary_rows),
        "codepoint_count": sum(item["codepoint_count"] for item in files),
        "line_count": sum(item["line_count"] for item in files),
        "unit_count": sum(len(item["units"]) for item in files),
        "punctuation_count": len(punctuation_rows),
        "uncovered_count": len(uncovered),
        "gap_count": len(gaps),
    }
    report["coverage_digest"] = canonical_digest(report)
    return report


def verify_complete_coverage(
    content: dict[str, bytes], report: dict[str, Any]
) -> list[str]:
    expected = build_complete_coverage(content)
    failures = []
    for field in (
        "files",
        "binary_files",
        "punctuation",
        "whitespace_control",
        "uncovered",
        "gaps",
        "file_count",
        "text_file_count",
        "binary_file_count",
        "schema_version",
        "codepoint_count",
        "line_count",
        "unit_count",
        "punctuation_count",
        "uncovered_count",
        "gap_count",
    ):
        if report.get(field) != expected[field]:
            failures.append(field)
    material = dict(report)
    declared = material.pop("coverage_digest", None)
    if canonical_digest(material) != declared:
        failures.append("coverage_digest")
    if expected["uncovered_count"] or expected["gap_count"]:
        failures.append("coverage_gaps")
    return failures
