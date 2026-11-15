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
COVERAGE_SCHEMA_ID = "inspection-closure.coverage"
COVERAGE_SCHEMA_VERSION = 2
DEFAULT_MAX_SOURCE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_DERIVED_BYTES = 64 * 1024 * 1024
COVERAGE_FIELDS = frozenset(
    {
        "schema_id",
        "schema_version",
        "files",
        "binary_files",
        "punctuation_runs",
        "whitespace_control_runs",
        "uncovered",
        "gaps",
        "file_count",
        "text_file_count",
        "binary_file_count",
        "codepoint_count",
        "line_count",
        "unit_count",
        "punctuation_count",
        "uncovered_count",
        "gap_count",
        "coverage_digest",
    }
)
FILE_FIELDS = frozenset(
    {
        "path",
        "kind",
        "bytes",
        "raw_sha256",
        "codepoint_count",
        "line_count",
        "empty_line_count",
        "bom",
        "newline_style",
        "final_terminator",
        "punctuation_count",
        "whitespace_control_count",
        "codepoint_spans",
        "lines",
        "units",
        "prose",
        "sentence_units",
        "paragraph_units",
        "clause_units",
        "unit_covered_codepoints",
        "sentence_covered_codepoints",
        "paragraph_covered_codepoints",
        "clause_covered_codepoints",
    }
)


class CoverageError(ValueError):
    """Raised when any repository range lacks reproducible coverage."""


class CoverageBudgetError(CoverageError):
    """Raised before coverage evidence exceeds its declared budget."""


class _EvidenceBudget:
    def __init__(self, maximum: int):
        if maximum <= 0:
            raise CoverageBudgetError("derived evidence budget must be positive")
        self.maximum = maximum
        self.used = 0

    def charge(self, amount: int) -> None:
        self.used += amount
        if self.used > self.maximum:
            raise CoverageBudgetError(
                f"derived evidence budget exceeded: {self.used}>{self.maximum}"
            )


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def _unit_rows(
    *,
    path: str,
    text: str,
    byte_offsets: list[int],
    kind: str,
    boundaries: list[tuple[int, int]],
    budget: _EvidenceBudget,
    include_text: bool = False,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cursor = 0
    for _start, end in [*boundaries, (len(text), len(text))]:
        if end <= cursor:
            continue
        if text[cursor:end].isspace() and rows:
            previous = rows[-1]
            previous["codepoint_end_exclusive"] = end
            previous["byte_end_exclusive"] = byte_offsets[end]
            previous["sha256"] = _sha(
                text[
                    int(previous["codepoint_start"]) : end
                ].encode("utf-8")
            )
            if include_text:
                previous["text"] = text[int(previous["codepoint_start"]) : end]
            cursor = end
            continue
        budget.charge(160 + (end - cursor if include_text else 0))
        row = {
                "path": path,
                "unit_number": len(rows) + 1,
                "kind": kind,
                "codepoint_start": cursor,
                "codepoint_end_exclusive": end,
                "byte_start": byte_offsets[cursor],
                "byte_end_exclusive": byte_offsets[end],
                "sha256": _sha(text[cursor:end].encode("utf-8")),
        }
        if include_text:
            row["text"] = text[cursor:end]
        rows.append(row)
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


def _character_runs(
    path: str,
    text: str,
    *,
    kind: str,
    predicate,
    budget: _EvidenceBudget,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    chunk_size = 1024
    chunk: list[int] = []
    hasher = hashlib.sha256()
    counts: dict[str, int] = {}

    def flush() -> None:
        nonlocal chunk, hasher, counts
        if not chunk:
            return
        budget.charge(200)
        rows.append(
            {
                "path": path,
                "kind": kind,
                "first_codepoint": chunk[0],
                "last_codepoint": chunk[-1],
                "count": len(chunk),
                "counts": dict(sorted(counts.items())),
                "sha256": hasher.hexdigest(),
            }
        )
        chunk = []
        hasher = hashlib.sha256()
        counts = {}

    for index, character in enumerate(text):
        if not predicate(character):
            continue
        category = unicodedata.category(character)
        hasher.update(f"{index}:{category}:{character}\0".encode())
        counts[category] = counts.get(category, 0) + 1
        chunk.append(index)
        if len(chunk) == chunk_size:
            flush()
    flush()
    return rows


def _text_evidence(
    path: str, content: bytes, budget: _EvidenceBudget
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    text = content.decode("utf-8", errors="strict")
    budget.charge(512 + len(text))
    byte_offsets = [0]
    total = 0
    for character in text:
        total += len(character.encode("utf-8"))
        byte_offsets.append(total)
    if total != len(content):
        raise CoverageError(f"byte/codepoint accounting mismatch: {path}")

    spans: list[dict[str, Any]] = []
    span_size = 256
    for start in range(0, len(text), span_size):
        end = min(len(text), start + span_size)
        budget.charge(160)
        spans.append(
            {
                "codepoint_start": start,
                "codepoint_end_exclusive": end,
                "codepoint_count": end - start,
                "byte_start": byte_offsets[start],
                "byte_end_exclusive": byte_offsets[end],
                "sha256": _sha(text[start:end].encode("utf-8")),
            }
        )
        start = end

    punctuation = _character_runs(
        path,
        text,
        kind="PUNCTUATION",
        predicate=lambda character: unicodedata.category(character).startswith("P"),
        budget=budget,
    )
    whitespace_control = _character_runs(
        path,
        text,
        kind="WHITESPACE_CONTROL",
        predicate=lambda character: (
            character.isspace()
            or unicodedata.category(character).startswith("C")
        ),
        budget=budget,
    )

    lines = []
    physical = _physical_lines(content)
    codepoint_cursor = 0
    byte_cursor = 0
    for number, raw_line in enumerate(physical, start=1):
        decoded = raw_line.decode("utf-8", errors="strict")
        count = len(decoded)
        budget.charge(160)
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
        budget=budget,
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
                r"[。！？]+[”’」』】）)]*|[.!?]+[”’\"')\]]*(?=\s|$|[^\x00-\x7F])",
            ),
            budget=budget,
            include_text=True,
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
            budget=budget,
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
            budget=budget,
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
        "punctuation_count": sum(
            item["count"] for item in punctuation
        ),
        "whitespace_control_count": sum(
            item["count"] for item in whitespace_control
        ),
        "codepoint_spans": spans,
        "lines": lines,
        "units": units,
        "prose": prose,
        "sentence_units": sentence_units,
        "paragraph_units": paragraph_units,
        "clause_units": clause_units,
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
    return file_record, punctuation, whitespace_control


def build_complete_coverage(
    content: dict[str, bytes],
    *,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    max_derived_bytes: int = DEFAULT_MAX_DERIVED_BYTES,
) -> dict[str, Any]:
    if max_source_bytes <= 0:
        raise CoverageError("source byte budget must be positive")
    source_bytes = sum(len(value) for value in content.values())
    if source_bytes > max_source_bytes:
        raise CoverageBudgetError(
            f"source byte budget exceeded: {source_bytes}>{max_source_bytes}"
        )
    budget = _EvidenceBudget(max_derived_bytes)
    files = []
    punctuation_runs = []
    whitespace_control_runs = []
    binary_rows = []
    uncovered = []
    for path in sorted(content):
        data = content[path]
        try:
            if _is_binary(path, data):
                budget.charge(256)
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
                record, punctuation, whitespace_control = _text_evidence(
                    path, data, budget
                )
                files.append(record)
                punctuation_runs.extend(punctuation)
                whitespace_control_runs.extend(whitespace_control)
        except CoverageBudgetError:
            raise
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
        "schema_id": COVERAGE_SCHEMA_ID,
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "files": files,
        "binary_files": binary_rows,
        "punctuation_runs": punctuation_runs,
        "whitespace_control_runs": whitespace_control_runs,
        "uncovered": uncovered,
        "gaps": gaps,
        "file_count": len(files) + len(binary_rows),
        "text_file_count": len(files),
        "binary_file_count": len(binary_rows),
        "codepoint_count": sum(item["codepoint_count"] for item in files),
        "line_count": sum(item["line_count"] for item in files),
        "unit_count": sum(len(item["units"]) for item in files),
        "punctuation_count": sum(
            item["count"] for item in punctuation_runs
        ),
        "uncovered_count": len(uncovered),
        "gap_count": len(gaps),
    }
    report["coverage_digest"] = canonical_digest(report)
    return report


def verify_complete_coverage(
    content: dict[str, bytes], report: dict[str, Any]
) -> list[str]:
    expected = build_complete_coverage(content)
    failures: list[str] = []
    if set(report) != COVERAGE_FIELDS:
        failures.append("schema")
    if report.get("schema_id") != COVERAGE_SCHEMA_ID:
        failures.append("schema_id")
    if report.get("schema_version") != COVERAGE_SCHEMA_VERSION:
        failures.append("schema_version")
    for record in report.get("files", ()):
        if not isinstance(record, dict) or set(record) != FILE_FIELDS:
            failures.append("schema:file")
            break
    for field in (
        "schema_id",
        "files",
        "binary_files",
        "punctuation_runs",
        "whitespace_control_runs",
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
    return sorted(set(failures))
