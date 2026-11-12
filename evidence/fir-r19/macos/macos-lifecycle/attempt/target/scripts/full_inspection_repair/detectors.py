from __future__ import annotations

import ast
import io
import multiprocessing
import os
import pickle
import re
import time
import tokenize
from dataclasses import dataclass
from pathlib import Path

import yaml

from .adapters import Subject
from .contracts import canonical_digest
from .protected_reader import MAX_FILE_BYTES

TEXT_SUFFIXES = frozenset(
    {".md", ".txt", ".py", ".json", ".jsonl", ".yaml", ".yml", ".toml"}
)
PLACEHOLDER_PATTERN = re.compile(r"\b(?:TODO|TBD)\b|\{\{[^{}]+\}\}")
LATENT_MARKER_PATTERN = re.compile(r"\b(?:FIXME|HACK|XXX|LEGACY)\b")
VULNERABILITY_PATTERN = re.compile(
    r"\beval\s*\(|shell\s*=\s*True|BEGIN PRIVATE KEY|AKIA[0-9A-Z]{16}"
)
ACTUAL_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    r"\s+[A-Za-z0-9+/=\s]{64,}"
)
ACTUAL_AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


@dataclass(frozen=True)
class DetectorResult:
    detector_id: str
    status: str
    findings: tuple[dict[str, object], ...]
    error: str | None = None
    detector_version: str = ""
    taxonomy_category_id: str = ""
    evidence_plane: str = ""


def _finding(
    subject: Subject,
    *,
    invariant_id: str,
    defect_class_id: str,
    taxonomy_category_id: str,
    severity: str,
    message: str,
    mechanism: str,
    source: str,
) -> dict[str, object]:
    locator = source
    identity = {
        "subject_id": subject.subject_id,
        "invariant_id": invariant_id,
        "locator": locator,
        "message": message,
    }
    return {
        "risk_id": canonical_digest(identity),
        "invariant_id": invariant_id,
        "defect_class_id": defect_class_id,
        "taxonomy_category_id": taxonomy_category_id,
        "subject_id": subject.subject_id,
        "source_id": f"source:{locator}",
        "severity": severity,
        "message": message,
        "mechanism": mechanism,
        "affected_refs": [locator],
        "root_cause_id": canonical_digest(
            {"invariant_id": invariant_id, "mechanism": mechanism}
        ),
        "status": "OPEN",
        "evidence_refs": [f"source:{locator}"],
        "evidence_sha256": canonical_digest(identity),
        "closed_by": None,
        "closed_at": None,
        "verification_check": None,
        "residual_risk": None,
    }


def _line_column(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    previous_newline = text.rfind("\n", 0, offset)
    return line, offset - previous_newline


def _mask_document_examples(text: str) -> str:
    pattern = re.compile(
        r"```[\s\S]*?```|~~~[\s\S]*?~~~|`[^`\r\n]+`",
    )
    return pattern.sub(
        lambda match: re.sub(r"[^\r\n]", " ", match.group(0)),
        text,
    )


def _python_marker_matches(
    content: bytes, pattern: re.Pattern[str]
) -> list[tuple[str, int, int]]:
    matches: list[tuple[str, int, int]] = []
    try:
        text = content.decode("utf-8")
        tree = ast.parse(text)
    except (SyntaxError, UnicodeDecodeError):
        text = content.decode("utf-8", errors="replace")
        tree = None
    line_offsets = [0]
    line_offsets.extend(match.end() for match in re.finditer(r"\n", text))
    try:
        tokens = list(tokenize.tokenize(io.BytesIO(content).readline))
    except (SyntaxError, UnicodeDecodeError, tokenize.TokenError):
        tokens = []
    for token in tokens:
        if token.type != tokenize.COMMENT:
            continue
        for marker in pattern.finditer(token.string):
            matches.append(
                (marker.group(0), token.start[0], token.start[1] + marker.start() + 1)
            )
    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if not node.body:
                continue
            statement = node.body[0]
            if not (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                continue
            value = statement.value
            start = line_offsets[value.lineno - 1] + value.col_offset
            for marker in pattern.finditer(value.value):
                line, column = _line_column(text, start + marker.start())
                matches.append((marker.group(0), line, column))
    return sorted(set(matches), key=lambda item: (item[1], item[2], item[0]))


def _marker_matches(
    locator: str, content: bytes, pattern: re.Pattern[str]
) -> list[tuple[str, int, int]]:
    if Path(locator).suffix.lower() == ".py":
        return _python_marker_matches(content, pattern)
    text = _mask_document_examples(content.decode("utf-8", errors="replace"))
    matches = []
    for match in pattern.finditer(text):
        line, column = _line_column(text, match.start())
        matches.append((match.group(0), line, column))
    return matches


def detect_skill_frontmatter_name(subject: Subject) -> tuple[dict[str, object], ...]:
    if subject.subject_kind != "SKILL":
        return ()
    skill_file = next(
        (item for item in subject.files if item.locator == "SKILL.md"),
        None,
    )
    if skill_file is None:
        return ()
    text = skill_file.content.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if lines:
        lines[0] = lines[0].lstrip("\ufeff")
    if not lines or lines[0].strip() != "---":
        return (
            _finding(
                subject,
                invariant_id="SKILL-FRONTMATTER-001",
                defect_class_id="skill.frontmatter.missing",
                taxonomy_category_id="INCONSISTENCY",
                severity="High",
                message="skill entrypoint has no leading YAML frontmatter",
                mechanism="The skill identity cannot be discovered from a structured contract.",
                source=skill_file.locator,
            ),
        )
    end: int | None = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = index
            break
    if end is None:
        return (
            _finding(
                subject,
                invariant_id="SKILL-FRONTMATTER-001",
                defect_class_id="skill.frontmatter.unterminated",
                taxonomy_category_id="INCONSISTENCY",
                severity="High",
                message="skill frontmatter has no closing delimiter",
                mechanism="The frontmatter boundary is incomplete and cannot be parsed safely.",
                source=skill_file.locator,
            ),
        )
    try:
        frontmatter = "\n".join(lines[1:end])
        metadata = yaml.safe_load(frontmatter) or {}
    except yaml.YAMLError as exc:
        return (
            _finding(
                subject,
                invariant_id="SKILL-FRONTMATTER-001",
                defect_class_id="skill.frontmatter.malformed",
                taxonomy_category_id="INCONSISTENCY",
                severity="High",
                message=f"skill frontmatter is malformed: {type(exc).__name__}",
                mechanism="YAML parsing failed before the skill identity could be validated.",
                source=skill_file.locator,
            ),
        )
    if not isinstance(metadata, dict):
        return (
            _finding(
                subject,
                invariant_id="SKILL-FRONTMATTER-001",
                defect_class_id="skill.frontmatter.malformed",
                taxonomy_category_id="INCONSISTENCY",
                severity="High",
                message="skill frontmatter must be a mapping",
                mechanism="The skill contract has the wrong top-level value type.",
                source=skill_file.locator,
            ),
        )
    name = metadata.get("name")
    declared = name.strip() if isinstance(name, str) else ""
    expected = subject.root.name
    if not declared:
        return (
            _finding(
                subject,
                invariant_id="SKILL-FRONTMATTER-NAME-001",
                defect_class_id="skill.frontmatter.missing_name",
                taxonomy_category_id="OMISSION",
                severity="High",
                message="skill frontmatter has no non-empty string name",
                mechanism="The skill has no stable declared identity.",
                source=skill_file.locator,
            ),
        )
    if declared == expected:
        return ()
    return (
        _finding(
            subject,
            invariant_id="SKILL-NAMING-001",
            defect_class_id="skill.frontmatter.name_mismatch",
            taxonomy_category_id="INCONSISTENCY",
            severity="Medium",
            message=f"frontmatter name {declared!r} does not match directory {expected!r}",
            mechanism="Skill identity is declared in two places without a single source of truth.",
            source=skill_file.locator,
        ),
    )


def detect_placeholders(subject: Subject) -> tuple[dict[str, object], ...]:
    findings: list[dict[str, object]] = []
    for item in subject.files:
        if Path(item.locator).suffix.lower() not in TEXT_SUFFIXES:
            continue
        for marker, line, column in _marker_matches(
            item.locator, item.content, PLACEHOLDER_PATTERN
        ):
            findings.append(
                _finding(
                    subject,
                    invariant_id="CONTENT-PLACEHOLDER-001",
                    defect_class_id="content.unfinished_placeholder",
                    taxonomy_category_id="OMISSION",
                    severity="Medium",
                    message=(
                        f"unfinished placeholder {marker!r} remains "
                        f"at line {line}, column {column}"
                    ),
                    mechanism="A scaffold marker survived into the deliverable.",
                    source=item.locator,
                )
            )
    return tuple(findings)


def detect_missing_final_newline(
    subject: Subject,
) -> tuple[dict[str, object], ...]:
    findings: list[dict[str, object]] = []
    for item in subject.files:
        if Path(item.locator).suffix.lower() not in TEXT_SUFFIXES or item.size == 0:
            continue
        data = item.content
        if data.endswith((b"\n", b"\r")):
            continue
        findings.append(
            _finding(
                subject,
                invariant_id="TEXT-FINAL-NEWLINE-001",
                defect_class_id="text.missing_final_newline",
                taxonomy_category_id="INCONSISTENCY",
                severity="Low",
                message="text file is missing a final newline",
                mechanism="The writer did not terminate the final text line.",
                source=item.locator,
            )
        )
    return tuple(findings)


def detect_missing_skill_entrypoint(
    subject: Subject,
) -> tuple[dict[str, object], ...]:
    if subject.subject_kind != "SKILL":
        return ()
    if any(item.locator == "SKILL.md" for item in subject.files):
        return ()
    return (
        _finding(
            subject,
            invariant_id="SKILL-ENTRYPOINT-001",
            defect_class_id="skill.missing_entrypoint",
            taxonomy_category_id="OMISSION",
            severity="Critical",
            message="skill has no SKILL.md entrypoint",
            mechanism="The adapter cannot load an executable skill contract.",
            source="SKILL.md",
        ),
    )


def detect_empty_text_files(subject: Subject) -> tuple[dict[str, object], ...]:
    findings: list[dict[str, object]] = []
    for item in subject.files:
        if Path(item.locator).suffix.lower() not in TEXT_SUFFIXES or item.size != 0:
            continue
        findings.append(
            _finding(
                subject,
                invariant_id="TEXT-EMPTY-001",
                defect_class_id="text.empty_file",
                taxonomy_category_id="FUNCTIONAL_FAULT",
                severity="Medium",
                message="required text file is empty",
                mechanism="A declared authored resource contains no usable content.",
                source=item.locator,
            )
        )
    return tuple(findings)


def detect_oversized_files(subject: Subject) -> tuple[dict[str, object], ...]:
    findings: list[dict[str, object]] = []
    for item in subject.files:
        if item.size <= MAX_FILE_BYTES:
            continue
        findings.append(
            _finding(
                subject,
                invariant_id="PERF-LARGE-FILE-001",
                defect_class_id="performance.oversized_file",
                taxonomy_category_id="RISK_EXPOSURE",
                severity="Low",
                message=f"file exceeds 1 MiB ({item.size} bytes)",
                mechanism="Large resources increase context, transfer, and review cost.",
                source=item.locator,
            )
        )
    return tuple(findings)


def detect_latent_markers(subject: Subject) -> tuple[dict[str, object], ...]:
    findings: list[dict[str, object]] = []
    for item in subject.files:
        if Path(item.locator).suffix.lower() not in TEXT_SUFFIXES:
            continue
        for marker, line, column in _marker_matches(
            item.locator, item.content, LATENT_MARKER_PATTERN
        ):
            findings.append(
                _finding(
                    subject,
                    invariant_id="CONTENT-LATENT-MARKER-001",
                    defect_class_id="content.latent_marker",
                    taxonomy_category_id="LATENT_DEFECT",
                    severity="Medium",
                    message=(
                        f"latent defect marker {marker!r} remains "
                        f"at line {line}, column {column}"
                    ),
                    mechanism="A known deferred defect marker is still present.",
                    source=item.locator,
                )
            )
    return tuple(findings)


def detect_vulnerability_markers(
    subject: Subject,
) -> tuple[dict[str, object], ...]:
    findings: list[dict[str, object]] = []
    for item in subject.files:
        if Path(item.locator).suffix.lower() not in TEXT_SUFFIXES:
            continue
        if Path(item.locator).suffix.lower() == ".py":
            for pattern, line, column in _python_vulnerabilities(item.content):
                findings.append(
                    _finding(
                        subject,
                        invariant_id="SECURITY-DANGEROUS-PATTERN-001",
                        defect_class_id="security.dangerous_pattern",
                        taxonomy_category_id="VULNERABILITY",
                        severity="High",
                        message=(
                            f"dangerous pattern {pattern!r} detected at "
                            f"line {line}, column {column}"
                        ),
                        mechanism=(
                            "Untrusted input or secrets may cross an unsafe "
                            "execution boundary."
                        ),
                        source=item.locator,
                    )
                )
            continue
        text = item.content.decode("utf-8", errors="replace")
        for match in VULNERABILITY_PATTERN.finditer(text):
            line, column = _line_column(text, match.start())
            findings.append(
                _finding(
                    subject,
                    invariant_id="SECURITY-DANGEROUS-PATTERN-001",
                    defect_class_id="security.dangerous_pattern",
                    taxonomy_category_id="VULNERABILITY",
                    severity="High",
                    message=(
                        f"dangerous pattern {match.group(0)!r} detected at "
                        f"line {line}, column {column}"
                    ),
                    mechanism=(
                        "Untrusted input or secrets may cross an unsafe "
                        "execution boundary."
                    ),
                    source=item.locator,
                )
            )
    return tuple(findings)


def detect_text_boundary_errors(subject: Subject) -> tuple[dict[str, object], ...]:
    findings: list[dict[str, object]] = []
    for item in subject.files:
        suffix = Path(item.locator).suffix.lower()
        if suffix not in TEXT_SUFFIXES:
            continue
        try:
            text = item.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            findings.append(
                _finding(
                    subject,
                    invariant_id="TEXT-ENCODING-001",
                    defect_class_id="text.invalid_utf8",
                    taxonomy_category_id="BOUNDARY",
                    severity="Medium",
                    message=f"invalid UTF-8 at byte {exc.start}",
                    mechanism="The file crosses the text boundary with invalid encoding.",
                    source=item.locator,
                )
            )
            continue
        if suffix != ".py":
            continue
        try:
            ast.parse(text)
        except SyntaxError as exc:
            findings.append(
                _finding(
                    subject,
                    invariant_id="PY-SYNTAX-001",
                    defect_class_id="python.syntax_error",
                    taxonomy_category_id="BOUNDARY",
                    severity="High",
                    message=(
                        f"Python syntax error at line {exc.lineno or 1}, "
                        f"column {exc.offset or 1}: {exc.msg}"
                    ),
                    mechanism=(
                        "The source cannot cross the parser boundary, so AST-based "
                        "checks have no trustworthy result."
                    ),
                    source=item.locator,
                )
            )
    return tuple(findings)


def detect_exception_swallowing(
    subject: Subject,
) -> tuple[dict[str, object], ...]:
    findings: list[dict[str, object]] = []
    for item in subject.files:
        if Path(item.locator).suffix.lower() != ".py":
            continue
        if not _python_swallows_exception(item.content):
            continue
        findings.append(
            _finding(
                subject,
                invariant_id="PY-EXCEPTION-SWALLOW-001",
                defect_class_id="python.swallowed_exception",
                taxonomy_category_id="EXCEPTION_PATH",
                severity="High",
                message="exception handler swallows the exception with pass",
                mechanism="The exceptional path completes without evidence or recovery.",
                source=item.locator,
            )
        )
    return tuple(findings)


class PythonParseError(ValueError):
    """Raised when a Python source cannot produce a trustworthy AST."""


def _python_tree(content: bytes) -> ast.AST:
    try:
        return ast.parse(content.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise PythonParseError(f"{type(exc).__name__}: {exc}") from exc


def _python_vulnerabilities(content: bytes) -> tuple[tuple[str, int, int], ...]:
    tree = _python_tree(content)
    matches: list[tuple[str, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                matches.append((f"{node.func.id}(", node.lineno, node.col_offset))
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr
                in {"run", "call", "check_call", "check_output", "Popen"}
                and any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
            ):
                matches.append(("shell=True", node.lineno, node.col_offset))
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if ACTUAL_PRIVATE_KEY_PATTERN.search(node.value):
                matches.append(("private-key", node.lineno, node.col_offset))
            if ACTUAL_AWS_KEY_PATTERN.search(node.value):
                matches.append(("aws-access-key", node.lineno, node.col_offset))
    return tuple(sorted(set(matches), key=lambda item: (item[1], item[2], item[0])))


def _python_swallows_exception(content: bytes) -> bool:
    tree = _python_tree(content)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ExceptHandler)
            and len(node.body) == 1
            and isinstance(node.body[0], ast.Pass)
        ):
            return True
    return False


DEFAULT_DETECTORS = (
    (
        "skill.frontmatter-name",
        "INCONSISTENCY",
        "CONTRACT",
        detect_skill_frontmatter_name,
    ),
    ("text.placeholder", "OMISSION", "SEMANTIC", detect_placeholders),
    ("text.final-newline", "INCONSISTENCY", "STATIC", detect_missing_final_newline),
    ("skill.entrypoint", "OMISSION", "STATIC", detect_missing_skill_entrypoint),
    ("text.empty", "FUNCTIONAL_FAULT", "STATIC", detect_empty_text_files),
    ("file.oversized", "RISK_EXPOSURE", "PERFORMANCE", detect_oversized_files),
    ("text.latent-marker", "LATENT_DEFECT", "SEMANTIC", detect_latent_markers),
    (
        "security.dangerous-pattern",
        "VULNERABILITY",
        "SECURITY",
        detect_vulnerability_markers,
    ),
    ("text.boundary", "BOUNDARY", "STATIC", detect_text_boundary_errors),
    (
        "python.exception-swallow",
        "EXCEPTION_PATH",
        "BEHAVIOR",
        detect_exception_swallowing,
    ),
)


DEFAULT_DETECTOR_TIMEOUT_SECONDS = 5.0


def _detector_worker(
    connection,
    detector_id: str,
    category_id: str,
    evidence_plane: str,
    detector,
    subject: Subject,
) -> None:
    try:
        try:
            findings = detector(subject)
        except BaseException as exc:  # noqa: BLE001 - worker isolation is fail-closed
            result = DetectorResult(
                detector_id=detector_id,
                status="BLOCKED",
                findings=(),
                error=f"{type(exc).__name__}: {exc}",
                detector_version="1.0.0",
                taxonomy_category_id=category_id,
                evidence_plane=evidence_plane,
            )
        else:
            result = DetectorResult(
                detector_id=detector_id,
                status="FINDINGS" if findings else "PASS",
                findings=findings,
                detector_version="1.0.0",
                taxonomy_category_id=category_id,
                evidence_plane=evidence_plane,
            )
        connection.send(result)
    finally:
        connection.close()


def _stop_process(process: multiprocessing.Process) -> None:
    if process.is_alive():
        process.terminate()
        process.join(1.0)
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
        process.join(1.0)


def run_detectors(
    subject: Subject,
    detectors,
    *,
    timeout_seconds: float = DEFAULT_DETECTOR_TIMEOUT_SECONDS,
) -> tuple[DetectorResult, ...]:
    if timeout_seconds <= 0:
        raise ValueError("detector timeout must be positive")
    context = multiprocessing.get_context("spawn" if os.name == "nt" else "forkserver")
    running = []
    for detector_id, category_id, evidence_plane, detector in detectors:
        receive, send = context.Pipe(duplex=False)
        process = context.Process(
            target=_detector_worker,
            args=(send, detector_id, category_id, evidence_plane, detector, subject),
            daemon=True,
        )
        try:
            process.start()
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            pickle.PicklingError,
        ) as exc:
            receive.close()
            send.close()
            _stop_process(process)
            running.append(
                (
                    detector_id,
                    None,
                    None,
                    DetectorResult(
                        detector_id=detector_id,
                        status="BLOCKED",
                        findings=(),
                        error=f"DetectorProcessError: {type(exc).__name__}: {exc}",
                        detector_version="1.0.0",
                        taxonomy_category_id=category_id,
                        evidence_plane=evidence_plane,
                    ),
                )
            )
            continue
        send.close()
        running.append((detector_id, process, receive, None))

    results: list[DetectorResult] = []
    scheduling_complete = time.monotonic()
    for detector_id, process, receive, deadline_or_result in running:
        if process is None or receive is None:
            results.append(deadline_or_result)
            continue
        deadline = (
            scheduling_complete + timeout_seconds
            if deadline_or_result is None
            else float(deadline_or_result)
        )
        result: DetectorResult | None = None
        try:
            remaining = max(0.0, deadline - time.monotonic())
            if receive.poll(remaining):
                received = receive.recv()
                if isinstance(received, DetectorResult):
                    result = received
        except (EOFError, OSError):
            result = None
        finally:
            receive.close()
        process.join(0.05)
        if result is None:
            timed_out = process.is_alive()
            _stop_process(process)
            error = (
                f"DeadlineExceeded: detector exceeded {timeout_seconds:.3f}s"
                if timed_out
                else f"DetectorProcessError: worker exited with {process.exitcode}"
            )
            result = DetectorResult(
                detector_id=detector_id,
                status="BLOCKED",
                findings=(),
                error=error,
                detector_version="1.0.0",
                taxonomy_category_id=category_id,
                evidence_plane=evidence_plane,
            )
        else:
            _stop_process(process)
        results.append(result)
    return tuple(results)


def run_default_detectors(
    subject: Subject, *, timeout_seconds: float = DEFAULT_DETECTOR_TIMEOUT_SECONDS
) -> tuple[DetectorResult, ...]:
    return run_detectors(
        subject,
        DEFAULT_DETECTORS,
        timeout_seconds=timeout_seconds,
    )
