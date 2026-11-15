from __future__ import annotations

import ast
import dis
import hashlib
import json
import ntpath
import re
import sys
import tokenize
import unicodedata
from io import StringIO
from pathlib import Path
from re import _parser as re_parser
from typing import Any, Iterable, Mapping

from .native_p2 import (
    MalformedSource,
    _qualified_name,
    canonical_digest,
    result,
    source_digest,
    validate_python_syntax,
)


def _oracle_result(
    cell_id: str,
    oracle_id: str,
    snapshot: Mapping[str, Any],
    findings: Iterable[Mapping[str, Any]],
    *,
    empty: bool = False,
) -> dict[str, Any]:
    body = result(cell_id, oracle_id, "ORACLE", "independent-recompute", snapshot, findings, empty=empty)
    body["detector_id"] = oracle_id
    body["receipt_kind"] = "ORACLE"
    body["recomputed_fact_set_digest"] = canonical_digest(
        {"cell_id": cell_id, "findings": body["findings"], "snapshot": source_digest(snapshot)}
    )
    body["fact_set_digest"] = canonical_digest(
        {key: value for key, value in body.items() if key != "fact_set_digest"}
    )
    return body


def _witness(path: str, line: int, kind: str, **value: Any) -> dict[str, Any]:
    item = {"witness": kind, "path": path, "line": line, "value": value}
    item["witness_id"] = canonical_digest(item)
    return item


def _python_sources(snapshot: Mapping[str, Any]) -> list[tuple[str, str]]:
    sources = []
    for path, raw in sorted(snapshot.get("files", {}).items()):
        if not path.endswith(".py"):
            continue
        try:
            sources.append((path, raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "strict")))
        except UnicodeDecodeError as exc:
            raise MalformedSource(f"{path}: {exc}") from exc
    return sources


def _tokens(source: str) -> list[tokenize.TokenInfo]:
    try:
        return list(tokenize.generate_tokens(StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
        raise MalformedSource(str(exc)) from exc


def _function_blocks(source: str) -> list[tuple[str, int, str]]:
    lines = source.splitlines()
    blocks = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)def\s+([A-Za-z_]\w*)\s*\(", lines[index])
        if not match:
            index += 1
            continue
        indent = len(match.group(1))
        end = index + 1
        while end < len(lines):
            if lines[end].strip() and len(lines[end]) - len(lines[end].lstrip()) <= indent:
                break
            end += 1
        blocks.append((match.group(2), index + 1, "\n".join(lines[index:end])))
        index = end
    return blocks


def oracle_functional_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:FUNCTIONAL_FAULT:SEMANTIC"
    sources = _python_sources(snapshot)
    if not sources:
        return _oracle_result(cell, "p2.oracle.effect-token-walk", snapshot, (), empty=True)
    findings = []
    effects = ("write_text", "write_bytes", "unlink", "mkdir", "os.system", "subprocess.run", "subprocess.Popen")
    for path, source in sources:
        for name, line, block in _function_blocks(source):
            declared = name.startswith(("read_", "validate_", "check_")) or re.search(r"read[- ]only", block, re.I)
            if declared and any(effect in block for effect in effects):
                findings.append(_witness(path, line, "token-declared-readonly-with-effect", function=name))
    return _oracle_result(cell, "p2.oracle.effect-token-walk", snapshot, findings)


def _code_objects(root: Any) -> list[Any]:
    values = [root]
    for constant in root.co_consts:
        if hasattr(constant, "co_code"):
            values.extend(_code_objects(constant))
    return values


def oracle_functional_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:FUNCTIONAL_FAULT:PERFORMANCE"
    sources = _python_sources(snapshot)
    if not sources:
        return _oracle_result(cell, "p2.oracle.bytecode-envelope", snapshot, (), empty=True)
    findings = []
    for path, source in sources:
        try:
            code = compile(source, path, "exec")
        except (SyntaxError, UnicodeError) as exc:
            raise MalformedSource(f"{path}: {exc}") from exc
        for item in _code_objects(code):
            doc = next((value for value in item.co_consts if isinstance(value, str) and "RESOURCE_MAX_BYTES" in value), None)
            if doc is None:
                continue
            names = set(item.co_names) | set(item.co_varnames)
            has_read = bool(names & {"read_bytes", "read_text", "read", "open"})
            has_guard = bool(names & {"_account_size", "enforce_limit", "read_bounded", "bounded_read", "max_bytes"})
            if has_read and not has_guard:
                findings.append(_witness(path, item.co_firstlineno, "bytecode-read-without-guard", function=item.co_name))
    return _oracle_result(cell, "p2.oracle.bytecode-envelope", snapshot, findings)


def oracle_risk_static(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:RISK_EXPOSURE:STATIC"
    sources = _python_sources(snapshot)
    if not sources:
        return _oracle_result(cell, "p2.oracle.authority-token-origin", snapshot, (), empty=True)
    findings = []
    pattern = re.compile(
        r"^\s*(?P<name>[A-Za-z_]\w*(?:trust|authority|key|policy)[A-Za-z_]*)\s*=\s*(?P<expr>.+)$",
        re.I,
    )
    for path, source in sources:
        for line_no, line in enumerate(source.splitlines(), 1):
            match = pattern.match(line)
            if match and re.search(r"getenv|environ|gettempdir|Path\.cwd|Path\.home", match.group("expr")):
                findings.append(
                    _witness(path, line_no, "token-authority-binding-to-runtime-root", target=match.group("name"))
                )
    return _oracle_result(cell, "p2.oracle.authority-token-origin", snapshot, findings)


def oracle_risk_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:RISK_EXPOSURE:SEMANTIC"
    files = snapshot.get("files", {})
    sources = _python_sources(snapshot)
    docs = [
        raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "replace")
        for path, raw in files.items()
        if path.endswith((".md", ".txt"))
    ]
    if not files:
        return _oracle_result(cell, "p2.oracle.reverse-authority-slice", snapshot, (), empty=True)
    says_none = any(re.search(r"(?:no|cannot|must not).{0,80}release authority", text, re.I | re.S) for text in docs)
    findings = []
    if says_none:
        for path, source in sources:
            for line_no, line in enumerate(source.splitlines(), 1):
                if re.search(r"release_authority\s*=\s*True|set_release_authority\s*\(\s*True", line):
                    findings.append(_witness(path, line_no, "reverse-authority-grant-slice"))
    return _oracle_result(cell, "p2.oracle.reverse-authority-slice", snapshot, findings)


def oracle_latent_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:LATENT_DEFECT:PERFORMANCE"
    sources = _python_sources(snapshot)
    if not sources:
        return _oracle_result(cell, "p2.oracle.backedge-work-audit", snapshot, (), empty=True)
    findings = []
    for path, source in sources:
        try:
            code = compile(source, path, "exec")
        except SyntaxError as exc:
            raise MalformedSource(f"{path}: {exc}") from exc
        for item in _code_objects(code):
            guards = set(item.co_varnames) | set(item.co_names)
            if guards & {"depth", "max_depth", "budget", "limit", "remaining", "max_nodes"}:
                continue
            if item.co_name not in item.co_names:
                continue
            instructions = list(dis.get_instructions(item))
            if any(instruction.opname.startswith("JUMP_BACKWARD") for instruction in instructions):
                recursive_line = next(
                    (instruction.positions.lineno for instruction in instructions
                     if instruction.opname in {"LOAD_GLOBAL", "LOAD_NAME"} and instruction.argval == item.co_name),
                    item.co_firstlineno,
                )
                findings.append(_witness(path, recursive_line or item.co_firstlineno, "bytecode-recursive-backedge-without-budget"))
    return _oracle_result(cell, "p2.oracle.backedge-work-audit", snapshot, findings)


def oracle_vulnerability_static(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:VULNERABILITY:STATIC"
    sources = _python_sources(snapshot)
    if not sources:
        return _oracle_result(cell, "p2.oracle.reverse-sink-slice", snapshot, (), empty=True)
    findings = []
    sanitizers = {"shlex.quote", "html.escape", "int", "float", "canonical_digest"}

    def tainted_expr(node: ast.AST) -> bool:
        if isinstance(node, ast.Call) and _qualified_name(node.func) in sanitizers:
            return False
        if isinstance(node, ast.Name) and node.id in tainted:
            return True
        return any(tainted_expr(child) for child in ast.iter_child_nodes(node))

    for path, source in sources:
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise MalformedSource(f"{path}: {exc}") from exc
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            params = {arg.arg for arg in function.args.args}
            tainted = params & {"user_input", "untrusted", "tainted"}
            changed = True
            while changed:
                changed = False
                for node in ast.walk(function):
                    if isinstance(node, ast.Assign):
                        if tainted_expr(node.value):
                            for target in node.targets:
                                if isinstance(target, ast.Name) and target.id not in tainted:
                                    tainted.add(target.id)
                                    changed = True
            for node in ast.walk(function):
                if not isinstance(node, ast.Call):
                    continue
                name = _qualified_name(node.func)
                is_sink = name in {"eval", "exec", "os.system"}
                if name.startswith("subprocess.") and any(
                    keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                    for keyword in node.keywords
                ):
                    is_sink = True
                if is_sink and tainted_expr(node):
                    findings.append(_witness(path, node.lineno, "reverse-slice-sink-to-untrusted-parameter", sink=name))
    return _oracle_result(cell, "p2.oracle.reverse-sink-slice", snapshot, findings)


def oracle_vulnerability_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:VULNERABILITY:SEMANTIC"
    sources = _python_sources(snapshot)
    if not sources:
        return _oracle_result(cell, "p2.oracle.trust-origin-lattice", snapshot, (), empty=True)
    findings = []
    for path, source in sources:
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise MalformedSource(f"{path}: {exc}") from exc
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            reads = {
                target.id
                for node in ast.walk(function)
                if isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and _qualified_name(node.value.func).endswith((".read_text", ".read_bytes"))
                for target in node.targets
                if isinstance(target, ast.Name)
            }
            if not reads:
                continue
            for node in ast.walk(function):
                if isinstance(node, ast.If) and any(isinstance(part, ast.Name) and part.id in reads for part in ast.walk(node.test)):
                    returns = [child for child in ast.walk(node) if isinstance(child, ast.Return)]
                    if any(
                        any(isinstance(part, ast.Constant) and part.value is True for part in ast.walk(item.value))
                        for item in returns
                        if item.value is not None
                    ):
                        findings.append(_witness(path, node.lineno, "lattice-origin-text-controls-trust"))
    return _oracle_result(cell, "p2.oracle.trust-origin-lattice", snapshot, findings)


def _nested_repeat_ast(parsed: Any) -> bool:
    def contains_repeat(items: Any) -> bool:
        for operation, argument in items:
            name = str(operation)
            if "MAX_REPEAT" in name or "MIN_REPEAT" in name:
                return True
            if isinstance(argument, re_parser.SubPattern) and contains_repeat(argument):
                return True
            if isinstance(argument, (list, tuple)):
                for child in argument:
                    if isinstance(child, re_parser.SubPattern) and contains_repeat(child):
                        return True
        return False

    def walk(items: Any) -> bool:
        for operation, argument in items:
            name = str(operation)
            if "MAX_REPEAT" in name or "MIN_REPEAT" in name:
                subpattern = argument[2] if isinstance(argument, tuple) and len(argument) >= 3 else None
                if isinstance(subpattern, re_parser.SubPattern) and contains_repeat(subpattern):
                    return True
            if isinstance(argument, re_parser.SubPattern) and walk(argument):
                return True
            if isinstance(argument, (list, tuple)):
                for child in argument:
                    if isinstance(child, re_parser.SubPattern) and walk(child):
                        return True
        return False

    return walk(parsed)


def oracle_vulnerability_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:VULNERABILITY:PERFORMANCE"
    sources = _python_sources(snapshot)
    if not sources:
        return _oracle_result(cell, "p2.oracle.regex-parse-ambiguity", snapshot, (), empty=True)
    findings = []
    for path, source in sources:
        try:
            tokens = _tokens(source)
        except MalformedSource:
            raise
        literals = [token.string for token in tokens if token.type == tokenize.STRING]
        for literal in literals:
            try:
                value = ast.literal_eval(literal)
            except (ValueError, SyntaxError):
                continue
            if not isinstance(value, str):
                continue
            try:
                parsed = re_parser.parse(value)
            except re.error:
                continue
            if _nested_repeat_ast(parsed):
                findings.append(_witness(path, 1, "regex-parse-tree-has-nested-repeat", pattern=value))
                break
    return _oracle_result(cell, "p2.oracle.regex-parse-ambiguity", snapshot, findings)


def oracle_omission_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:OMISSION:PERFORMANCE"
    sources = _python_sources(snapshot)
    profile = None
    for path, raw in snapshot.get("files", {}).items():
        if path.endswith("runtime-profile.json"):
            try:
                profile = json.loads(raw if isinstance(raw, str) else bytes(raw).decode())
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise MalformedSource(f"{path}: {exc}") from exc
    if not sources:
        return _oracle_result(cell, "p2.oracle.profile-ceiling-set", snapshot, (), empty=True)
    if profile is None:
        raise MalformedSource("runtime-profile.json is required")
    findings = []
    for operation in profile.get("operations", []):
        if operation.get("external_sinks") and not operation.get("limits"):
            findings.append(
                _witness(
                    "runtime-profile.json",
                    int(operation.get("line", 1)),
                    "profile-operation-has-no-resource-ceiling",
                    function=operation.get("function"),
                )
            )
    return _oracle_result(cell, "p2.oracle.profile-ceiling-set", snapshot, findings)


def oracle_inconsistency_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:INCONSISTENCY:SEMANTIC"
    sources = _python_sources(snapshot)
    docs = [
        raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "replace")
        for path, raw in snapshot.get("files", {}).items()
        if path.endswith((".md", ".txt"))
    ]
    expected = {}
    for text in docs:
        for state, status in re.findall(r"\b([A-Z][A-Z_]+)\s*=>\s*([A-Z][A-Z_]+)\b", text):
            expected[state] = status
    if not expected or not sources:
        return _oracle_result(cell, "p2.oracle.transition-execution", snapshot, (), empty=True)
    findings = []
    for path, source in sources:
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise MalformedSource(f"{path}: {exc}") from exc
        for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "transition"):
            emitted: dict[str, str] = {}
            for node in ast.walk(function):
                if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Dict):
                    continue
                for key, value in zip(node.value.keys, node.value.values):
                    if (
                        isinstance(key, ast.Constant)
                        and isinstance(key.value, str)
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)
                    ):
                        emitted[key.value] = value.value
            for state, status in expected.items():
                observed = emitted.get(state)
                if observed != status:
                    findings.append(
                        _witness(path, function.lineno, "transition-map-differs-from-doc", state=state, documented=status, actual=observed)
                    )
    return _oracle_result(cell, "p2.oracle.transition-execution", snapshot, findings)


def oracle_inconsistency_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:INCONSISTENCY:PERFORMANCE"
    sources = _python_sources(snapshot)
    manifest = {}
    for path, raw in snapshot.get("files", {}).items():
        if path.endswith(".json") and not path.endswith("runtime-profile.json"):
            try:
                manifest = json.loads(raw if isinstance(raw, str) else bytes(raw).decode())
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise MalformedSource(f"{path}: {exc}") from exc
    declared = manifest.get("timeout_seconds")
    if not sources or not isinstance(declared, (int, float)):
        return _oracle_result(cell, "p2.oracle.bytecode-timeout-recompute", snapshot, (), empty=True)
    findings = []
    for path, source in sources:
        try:
            code = compile(source, path, "exec")
        except SyntaxError as exc:
            raise MalformedSource(f"{path}: {exc}") from exc
        for item in _code_objects(code):
            if item.co_name == "<module>":
                continue
            if "subprocess" not in item.co_names and "run" not in item.co_names and "Popen" not in item.co_names:
                continue
            numeric = [value for value in item.co_consts if isinstance(value, (int, float)) and not isinstance(value, bool)]
            if numeric and declared not in numeric:
                findings.append(_witness(path, item.co_firstlineno, "bytecode-timeout-differs", declared=declared, constants=numeric))
    return _oracle_result(cell, "p2.oracle.bytecode-timeout-recompute", snapshot, findings)


def oracle_boundary_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:BOUNDARY:SEMANTIC"
    files = snapshot.get("files", {})
    if not files:
        return _oracle_result(cell, "p2.oracle.platform-path-identity", snapshot, (), empty=True)
    platform = str(snapshot.get("metadata", {}).get("platform", ""))
    if not platform:
        raise MalformedSource("platform metadata is required")
    buckets: dict[str, list[str]] = {}
    for path in files:
        normalized = unicodedata.normalize("NFKC", path.replace("\\", "/"))
        if platform == "windows":
            normalized = ntpath.normcase(ntpath.normpath(normalized))
        else:
            normalized = normalized.casefold() if platform == "darwin" else normalized
        buckets.setdefault(normalized, []).append(path)
    findings = [
        _witness(sorted(paths)[0], 1, "platform-identity-bucket-collision", paths=sorted(paths))
        for paths in buckets.values()
        if len(paths) > 1
    ]
    return _oracle_result(cell, "p2.oracle.platform-path-identity", snapshot, findings)


def oracle_boundary_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:BOUNDARY:PERFORMANCE"
    sources = _python_sources(snapshot)
    doc_text = "\n".join(
        raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "replace")
        for path, raw in snapshot.get("files", {}).items()
        if path.endswith((".md", ".txt"))
    )
    marker = re.search(r"BOUNDARY_MAX_BYTES\s*=\s*(\d+)\s+(INCLUSIVE|EXCLUSIVE)", doc_text)
    if not sources or not marker:
        return _oracle_result(cell, "p2.oracle.threshold-probe", snapshot, (), empty=True)
    limit, semantics = int(marker.group(1)), marker.group(2)
    findings = []
    for path, source in sources:
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise MalformedSource(f"{path}: {exc}") from exc
        function = next(
            (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "accepts"),
            None,
        )
        if function is None:
            continue
        comparison = next(
            (
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and node.comparators
                and isinstance(node.comparators[0], ast.Constant)
                and isinstance(node.comparators[0].value, int)
            ),
            None,
        )
        if comparison is None:
            continue
        boundary = int(comparison.comparators[0].value)
        operator = comparison.ops[0]
        results = {
            value: (
                value <= boundary
                if isinstance(operator, ast.LtE)
                else value < boundary
                if isinstance(operator, ast.Lt)
                else value >= boundary
                if isinstance(operator, ast.GtE)
                else value > boundary
                if isinstance(operator, ast.Gt)
                else value == boundary
                if isinstance(operator, ast.Eq)
                else value != boundary
            )
            for value in (limit - 1, limit, limit + 1)
        }
        expected = (
            {limit - 1: True, limit: True, limit + 1: False}
            if semantics == "INCLUSIVE"
            else {limit - 1: True, limit: False, limit + 1: False}
        )
        if results != expected:
            findings.append(_witness(path, function.lineno, "executed-threshold-probe-mismatch", observed=results, expected=expected))
    return _oracle_result(cell, "p2.oracle.threshold-probe", snapshot, findings)


def oracle_exception_static(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:EXCEPTION_PATH:STATIC"
    sources = _python_sources(snapshot)
    if not sources:
        return _oracle_result(cell, "p2.oracle.executed-exception-outcome", snapshot, (), empty=True)
    findings = []
    for path, source in sources:
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise MalformedSource(f"{path}: {exc}") from exc
        function = next(
            (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "run_task"),
            None,
        )
        if function is None:
            continue
        lines = source.splitlines()
        start = function.lineno - 1
        indent = len(lines[start]) - len(lines[start].lstrip())
        end = start + 1
        while end < len(lines):
            line = lines[end]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            end += 1
        block = "\n".join(lines[start:end])
        for match in re.finditer(
            r"except[^:]*:\s*(?:\r?\n[ \t]+)+(?P<body>.*?)(?=\r?\n\s*except\b|\Z)",
            block,
            re.S,
        ):
            handler = match.group("body")
            if re.search(r"\b(?:raise|append|observe|write_failure)\b", handler):
                continue
            returned = re.search(
                r"\breturn\s+(True|0|[\"'](?:pass|clean|ok|success|checked)[\"'])",
                handler,
                re.I,
            )
            if returned:
                findings.append(
                    _witness(
                        path,
                        function.lineno + block[: match.start()].count("\n"),
                        "token-handler-returns-success",
                        observed=returned.group(1),
                    )
                )
    return _oracle_result(cell, "p2.oracle.executed-exception-outcome", snapshot, findings)


def oracle_exception_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:EXCEPTION_PATH:SEMANTIC"
    sources = _python_sources(snapshot)
    if not sources:
        return _oracle_result(cell, "p2.oracle.cause-token-continuity", snapshot, (), empty=True)
    findings = []
    for path, source in sources:
        lines = source.splitlines()
        handlers: list[str | None] = []
        for line_no, line in enumerate(lines, 1):
            match = re.match(r"^(\s*)except(?:\s+\w+)?(?:\s+as\s+(\w+))?", line)
            if match:
                handlers.append(match.group(2))
                continue
            if not handlers:
                continue
            if re.search(r"^\s*raise\s+\w+\s*\(", line):
                if not re.search(r"\bfrom\s+" + re.escape(handlers[-1] or "__never__") + r"\b", line):
                    findings.append(_witness(path, line_no, "token-transformed-exception-drops-cause"))
            if line and len(line) - len(line.lstrip()) == 0:
                handlers.clear()
    return _oracle_result(cell, "p2.oracle.cause-token-continuity", snapshot, findings)


def oracle_exception_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:EXCEPTION_PATH:PERFORMANCE"
    sources = _python_sources(snapshot)
    if not sources:
        return _oracle_result(cell, "p2.oracle.bytecode-process-cleanup", snapshot, (), empty=True)
    findings = []
    for path, source in sources:
        try:
            code = compile(source, path, "exec")
        except SyntaxError as exc:
            raise MalformedSource(f"{path}: {exc}") from exc
        for item in _code_objects(code):
            if item.co_name == "<module>":
                continue
            names = set(item.co_names)
            if not (names & {"Popen", "run"}):
                continue
            constants = {
                value
                for constant in item.co_consts
                for value in (
                    constant
                    if isinstance(constant, tuple)
                    else (constant,)
                )
                if isinstance(value, str)
            }
            bounded = "communicate" in names and "timeout" in constants
            cleaned = bool(names & {"kill", "terminate", "kill_process_tree", "terminate_process_tree"})
            if not bounded or not cleaned:
                findings.append(_witness(path, item.co_firstlineno, "bytecode-process-path-lacks-bounds-or-cleanup", bounded=bounded, cleaned=cleaned))
    return _oracle_result(cell, "p2.oracle.bytecode-process-cleanup", snapshot, findings)


ORACLES = {
    "SKILL:FUNCTIONAL_FAULT:SEMANTIC": oracle_functional_semantic,
    "SKILL:FUNCTIONAL_FAULT:PERFORMANCE": oracle_functional_performance,
    "SKILL:RISK_EXPOSURE:STATIC": oracle_risk_static,
    "SKILL:RISK_EXPOSURE:SEMANTIC": oracle_risk_semantic,
    "SKILL:LATENT_DEFECT:PERFORMANCE": oracle_latent_performance,
    "SKILL:VULNERABILITY:STATIC": oracle_vulnerability_static,
    "SKILL:VULNERABILITY:SEMANTIC": oracle_vulnerability_semantic,
    "SKILL:VULNERABILITY:PERFORMANCE": oracle_vulnerability_performance,
    "SKILL:OMISSION:PERFORMANCE": oracle_omission_performance,
    "SKILL:INCONSISTENCY:SEMANTIC": oracle_inconsistency_semantic,
    "SKILL:INCONSISTENCY:PERFORMANCE": oracle_inconsistency_performance,
    "SKILL:BOUNDARY:SEMANTIC": oracle_boundary_semantic,
    "SKILL:BOUNDARY:PERFORMANCE": oracle_boundary_performance,
    "SKILL:EXCEPTION_PATH:STATIC": oracle_exception_static,
    "SKILL:EXCEPTION_PATH:SEMANTIC": oracle_exception_semantic,
    "SKILL:EXCEPTION_PATH:PERFORMANCE": oracle_exception_performance,
}


def run_oracle(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    try:
        validate_python_syntax(snapshot)
        return ORACLES[cell_id](snapshot)
    except MalformedSource as exc:
        body = {
            "schema_version": 2,
            "cell_id": cell_id,
            "detector_id": "p2.oracle",
            "receipt_kind": "ORACLE",
            "status": "BLOCKED_MALFORMED",
            "error": str(exc),
            "subject_digest": source_digest(snapshot),
        }
        body["fact_set_digest"] = canonical_digest(body)
        return body


if __name__ == "__main__":
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(json.dumps(run_oracle(payload["cell_id"], payload["snapshot"]), ensure_ascii=False, sort_keys=True))
