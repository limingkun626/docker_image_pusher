from __future__ import annotations

import ast
import hashlib
import json
import re
import unicodedata
from collections import deque
from pathlib import Path
from typing import Any, Iterable, Mapping


class MalformedSource(ValueError):
    pass


def canonical_digest(value: Any) -> str:
    data = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def source_digest(snapshot: Mapping[str, Any]) -> str:
    files = snapshot.get("files", {})
    material = {
        path: hashlib.sha256(
            value.encode("utf-8") if isinstance(value, str) else bytes(value)
        ).hexdigest()
        for path, value in sorted(files.items())
    }
    return canonical_digest(material)


def result(
    cell_id: str,
    detector_id: str,
    invariant_id: str,
    predicate: str,
    snapshot: Mapping[str, Any],
    findings: Iterable[Mapping[str, Any]],
    *,
    empty: bool = False,
) -> dict[str, Any]:
    facts = [dict(item) for item in findings]
    if empty:
        status = "EMPTY_RESULT"
    else:
        status = "FINDING" if facts else "CLEAN"
    body = {
        "schema_version": 2,
        "cell_id": cell_id,
        "detector_id": detector_id,
        "detector_version": "1.0.0",
        "invariant_id": invariant_id,
        "predicate_id": predicate,
        "subject_digest": source_digest(snapshot),
        "status": status,
        "findings": facts,
    }
    body["fact_set_digest"] = canonical_digest(body)
    return body


def _python_trees(
    snapshot: Mapping[str, Any],
) -> list[tuple[str, str, ast.Module]]:
    trees = []
    for path, raw in sorted(snapshot.get("files", {}).items()):
        if not path.endswith(".py"):
            continue
        text = raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "strict")
        try:
            trees.append((path, text, ast.parse(text)))
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise MalformedSource(f"{path}: {type(exc).__name__}: {exc}") from exc
    return trees


def validate_python_syntax(snapshot: Mapping[str, Any]) -> None:
    for path, raw in sorted(snapshot.get("files", {}).items()):
        if not path.endswith(".py"):
            continue
        text = raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "strict")
        try:
            ast.parse(text)
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise MalformedSource(f"{path}: {type(exc).__name__}: {exc}") from exc


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _qualified_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


def _call_names(tree: ast.AST) -> list[tuple[ast.Call, str, int]]:
    values = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            values.append((node, _qualified_name(node.func), node.lineno))
    values.sort(key=lambda item: (item[2], item[1]))
    return values


def _contains_name(tree: ast.AST, names: set[str], prefixes: tuple[str, ...] = ()) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in names:
            return True
        if isinstance(node, ast.Call):
            name = _qualified_name(node.func)
            if name in names or any(name.startswith(prefix) for prefix in prefixes):
                return True
    return False


def _finding(
    *,
    path: str,
    line: int,
    witness: str,
    mechanism: str,
    value: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    item = {
        "witness": witness,
        "path": path,
        "line": line,
        "mechanism": mechanism,
        "value": dict(value or {}),
    }
    item["witness_id"] = canonical_digest(item)
    return item


def functional_fault_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:FUNCTIONAL_FAULT:SEMANTIC"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.functional.effect-mismatch", "P2-F01", "declared-effect-vs-sink", snapshot, (), empty=True)
    findings = []
    sinks = {
        "write_text",
        "write_bytes",
        "unlink",
        "mkdir",
        "os.system",
        "subprocess.run",
        "subprocess.Popen",
        "requests.get",
        "requests.post",
        "urlopen",
    }
    for path, _text, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            doc = (ast.get_docstring(node) or "").lower()
            declared_read_only = (
                node.name.startswith(("read_", "validate_", "check_"))
                or "read-only" in doc
                or "read only" in doc
            )
            if not declared_read_only:
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _qualified_name(child.func)
                    short_name = name.rsplit(".", 1)[-1]
                    if short_name in sinks or name in sinks or name.startswith(("requests.", "subprocess.")):
                        findings.append(
                            _finding(
                                path=path,
                                line=child.lineno,
                                witness="declared-read-only-reaches-effect",
                                mechanism="A read/validate/check contract reaches a mutating, network, or process effect.",
                                value={"function": node.name, "effect": name},
                            )
                        )
                        break
            if findings and findings[-1]["path"] == path:
                break
    return result(cell, "p2.functional.effect-mismatch", "P2-F01", "declared-effect-vs-sink", snapshot, findings)


def functional_fault_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:FUNCTIONAL_FAULT:PERFORMANCE"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.functional.resource-envelope", "P2-F02", "declared-envelope-vs-enforced-guard", snapshot, (), empty=True)
    findings = []
    read_calls = {"read_bytes", "read_text", "os.read", "open"}
    guard_calls = {"_account_size", "enforce_limit", "read_bounded", "bounded_read"}
    for path, _text, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            doc = ast.get_docstring(node) or ""
            if "RESOURCE_MAX_BYTES" not in doc:
                continue
            has_read = any(
                isinstance(child, ast.Call)
                and (
                    _qualified_name(child.func) in read_calls
                    or _qualified_name(child.func).endswith(tuple(read_calls))
                )
                for child in ast.walk(node)
            )
            has_guard = _contains_name(node, guard_calls) or any(
                arg.arg in {"limits", "max_bytes"} for arg in node.args.args
            )
            if has_read and not has_guard:
                findings.append(
                    _finding(
                        path=path,
                        line=node.lineno,
                        witness="resource-read-without-envelope-guard",
                        mechanism="A function declares a byte envelope but performs unbounded source reads without the matching guard.",
                        value={"function": node.name, "declared_marker": "RESOURCE_MAX_BYTES"},
                    )
                )
    return result(cell, "p2.functional.resource-envelope", "P2-F02", "declared-envelope-vs-enforced-guard", snapshot, findings)


def risk_exposure_static(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:RISK_EXPOSURE:STATIC"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.risk.sensitive-binding", "P2-R01", "authority-binding-origin", snapshot, (), empty=True)
    findings = []
    authority_words = ("trust", "authority", "private_key", "signing_key", "policy")
    dynamic_roots = {"os.getenv", "os.environ.get", "tempfile.gettempdir", "Path.cwd", "Path.home"}
    for path, _text, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [target.id for target in targets if isinstance(target, ast.Name)]
            if not any(any(word in name.lower() for word in authority_words) for name in names):
                continue
            value = node.value
            if value is None:
                continue
            dynamic = _contains_name(value, dynamic_roots)
            if isinstance(value, ast.Subscript) and "os.environ" in _qualified_name(value.value):
                dynamic = True
            if dynamic:
                findings.append(
                    _finding(
                        path=path,
                        line=node.lineno,
                        witness="authority-bound-to-mutable-runtime-root",
                        mechanism="A trust-sensitive artifact is bound through cwd, home, temporary, or environment state.",
                        value={"targets": names, "source": ast.dump(value)},
                    )
                )
    return result(cell, "p2.risk.sensitive-binding", "P2-R01", "authority-binding-origin", snapshot, findings)


def risk_exposure_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:RISK_EXPOSURE:SEMANTIC"
    trees = _python_trees(snapshot)
    docs = [
        (path, raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "replace"))
        for path, raw in sorted(snapshot.get("files", {}).items())
        if path.endswith((".md", ".txt"))
    ]
    if not trees and not docs:
        return result(cell, "p2.risk.authority-drift", "P2-R02", "documented-vs-effective-release-authority", snapshot, (), empty=True)
    no_authority = any(
        re.search(r"(?:no|cannot|must not|has zero).{0,80}release authority", text, re.I | re.S)
        for _path, text in docs
    )
    if not no_authority:
        return result(cell, "p2.risk.authority-drift", "P2-R02", "documented-vs-effective-release-authority", snapshot, ())
    findings = []
    for path, _text, tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = [_qualified_name(target) for target in node.targets]
                if any("release_authority" in target for target in targets) and isinstance(node.value, ast.Constant) and node.value.value is True:
                    findings.append(
                        _finding(
                            path=path,
                            line=node.lineno,
                            witness="documented-no-authority-code-grants-authority",
                            mechanism="The documented non-authority boundary is contradicted by an effective authority grant.",
                            value={"targets": targets},
                        )
                    )
            if isinstance(node, ast.Call) and _qualified_name(node.func) in {"set_release_authority", "grant_release_authority"}:
                if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value is True:
                    findings.append(
                        _finding(
                            path=path,
                            line=node.lineno,
                            witness="documented-no-authority-code-grants-authority",
                            mechanism="The documented non-authority boundary is contradicted by an authority grant call.",
                            value={"call": _qualified_name(node.func)},
                        )
                    )
    return result(cell, "p2.risk.authority-drift", "P2-R02", "documented-vs-effective-release-authority", snapshot, findings)


def latent_defect_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:LATENT_DEFECT:PERFORMANCE"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.latent.work-amplification", "P2-L01", "recursive-work-without-budget", snapshot, (), empty=True)
    findings = []
    loop_types = (ast.For, ast.AsyncFor, ast.While, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
    guard_names = {"depth", "max_depth", "budget", "limit", "remaining", "max_nodes"}
    for path, _text, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            recursive_lines = []
            for child in ast.walk(node):
                if not isinstance(child, loop_types):
                    continue
                for call in ast.walk(child):
                    if isinstance(call, ast.Call) and _qualified_name(call.func) == node.name:
                        recursive_lines.append(call.lineno)
            if recursive_lines and not _contains_name(node, guard_names):
                findings.append(
                    _finding(
                        path=path,
                        line=recursive_lines[0],
                        witness="recursive-call-inside-iteration-without-work-budget",
                        mechanism="A recursive traversal can amplify work with nested input and has no depth/node budget.",
                        value={"function": node.name},
                    )
                )
    return result(cell, "p2.latent.work-amplification", "P2-L01", "recursive-work-without-budget", snapshot, findings)


class _TaintFlow(ast.NodeVisitor):
    def __init__(self, sources: set[str], sanitizers: set[str]):
        self.sources = sources
        self.sanitizers = sanitizers
        self.tainted: set[str] = set()
        self.findings: list[tuple[int, str]] = []

    def _expr_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted or node.id in self.sources
        if isinstance(node, ast.Subscript):
            return self._expr_tainted(node.value)
        if isinstance(node, ast.Attribute):
            return self._expr_tainted(node.value)
        if isinstance(node, ast.Call):
            name = _qualified_name(node.func)
            if name in self.sanitizers:
                return False
            if name in {"sys.argv", "os.getenv", "os.environ.get"} or name.endswith((".read_text", ".read_bytes")):
                return True
            return any(self._expr_tainted(arg) for arg in node.args)
        return any(self._expr_tainted(child) for child in ast.iter_child_nodes(node))

    def _assign(self, targets: list[ast.AST], value: ast.AST) -> None:
        tainted = self._expr_tainted(value)
        for target in targets:
            if isinstance(target, ast.Name):
                if tainted:
                    self.tainted.add(target.id)
                else:
                    self.tainted.discard(target.id)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._assign(list(node.targets), node.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.sources.update(
            arg.arg for arg in node.args.args if arg.arg.lower() in {"user_input", "untrusted", "tainted"}
        )
        for statement in node.body:
            self.visit(statement)


def vulnerability_static(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:VULNERABILITY:STATIC"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.vulnerability.unsafe-dataflow", "P2-V01", "untrusted-source-to-execution-sink", snapshot, (), empty=True)
    findings = []
    sanitizers = {"shlex.quote", "html.escape", "int", "float", "canonical_digest"}
    for path, _text, tree in trees:
        visitor = _TaintFlow(set(), sanitizers)
        visitor.visit(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _qualified_name(node.func)
            unsafe = (
                name in {"eval", "exec", "os.system"}
                and any(visitor._expr_tainted(arg) for arg in node.args)
            )
            if name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call"}:
                shell = any(
                    keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                    for keyword in node.keywords
                )
                unsafe = unsafe or (shell and bool(node.args) and visitor._expr_tainted(node.args[0]))
            if unsafe:
                findings.append(
                    _finding(
                        path=path,
                        line=node.lineno,
                        witness="untrusted-value-reaches-execution-sink",
                        mechanism="Untrusted data reaches a process, shell, or dynamic-evaluation sink without an admitted sanitizer.",
                        value={"sink": name},
                    )
                )
    return result(cell, "p2.vulnerability.unsafe-dataflow", "P2-V01", "untrusted-source-to-execution-sink", snapshot, findings)


def vulnerability_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:VULNERABILITY:SEMANTIC"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.vulnerability.trust-decision", "P2-V02", "untrusted-text-to-trust-decision", snapshot, (), empty=True)
    findings = []
    decision_keys = {"trusted", "trust", "release_ready", "status", "decision", "allowed"}
    for path, _text, tree in trees:
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            tainted: set[str] = set()
            for statement in function.body:
                for node in ast.walk(statement):
                    if isinstance(node, ast.Assign):
                        value_tainted = isinstance(node.value, ast.Call) and _qualified_name(node.value.func).endswith(
                            (".read_text", ".read_bytes")
                        )
                        if value_tainted:
                            tainted.update(target.id for target in node.targets if isinstance(target, ast.Name))
                    if isinstance(node, ast.If):
                        test_tainted = any(isinstance(part, ast.Name) and part.id in tainted for part in ast.walk(node.test))
                        if not test_tainted:
                            continue
                        for child in ast.walk(node):
                            keys: list[str] = []
                            if isinstance(child, ast.Dict):
                                keys = [key.value for key in child.keys if isinstance(key, ast.Constant) and isinstance(key.value, str)]
                            if any(key in decision_keys for key in keys) or (
                                isinstance(child, ast.Return) and child.value is not None
                                and any(isinstance(part, ast.Constant) and part.value is True for part in ast.walk(child.value))
                            ):
                                findings.append(
                                    _finding(
                                        path=path,
                                        line=node.lineno,
                                        witness="repository-text-controls-trust-decision",
                                        mechanism="Untrusted repository text influences a trust, release, or status decision without digest/origin separation.",
                                        value={"function": function.name, "decision_keys": keys},
                                    )
                                )
                                break
    return result(cell, "p2.vulnerability.trust-decision", "P2-V02", "untrusted-text-to-trust-decision", snapshot, findings)


def _nested_quantifier(pattern: str) -> bool:
    for match in re.finditer(r"\((?:\?:)?([^()]*)\)([+*]|\{\d+(?:,\d*)?\})", pattern):
        inner, outer = match.group(1), match.group(2)
        if outer and re.search(r"([+*]|\{\d+(?:,\d*)?\})", inner):
            return True
        branches = inner.split("|")
        if outer and any(a and b and (a.startswith(b) or b.startswith(a)) for a in branches for b in branches if a != b):
            return True
    return False


def vulnerability_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:VULNERABILITY:PERFORMANCE"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.vulnerability.redos", "P2-V03", "attacker-controlled-regex-backtracking", snapshot, (), empty=True)
    findings = []
    for path, _text, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _qualified_name(node.func)
            if name not in {"re.search", "re.match", "re.fullmatch", "re.findall", "re.compile"}:
                continue
            literal = None
            if name == "re.compile" and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                literal = node.args[0].value
            elif len(node.args) >= 2 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                literal = node.args[0].value
            if literal and _nested_quantifier(literal):
                input_arg = node.args[1] if len(node.args) > 1 else None
                attacker_controlled = input_arg is None or any(
                    isinstance(part, ast.Name) and part.id.lower() in {"text", "data", "user_input", "untrusted"}
                    for part in ast.walk(input_arg)
                ) or any(
                    isinstance(part, ast.Call) and _qualified_name(part.func).endswith((".read_text", ".read_bytes"))
                    for part in ast.walk(input_arg)
                )
                if attacker_controlled:
                    findings.append(
                        _finding(
                            path=path,
                            line=node.lineno,
                            witness="nested-quantifier-on-attacker-text",
                            mechanism="A nested quantified regular expression is applied to attacker-controlled text without a match budget.",
                            value={"pattern": literal, "call": name},
                        )
                    )
    return result(cell, "p2.vulnerability.redos", "P2-V03", "attacker-controlled-regex-backtracking", snapshot, findings)


def omission_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:OMISSION:PERFORMANCE"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.omission.resource-ceiling", "P2-O01", "external-work-has-explicit-ceiling", snapshot, (), empty=True)
    findings = []
    sinks = {"subprocess.run", "subprocess.Popen", "Path.read_text", "Path.read_bytes", "os.read"}
    ceiling_args = {"limits", "timeout", "timeout_seconds", "max_bytes", "memory_mib", "max_files"}
    guard_names = {"enforce_limits", "enforce_limit", "bounded_read", "read_bounded"}
    for path, _text, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            has_external = any(
                isinstance(child, ast.Call)
                and (
                    _qualified_name(child.func) in sinks
                    or _qualified_name(child.func).endswith((".read_text", ".read_bytes"))
                    or _qualified_name(child.func) in {"read_text", "read_bytes"}
                )
                for child in ast.walk(node)
            )
            if not has_external:
                continue
            arg_names = {arg.arg for arg in node.args.args}
            has_ceiling = bool(arg_names & ceiling_args) or _contains_name(node, guard_names)
            if not has_ceiling:
                findings.append(
                    _finding(
                        path=path,
                        line=node.lineno,
                        witness="external-input-without-resource-ceiling",
                        mechanism="A file or process operation consumes externally sized work without a declared timeout, memory, file, or byte ceiling.",
                        value={"function": node.name, "arguments": sorted(arg_names)},
                    )
                )
    return result(cell, "p2.omission.resource-ceiling", "P2-O01", "external-work-has-explicit-ceiling", snapshot, findings)


def inconsistency_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:INCONSISTENCY:SEMANTIC"
    trees = _python_trees(snapshot)
    docs = [
        raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "replace")
        for path, raw in sorted(snapshot.get("files", {}).items())
        if path.endswith((".md", ".txt"))
    ]
    doc_map: dict[str, str] = {}
    for text in docs:
        for state, status in re.findall(r"\b([A-Z][A-Z_]+)\s*=>\s*([A-Z][A-Z_]+)\b", text):
            doc_map[state] = status
    if not doc_map or not trees:
        return result(cell, "p2.inconsistency.status-drift", "P2-I01", "documented-state-status-map", snapshot, (), empty=True)
    code_map: dict[tuple[str, str], str] = {}
    for path, _text, tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
                pairs = zip(node.value.keys, node.value.values)
                for key, value in pairs:
                    if isinstance(key, ast.Constant) and isinstance(value, ast.Constant):
                        code_map[(path, str(key.value))] = str(value.value)
    findings = []
    for (path, state), status in code_map.items():
        if state in doc_map and doc_map[state] != status:
            findings.append(
                _finding(
                    path=path,
                    line=1,
                    witness="documented-status-differs-from-code-status",
                    mechanism="A documented state-to-status mapping disagrees with the mapping emitted by code.",
                    value={"state": state, "documented": doc_map[state], "code": status},
                )
            )
    return result(cell, "p2.inconsistency.status-drift", "P2-I01", "documented-state-status-map", snapshot, findings)


def inconsistency_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:INCONSISTENCY:PERFORMANCE"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.inconsistency.budget-drift", "P2-I02", "declared-vs-effective-timeout", snapshot, (), empty=True)
    manifest: dict[str, Any] = {}
    for path, raw in snapshot.get("files", {}).items():
        if path.endswith(".json"):
            try:
                parsed = json.loads(raw if isinstance(raw, str) else bytes(raw).decode())
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise MalformedSource(f"{path}: {type(exc).__name__}: {exc}") from exc
            if isinstance(parsed, dict):
                manifest.update(parsed)
    declared = manifest.get("timeout_seconds")
    if not isinstance(declared, (int, float)):
        return result(cell, "p2.inconsistency.budget-drift", "P2-I02", "declared-vs-effective-timeout", snapshot, (), empty=True)
    findings = []
    for path, _text, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _qualified_name(node.func) not in {"subprocess.run", "subprocess.Popen"}:
                continue
            timeout = next((keyword.value for keyword in node.keywords if keyword.arg == "timeout"), None)
            effective = timeout.value if isinstance(timeout, ast.Constant) and isinstance(timeout.value, (int, float)) else None
            if effective != declared:
                findings.append(
                    _finding(
                        path=path,
                        line=node.lineno,
                        witness="declared-timeout-differs-from-call-timeout",
                        mechanism="The frozen manifest and the effective process call disagree on the timeout budget.",
                        value={"declared": declared, "effective": effective},
                    )
                )
    return result(cell, "p2.inconsistency.budget-drift", "P2-I02", "declared-vs-effective-timeout", snapshot, findings)


def boundary_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:BOUNDARY:SEMANTIC"
    files = snapshot.get("files", {})
    if not files:
        return result(cell, "p2.boundary.path-identity", "P2-B01", "raw-path-normalized-identity", snapshot, (), empty=True)
    platform = snapshot.get("metadata", {}).get("platform")
    if not platform:
        raise MalformedSource("platform metadata is required")
    platform = str(platform)
    if platform not in {"windows", "linux", "darwin"}:
        raise MalformedSource(f"unknown platform: {platform}")
    buckets: dict[str, list[str]] = {}
    for path in files:
        normalized = unicodedata.normalize("NFC", path).replace("\\", "/")
        if platform == "windows":
            normalized = normalized.casefold()
        buckets.setdefault(normalized, []).append(path)
    findings = []
    for normalized, paths in sorted(buckets.items()):
        if len(paths) > 1:
            findings.append(
                _finding(
                    path=sorted(paths)[0],
                    line=1,
                    witness="raw-paths-collapse-to-one-filesystem-identity",
                    mechanism="Distinct raw locators collapse to one case/normalization identity on the frozen platform.",
                    value={"normalized": normalized, "paths": sorted(paths)},
                )
            )
    return result(cell, "p2.boundary.path-identity", "P2-B01", "raw-path-normalized-identity", snapshot, findings)


def boundary_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:BOUNDARY:PERFORMANCE"
    trees = _python_trees(snapshot)
    doc_text = "\n".join(
        raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "replace")
        for path, raw in snapshot.get("files", {}).items()
        if path.endswith((".md", ".txt"))
    )
    marker = re.search(r"BOUNDARY_MAX_BYTES\s*=\s*(\d+)\s+(INCLUSIVE|EXCLUSIVE)", doc_text)
    if not trees or not marker:
        return result(cell, "p2.boundary.threshold-transition", "P2-B02", "documented-threshold-operator", snapshot, (), empty=True)
    maximum, semantics = int(marker.group(1)), marker.group(2)
    findings = []
    for path, _text, tree in trees:
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            for node in ast.walk(function):
                if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
                    continue
                right = node.comparators[0]
                if not (isinstance(right, ast.Constant) and right.value == maximum):
                    continue
                operator = type(node.ops[0]).__name__
                wrong = (
                    semantics == "INCLUSIVE" and operator in {"Lt", "GtE"}
                ) or (
                    semantics == "EXCLUSIVE" and operator in {"LtE", "Gt"}
                )
                if wrong:
                    findings.append(
                        _finding(
                            path=path,
                            line=node.lineno,
                            witness="operator-excludes-or-includes-wrong-threshold-side",
                            mechanism="The comparison operator disagrees with the frozen inclusive/exclusive boundary contract.",
                            value={"maximum": maximum, "semantics": semantics, "operator": operator, "function": function.name},
                        )
                    )
    return result(cell, "p2.boundary.threshold-transition", "P2-B02", "documented-threshold-operator", snapshot, findings)


def exception_path_static(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:EXCEPTION_PATH:STATIC"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.exception.fail-open", "P2-E01", "handler-terminal-state", snapshot, (), empty=True)
    findings = []
    success_constants = {"pass", "clean", "ok", "success", "checked"}
    for path, _text, tree in trees:
        for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
            has_evidence = _contains_name(
                handler,
                {"append", "observe", "blocked", "raise", "write_failure"},
                prefixes=("journal.", "observations."),
            )
            if has_evidence:
                continue
            for node in ast.walk(handler):
                if not isinstance(node, ast.Return):
                    continue
                value = node.value
                fail_open = (
                    isinstance(value, ast.Constant)
                    and (
                        value.value in success_constants
                        or (
                            isinstance(value.value, str)
                            and value.value.lower() in success_constants
                        )
                        or value.value is True
                        or value.value == 0
                    )
                )
                if fail_open:
                    findings.append(
                        _finding(
                            path=path,
                            line=node.lineno,
                            witness="exception-handler-returns-success-without-evidence",
                            mechanism="The exceptional path terminates as success without re-raise, blocked status, or durable observation.",
                            value={"returned": value.value},
                        )
                    )
                    break
    return result(cell, "p2.exception.fail-open", "P2-E01", "handler-terminal-state", snapshot, findings)


def exception_path_semantic(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:EXCEPTION_PATH:SEMANTIC"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.exception.cause-continuity", "P2-E02", "transformed-exception-retains-cause", snapshot, (), empty=True)
    findings = []
    for path, _text, tree in trees:
        for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
            for node in ast.walk(handler):
                if not isinstance(node, ast.Raise) or node.exc is None:
                    continue
                if isinstance(node.exc, ast.Call):
                    cause = node.cause
                    continuous = (
                        isinstance(cause, ast.Name)
                        and handler.name is not None
                        and cause.id == handler.name
                    ) or (
                        isinstance(cause, ast.Call)
                        and any(
                            keyword.arg in {"cause", "original", "source_exc"}
                            for keyword in node.exc.keywords
                        )
                    )
                    if not continuous:
                        findings.append(
                            _finding(
                                path=path,
                                line=node.lineno,
                                witness="exception-transformed-without-cause-continuity",
                                mechanism="A replacement exception drops the caught exception's causal or rollback context.",
                                value={"handler_exception": handler.name or "bare"},
                            )
                        )
    return result(cell, "p2.exception.cause-continuity", "P2-E02", "transformed-exception-retains-cause", snapshot, findings)


def exception_path_performance(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cell = "SKILL:EXCEPTION_PATH:PERFORMANCE"
    trees = _python_trees(snapshot)
    if not trees:
        return result(cell, "p2.exception.timeout-cleanup", "P2-E03", "bounded-wait-and-tree-cleanup", snapshot, (), empty=True)
    findings = []
    for path, _text, tree in trees:
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
            process_calls = [
                node for node in calls
                if _qualified_name(node.func) in {"subprocess.run", "subprocess.Popen"}
            ]
            if not process_calls:
                continue
            bounded_wait = any(
                _qualified_name(node.func).endswith(".communicate")
                and any(keyword.arg == "timeout" for keyword in node.keywords)
                for node in calls
            ) or any(
                any(keyword.arg == "timeout" for keyword in node.keywords)
                for node in process_calls
            )
            cleaned = any(
                _qualified_name(node.func).endswith((".kill", ".terminate", "kill_process_tree", "terminate_process_tree"))
                for node in calls
            )
            if not bounded_wait or not cleaned:
                first = process_calls[0]
                findings.append(
                    _finding(
                        path=path,
                        line=first.lineno,
                        witness="process-exception-path-lacks-bounded-wait-or-cleanup",
                        mechanism="A process failure path can wait indefinitely or leave children running.",
                        value={"function": function.name, "bounded_wait": bounded_wait, "cleanup": cleaned},
                    )
                )
    return result(cell, "p2.exception.timeout-cleanup", "P2-E03", "bounded-wait-and-tree-cleanup", snapshot, findings)


DETECTORS = {
    "SKILL:FUNCTIONAL_FAULT:SEMANTIC": functional_fault_semantic,
    "SKILL:FUNCTIONAL_FAULT:PERFORMANCE": functional_fault_performance,
    "SKILL:RISK_EXPOSURE:STATIC": risk_exposure_static,
    "SKILL:RISK_EXPOSURE:SEMANTIC": risk_exposure_semantic,
    "SKILL:LATENT_DEFECT:PERFORMANCE": latent_defect_performance,
    "SKILL:VULNERABILITY:STATIC": vulnerability_static,
    "SKILL:VULNERABILITY:SEMANTIC": vulnerability_semantic,
    "SKILL:VULNERABILITY:PERFORMANCE": vulnerability_performance,
    "SKILL:OMISSION:PERFORMANCE": omission_performance,
    "SKILL:INCONSISTENCY:SEMANTIC": inconsistency_semantic,
    "SKILL:INCONSISTENCY:PERFORMANCE": inconsistency_performance,
    "SKILL:BOUNDARY:SEMANTIC": boundary_semantic,
    "SKILL:BOUNDARY:PERFORMANCE": boundary_performance,
    "SKILL:EXCEPTION_PATH:STATIC": exception_path_static,
    "SKILL:EXCEPTION_PATH:SEMANTIC": exception_path_semantic,
    "SKILL:EXCEPTION_PATH:PERFORMANCE": exception_path_performance,
}


def run_native(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    try:
        validate_python_syntax(snapshot)
        return DETECTORS[cell_id](snapshot)
    except MalformedSource as exc:
        body = {
            "schema_version": 2,
            "cell_id": cell_id,
            "detector_id": "p2.native",
            "status": "BLOCKED_MALFORMED",
            "error": str(exc),
            "subject_digest": source_digest(snapshot),
        }
        body["fact_set_digest"] = canonical_digest(body)
        return body


if __name__ == "__main__":
    import sys

    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(json.dumps(run_native(payload["cell_id"], payload["snapshot"]), ensure_ascii=False, sort_keys=True))
