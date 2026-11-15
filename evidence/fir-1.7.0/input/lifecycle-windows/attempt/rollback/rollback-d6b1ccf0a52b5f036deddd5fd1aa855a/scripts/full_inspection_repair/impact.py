from __future__ import annotations

import ast
import re
from collections import deque
from collections.abc import Iterable
from pathlib import PurePosixPath

from .adapters import Subject
from .contracts import ContractError, canonical_digest
from .file_classes import (
    BINARY_OPAQUE,
    CACHE_ARTIFACT,
    CONFIGURATION,
    DOCUMENTATION,
    TEST_SOURCE,
    classify_file,
)

MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
URI_SCHEME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
QUOTED_REFERENCE_PATTERN = re.compile(r"""["']([^"'\r\n]+)["']""")
PATH_TOKEN_PATTERN = re.compile(
    r"""((?<![\w./-])(?:\.{0,2}/)?(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.[A-Za-z0-9]+)"""
)
JS_IMPORT_PATTERN = re.compile(
    r"""(?:\bfrom\s+|\bimport\s*\(\s*|\brequire\s*\(\s*)["']([^"']+)["']"""
)
HTML_REFERENCE_PATTERN = re.compile(
    r"""(?:\bsrc|\bhref)\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
CSS_REFERENCE_PATTERN = re.compile(r"""\burl\(\s*["']?([^"')]+)["']?\s*\)""")
TEST_COMMAND_PATTERN = re.compile(
    r"""\b(?:python(?:\.exe)?\s+-m\s+)?pytest\b[^\r\n]*?([A-Za-z0-9_./\\-]+\.[A-Za-z0-9]+)"""
)
CONSUMER_EDGE_KINDS = frozenset(
    {
        "IMPORTS",
        "IMPORTS_DYNAMIC",
        "REFERENCES",
        "JS_IMPORT",
        "COMMAND_REF",
        "CONFIG_REF",
        "TEST_REF",
        "RUNTIME_LOAD",
        "LIFECYCLE_REF",
        "EXTERNAL_DEPENDENCY",
    }
)
REFERENCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".ps1",
        ".psm1",
        ".sh",
        ".bash",
        ".zsh",
        ".md",
        ".markdown",
        ".json",
        ".jsonl",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".xml",
        ".html",
        ".css",
    }
)
SCANNER_REGISTRY_DIGEST = canonical_digest(
    {
        "scanner_set": "fir-impact-scanners",
        "version": "1.0.0",
        "edge_kinds": sorted(CONSUMER_EDGE_KINDS),
    }
)


def _local_reference(source: str, raw_target: str, known: set[str]) -> str | None:
    candidate = _normalize_local_reference(source, raw_target)
    if candidate is None:
        return None
    target_id = f"file:{candidate}"
    return target_id if target_id in known else None


def _normalize_local_reference(source: str, raw_target: str) -> str | None:
    target = raw_target.strip().split("#", 1)[0]
    if not target or URI_SCHEME_PATTERN.match(target):
        return None
    source_path = PurePosixPath(source)
    resolved = (source_path.parent / target).as_posix()
    normalized = PurePosixPath(resolved)
    parts: list[str] = []
    for part in normalized.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return PurePosixPath(*parts).as_posix()


def _module_target(file_ids: set[str], module: PurePosixPath) -> str | None:
    path = module.as_posix()
    candidates = (f"file:{path}.py", f"file:{path}/__init__.py")
    exact = next((candidate for candidate in candidates if candidate in file_ids), None)
    if exact is not None:
        return exact
    suffix_files = (
        f"/{path}.py",
        f"/{path}/__init__.py",
    )
    matches = sorted(
        candidate
        for candidate in file_ids
        if any(candidate.endswith(suffix) for suffix in suffix_files)
    )
    return matches[0] if len(matches) == 1 else None


def _local_missing(file_ids: set[str], module: PurePosixPath) -> bool:
    module_parts = module.parts
    if not module_parts:
        return True
    for file_id in file_ids:
        parts = PurePosixPath(file_id.removeprefix("file:")).parts
        for offset, part in enumerate(parts[:-1]):
            if part != module_parts[0]:
                continue
            namespace = parts[offset : offset + len(module_parts)]
            if namespace[: len(module_parts) - 1] == module_parts[:-1]:
                return True
    return False


def _relative_base(source: str, level: int, module: str | None) -> PurePosixPath | None:
    base = PurePosixPath(source).parent
    for _ in range(max(0, level - 1)):
        if not base.parts:
            return None
        base = base.parent
    if module:
        for part in module.split("."):
            base = base / part
    return base


def _import_records(source: str, content: bytes, file_ids: set[str]) -> list[dict[str, object]]:
    try:
        tree = ast.parse(content.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError) as exc:
        line = getattr(exc, "lineno", 1) or 1
        return [
            {
                "source": f"file:{source}",
                "module": "<syntax-error>",
                "line": line,
                "kind": "UNRESOLVED",
                "target": f"unresolved-import:{canonical_digest([source, '<syntax-error>', line])[:16]}",
            }
        ]

    records: list[dict[str, object]] = []
    source_id = f"file:{source}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_path = PurePosixPath(*alias.name.split("."))
                target = _module_target(file_ids, module_path)
                if target:
                    kind = "INTERNAL"
                elif _local_missing(file_ids, module_path):
                    kind = "UNRESOLVED"
                else:
                    kind = "EXTERNAL"
                records.append(
                    {
                        "source": source_id,
                        "module": alias.name,
                        "line": node.lineno,
                        "kind": kind,
                        "target": target
                        or f"{kind.lower()}-import:{alias.name}",
                    }
                )
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _relative_base(source, node.level, node.module)
                if base is None:
                    records.append(
                        {
                            "source": source_id,
                            "module": "." * node.level + (node.module or ""),
                            "line": node.lineno,
                            "kind": "UNRESOLVED",
                            "target": (
                                "unresolved-import:"
                                + canonical_digest([source, node.level, node.module, node.lineno])[:16]
                            ),
                        }
                    )
                    continue
                module_path = base
            else:
                module_path = PurePosixPath(*(node.module or "").split("."))

            direct = _module_target(file_ids, module_path)
            if direct:
                records.append(
                    {
                        "source": source_id,
                        "module": "." * node.level + (node.module or ""),
                        "line": node.lineno,
                        "kind": "INTERNAL",
                        "target": direct,
                    }
                )
            elif not node.level and _local_missing(file_ids, module_path):
                records.append(
                    {
                        "source": source_id,
                        "module": "." * node.level + (node.module or ""),
                        "line": node.lineno,
                        "kind": "UNRESOLVED",
                        "target": (
                            "unresolved-import:"
                            + canonical_digest(
                                [source, node.level, node.module, node.lineno]
                            )[:16]
                        ),
                    }
                )
            elif not node.level:
                records.append(
                    {
                        "source": source_id,
                        "module": "." * node.level + (node.module or ""),
                        "line": node.lineno,
                        "kind": "EXTERNAL",
                        "target": f"external-import:{node.module}",
                    }
                )

            alias_internal = False
            for alias in node.names:
                if alias.name == "*":
                    continue
                submodule = module_path / alias.name
                target = _module_target(file_ids, submodule)
                if target:
                    alias_internal = True
                    records.append(
                        {
                            "source": source_id,
                            "module": (
                                "." * node.level
                                + (node.module + "." if node.module else "")
                                + alias.name
                            ),
                            "line": node.lineno,
                            "kind": "INTERNAL",
                            "target": target,
                        }
                    )
            if node.level and not direct and not alias_internal:
                records.append(
                    {
                        "source": source_id,
                        "module": "." * node.level + (node.module or ""),
                        "line": node.lineno,
                        "kind": "UNRESOLVED",
                        "target": (
                            "unresolved-import:"
                            + canonical_digest(
                                [source, node.level, node.module, node.lineno]
                            )[:16]
                        ),
                    }
                )
    unique: dict[tuple[object, ...], dict[str, object]] = {}
    for record in records:
        key = (
            record["source"],
            record["module"],
            record["line"],
            record["kind"],
            record["target"],
        )
        unique[key] = record
    records = [
        unique[key] for key in sorted(unique, key=lambda item: tuple(map(str, item)))
    ]
    records.extend(_dynamic_import_records(source, tree, file_ids))
    return records


def _dynamic_import_records(
    source: str, tree: ast.AST, file_ids: set[str]
) -> list[dict[str, object]]:
    aliases = {"importlib.import_module", "__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib" and alias.asname:
                    aliases.add(f"{alias.asname}.import_module")
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module == "importlib"
            and not node.level
        ):
            for alias in node.names:
                if alias.name == "import_module":
                    aliases.add(alias.asname or "import_module")
    records: list[dict[str, object]] = []
    source_id = f"file:{source}"
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = _call_name(node.func)
        if name not in aliases:
            continue
        argument = node.args[0]
        module = (
            argument.value
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
            else None
        )
        if module is None:
            records.append(
                {
                    "source": source_id,
                    "module": "<dynamic>",
                    "line": node.lineno,
                    "kind": "UNRESOLVED",
                    "target": (
                        "unresolved-dynamic-import:"
                        + canonical_digest([source, node.lineno])[:16]
                    ),
                }
            )
            continue
        if module.startswith("."):
            level = len(module) - len(module.lstrip("."))
            base = _relative_base(source, level, module.lstrip("."))
            module_path = base
        else:
            module_path = PurePosixPath(*module.split("."))
        target = _module_target(file_ids, module_path) if module_path else None
        if target:
            kind = "INTERNAL"
        elif module_path and _local_missing(file_ids, module_path):
            kind = "UNRESOLVED"
        else:
            kind = "EXTERNAL"
        records.append(
            {
                "source": source_id,
                "module": module,
                "line": node.lineno,
                "kind": kind,
                "target": target
                or (
                    f"unresolved-dynamic-import:{module}"
                    if kind == "UNRESOLVED"
                    else f"external-import:{module}"
                ),
                "dynamic": True,
            }
        )
    return records


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _reverse_consumers(
    nodes_by_id: dict[str, dict[str, object]],
    edges: Iterable[dict[str, str]],
    starts: Iterable[str],
) -> list[str]:
    reverse: dict[str, list[str]] = {}
    for edge in edges:
        if edge["kind"] in CONSUMER_EDGE_KINDS:
            reverse.setdefault(edge["to"], []).append(edge["from"])
    queue = deque(starts)
    seen = set(starts)
    consumers: set[str] = set()
    while queue:
        target = queue.popleft()
        for source in reverse.get(target, []):
            if source in seen:
                continue
            seen.add(source)
            queue.append(source)
            if nodes_by_id.get(source, {}).get("kind") == "FILE":
                consumers.add(source)
    return sorted(consumers)


def _no_consumer_proof(
    scope: str,
    subject: Subject,
    edges: list[dict[str, str]],
    scanner_coverage: list[dict[str, object]],
) -> dict[str, object]:
    scanned = [
        item
        for item in scanner_coverage
        if item["coverage_status"] == "SCANNED"
    ]
    opaque = [
        str(item["locator"])
        for item in scanner_coverage
        if item["coverage_status"] == "OPAQUE_RAW_ONLY"
    ]
    unsupported = [
        str(item["locator"])
        for item in scanner_coverage
        if item["coverage_status"] == "UNSUPPORTED"
    ]
    proof: dict[str, object] = {
        "schema_version": 1,
        "kind": "NO_CONSUMERS",
        "scope": scope,
        "scanner_id": "scanner-set.registry",
        "scanner_digest": SCANNER_REGISTRY_DIGEST,
        "scanner_registry_digest": SCANNER_REGISTRY_DIGEST,
        "scanned_sources": [
            {"locator": item.locator, "sha256": item.sha256}
            for item in subject.files
            if item.locator in {str(row["locator"]) for row in scanned}
        ],
        "covered_file_classes": sorted(
            {str(item["file_class"]) for item in scanned}
        ),
        "opaque_sources": sorted(opaque),
        "unsupported_sources": sorted(unsupported),
        "scanner_coverage_digest": canonical_digest(scanner_coverage),
        "edge_count": len(edges),
    }
    proof["evidence_digest"] = canonical_digest(proof)
    return proof


def _valid_no_consumer_proof(
    proof: object,
    scope: str,
    edge_count: int,
    scanner_coverage: list[dict[str, object]],
) -> bool:
    if not isinstance(proof, dict):
        return False
    required = {
        "schema_version",
        "kind",
        "scope",
        "scanner_id",
        "scanner_digest",
        "scanner_registry_digest",
        "scanned_sources",
        "covered_file_classes",
        "opaque_sources",
        "unsupported_sources",
        "scanner_coverage_digest",
        "edge_count",
        "evidence_digest",
    }
    if set(proof) != required:
        return False
    if (
        proof["schema_version"] != 1
        or proof["kind"] != "NO_CONSUMERS"
        or proof["scope"] != scope
        or proof["scanner_id"] != "scanner-set.registry"
        or proof["scanner_digest"] != SCANNER_REGISTRY_DIGEST
        or proof["scanner_registry_digest"] != SCANNER_REGISTRY_DIGEST
        or proof["scanner_coverage_digest"] != canonical_digest(scanner_coverage)
        or proof["opaque_sources"]
        or proof["unsupported_sources"]
        or proof["edge_count"] != edge_count
    ):
        return False
    payload = {key: value for key, value in proof.items() if key != "evidence_digest"}
    return proof["evidence_digest"] == canonical_digest(payload)


def _valid_consumer_receipt(
    receipt: object, consumer: str, subject_digest: str
) -> bool:
    if not isinstance(receipt, dict):
        return False
    required = {
        "consumer",
        "command",
        "exit_code",
        "subject_digest",
        "verifier_id",
        "verifier_version",
        "verifier_sha256",
        "receipt_sha256",
    }
    if set(receipt) != required:
        return False
    payload = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return (
        receipt["consumer"] == consumer
        and receipt["subject_digest"] == subject_digest
        and receipt["exit_code"] == 0
        and isinstance(receipt["command"], str)
        and bool(receipt["command"])
        and isinstance(receipt["verifier_id"], str)
        and bool(receipt["verifier_id"])
        and isinstance(receipt["verifier_version"], str)
        and bool(receipt["verifier_version"])
        and isinstance(receipt["verifier_sha256"], str)
        and len(receipt["verifier_sha256"]) == 64
        and receipt["receipt_sha256"] == canonical_digest(payload)
    )


def build_impact_graph(
    subject: Subject,
    findings: list[dict[str, object]],
    *,
    consumer_receipts: dict[str, list[dict[str, object]]] | None = None,
    candidate_digest: str | None = None,
    source_closure_digest: str | None = None,
) -> dict[str, object]:
    file_ids = {f"file:{item.locator}" for item in subject.files}
    nodes: list[dict[str, object]] = [
        {
            "id": f"file:{item.locator}",
            "kind": "FILE",
            "locator": item.locator,
            "roles": _roles(item.locator),
        }
        for item in subject.files
    ]
    nodes_by_id = {str(node["id"]): node for node in nodes}
    edges: list[dict[str, str]] = []
    imports: list[dict[str, object]] = []
    classifications = {
        item.locator: classify_file(item.locator, item.content)
        for item in subject.files
    }
    edge_kinds_by_locator: dict[str, set[str]] = {
        item.locator: set() for item in subject.files
    }

    def add_edge(source: str, target: str, kind: str) -> None:
        edge = {"from": source, "to": target, "kind": kind}
        if edge not in edges:
            edges.append(edge)
            edge_kinds_by_locator.setdefault(source.removeprefix("file:"), set()).add(kind)

    def reference_target(source: str, raw: str) -> tuple[str, str] | None:
        raw = raw.strip().split("#", 1)[0]
        if (
            not raw
            or URI_SCHEME_PATTERN.match(raw)
            or raw.startswith(("$", "{", "<"))
            or PurePosixPath(raw).suffix.casefold() not in REFERENCE_SUFFIXES
        ):
            return None
        candidate = _normalize_local_reference(source, raw)
        if candidate is None:
            return None
        return f"file:{candidate}", candidate

    for item in subject.files:
        text = item.content.decode("utf-8", errors="replace")
        classification = classifications[item.locator]
        if item.locator.endswith(".md"):
            for match in MARKDOWN_LINK_PATTERN.finditer(text):
                candidate = _normalize_local_reference(
                    item.locator, match.group(1)
                )
                if candidate is None:
                    continue
                target = f"file:{candidate}"
                if target:
                    if target not in file_ids:
                        target = (
                            "unresolved-reference:"
                            + canonical_digest(
                                [item.locator, candidate]
                            )[:16]
                        )
                        if target not in nodes_by_id:
                            nodes_by_id[target] = {
                                "id": target,
                                "kind": "UNRESOLVED_REFERENCE",
                                "locator": candidate,
                                "source": f"file:{item.locator}",
                            }
                            nodes.append(nodes_by_id[target])
                        edge_kind = "UNRESOLVED_REFERENCE"
                    else:
                        edge_kind = "REFERENCES"
                    add_edge(f"file:{item.locator}", target, edge_kind)
        if item.locator.endswith(".py"):
            for record in _import_records(item.locator, item.content, file_ids):
                imports.append(record)
                target = str(record["target"])
                if record["kind"] == "INTERNAL":
                    edge_kind = (
                        "IMPORTS_DYNAMIC"
                        if record.get("dynamic")
                        else "IMPORTS"
                    )
                elif record["kind"] == "EXTERNAL":
                    edge_kind = "IMPORTS_EXTERNAL"
                    if target not in nodes_by_id:
                        nodes_by_id[target] = {
                            "id": target,
                            "kind": "EXTERNAL_IMPORT",
                            "locator": record["module"],
                        }
                        nodes.append(nodes_by_id[target])
                else:
                    edge_kind = "UNRESOLVED_IMPORT"
                    if target not in nodes_by_id:
                        nodes_by_id[target] = {
                            "id": target,
                            "kind": "UNRESOLVED_IMPORT",
                            "locator": record["module"],
                            "source": f"file:{item.locator}",
                        }
                        nodes.append(nodes_by_id[target])
                add_edge(f"file:{item.locator}", target, edge_kind)
                if edge_kind == "IMPORTS_DYNAMIC":
                    add_edge(f"file:{item.locator}", target, "RUNTIME_LOAD")
                elif edge_kind == "IMPORTS_EXTERNAL":
                    add_edge(f"file:{item.locator}", target, "EXTERNAL_DEPENDENCY")

        structured_patterns: list[tuple[re.Pattern[str], str]] = []
        if item.locator.casefold().endswith((".ps1", ".psm1")):
            structured_patterns.append((QUOTED_REFERENCE_PATTERN, "COMMAND_REF"))
            structured_patterns.append((PATH_TOKEN_PATTERN, "COMMAND_REF"))
        elif item.locator.casefold().endswith((".sh", ".bash", ".zsh", ".fish")):
            structured_patterns.append((QUOTED_REFERENCE_PATTERN, "COMMAND_REF"))
            structured_patterns.append((PATH_TOKEN_PATTERN, "COMMAND_REF"))
        elif item.locator.casefold().endswith(
            (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
        ):
            structured_patterns.append((JS_IMPORT_PATTERN, "JS_IMPORT"))
        elif item.locator.casefold().endswith((".html", ".htm")):
            structured_patterns.append((HTML_REFERENCE_PATTERN, "REFERENCES"))
        elif item.locator.casefold().endswith((".css", ".scss")):
            structured_patterns.append((CSS_REFERENCE_PATTERN, "REFERENCES"))
        elif classification["file_class"] == CONFIGURATION:
            structured_patterns.append((QUOTED_REFERENCE_PATTERN, "CONFIG_REF"))

        for pattern, edge_kind in structured_patterns:
            for match in pattern.finditer(text):
                resolved = reference_target(item.locator, match.group(1))
                if resolved is None:
                    continue
                target, candidate = resolved
                if target not in file_ids:
                    target = (
                        "unresolved-reference:"
                        + canonical_digest([item.locator, candidate])[:16]
                    )
                    if target not in nodes_by_id:
                        nodes_by_id[target] = {
                            "id": target,
                            "kind": "UNRESOLVED_REFERENCE",
                            "locator": candidate,
                            "source": f"file:{item.locator}",
                        }
                        nodes.append(nodes_by_id[target])
                    add_edge(f"file:{item.locator}", target, "UNRESOLVED_REFERENCE")
                else:
                    add_edge(f"file:{item.locator}", target, edge_kind)
                    if edge_kind == "COMMAND_REF" and "release" in candidate.casefold():
                        add_edge(f"file:{item.locator}", target, "LIFECYCLE_REF")
        for match in TEST_COMMAND_PATTERN.finditer(text):
            resolved = reference_target(item.locator, match.group(1))
            if resolved is None:
                continue
            target, candidate = resolved
            if target not in file_ids:
                target = (
                    "unresolved-reference:"
                    + canonical_digest([item.locator, candidate])[:16]
                )
                if target not in nodes_by_id:
                    nodes_by_id[target] = {
                        "id": target,
                        "kind": "UNRESOLVED_REFERENCE",
                        "locator": candidate,
                        "source": f"file:{item.locator}",
                    }
                    nodes.append(nodes_by_id[target])
                add_edge(f"file:{item.locator}", target, "UNRESOLVED_REFERENCE")
            else:
                add_edge(f"file:{item.locator}", target, "TEST_REF")

    for finding in findings:
        risk_id = str(finding["risk_id"])
        finding_node = f"finding:{risk_id}"
        if finding_node not in nodes_by_id:
            nodes_by_id[finding_node] = {
                "id": finding_node,
                "kind": "FINDING",
                "risk_id": risk_id,
            }
            nodes.append(nodes_by_id[finding_node])
        for ref in finding["affected_refs"]:
            target = f"file:{ref}"
            if target not in file_ids:
                if subject.subject_kind == "SKILL" and ref == "SKILL.md":
                    target = f"missing-source:{ref}"
                    if target not in nodes_by_id:
                        nodes_by_id[target] = {
                            "id": target,
                            "kind": "MISSING_SOURCE",
                            "locator": ref,
                        }
                        nodes.append(nodes_by_id[target])
                else:
                    target = f"unresolved:{ref}"
                    if target not in nodes_by_id:
                        nodes_by_id[target] = {
                            "id": target,
                            "kind": "UNRESOLVED",
                            "locator": ref,
                        }
                        nodes.append(nodes_by_id[target])
            add_edge(finding_node, target, "AFFECTS")

    consumer_evidence: dict[str, list[str]] = {}
    no_consumer_proofs: dict[str, dict[str, object]] = {}
    scanner_coverage: list[dict[str, object]] = []
    opaque_sources: list[str] = []
    unsupported_sources: list[str] = []
    for item in subject.files:
        classification = classifications[item.locator]
        scanner_ids = classification["scanner_ids"]
        scanner_id = scanner_ids[0] if scanner_ids else "scanner.none"
        coverage_status = classification["coverage_status"]
        if coverage_status == "OPAQUE_RAW_ONLY":
            opaque_sources.append(item.locator)
        elif coverage_status == "UNSUPPORTED":
            unsupported_sources.append(item.locator)
        scanner_coverage.append(
            {
                "locator": item.locator,
                "file_class": classification["file_class"],
                "scanner_id": scanner_id,
                "scanner_version": "1.0.0",
                "scanner_digest": canonical_digest(
                    {
                        "scanner_id": scanner_id,
                        "version": "1.0.0",
                        "file_class": classification["file_class"],
                    }
                ),
                "coverage_status": coverage_status,
                "observed_ranges": (
                    [{"start_byte": 0, "end_byte": len(item.content)}]
                    if coverage_status == "SCANNED"
                    else []
                ),
                "edge_kinds": sorted(edge_kinds_by_locator.get(item.locator, set())),
                "failure_reason": classification["unscanned_reason"],
            }
        )
    for target_id in sorted(
        {
            edge["to"]
            for edge in edges
            if edge["kind"] == "AFFECTS"
            and nodes_by_id[edge["to"]]["kind"] in {"FILE", "MISSING_SOURCE"}
        }
    ):
        consumers = _reverse_consumers(nodes_by_id, edges, [target_id])
        consumer_evidence[target_id] = consumers
        if not consumers:
            no_consumer_proofs[target_id] = _no_consumer_proof(
                target_id, subject, edges, scanner_coverage
            )

    finding_closure: dict[str, dict[str, object]] = {}
    for finding in findings:
        finding_node = f"finding:{finding['risk_id']}"
        targets = [
            edge["to"]
            for edge in edges
            if edge["from"] == finding_node and edge["kind"] == "AFFECTS"
        ]
        unresolved = sorted(
            target
            for target in targets
            if nodes_by_id[target]["kind"] == "UNRESOLVED"
        )
        affected = sorted(
            target
            for target in targets
            if nodes_by_id[target]["kind"] in {"FILE", "MISSING_SOURCE"}
        )
        consumers = sorted(
            {
                consumer
                for target in affected
                for consumer in consumer_evidence.get(target, [])
            }
        )
        receipt_digests = []
        for consumer in consumers:
            candidates = (consumer_receipts or {}).get(consumer, [])
            passing = [
                receipt
                for receipt in candidates
                if _valid_consumer_receipt(receipt, consumer, subject.tree_digest)
            ]
            if passing:
                receipt_digests.append(str(passing[0]["receipt_sha256"]))
        finding_closure[finding_node] = {
            "status": (
                "UNRESOLVED"
                if unresolved
                else (
                    "CLOSED"
                    if not consumers or len(receipt_digests) == len(consumers)
                    else "OPEN_TERMINAL_EVIDENCE"
                )
            ),
            "affected": affected,
            "consumers": consumers,
            "terminal_evidence": receipt_digests,
        }

    graph: dict[str, object] = {
        "schema_version": 3,
        "subject_digest": subject.tree_digest,
        "candidate_digest": candidate_digest,
        "source_closure_digest": source_closure_digest,
        "impact_scanner_registry_digest": SCANNER_REGISTRY_DIGEST,
        "scanner_coverage_digest": canonical_digest(scanner_coverage),
        "scanner_coverage": scanner_coverage,
        "opaque_sources": sorted(opaque_sources),
        "unsupported_sources": sorted(unsupported_sources),
        "nodes": nodes,
        "edges": edges,
        "imports": imports,
        "consumer_evidence": consumer_evidence,
        "no_consumer_proofs": {
            key: no_consumer_proofs[key] for key in sorted(no_consumer_proofs)
        },
        "finding_closure": finding_closure,
        "consumer_receipts": consumer_receipts or {},
    }
    graph["graph_digest"] = canonical_digest(graph)
    return graph


def assert_impact_closed(graph: dict[str, object]) -> None:
    declared_digest = graph.get("graph_digest")
    recomputed_digest = canonical_digest(
        {key: value for key, value in graph.items() if key != "graph_digest"}
    )
    if declared_digest != recomputed_digest:
        raise ContractError("impact graph digest mismatch")
    nodes = {node["id"]: node for node in graph["nodes"]}
    edges = graph["edges"]
    unresolved_references = sorted(
        node["locator"]
        for node in nodes.values()
        if node["kind"] == "UNRESOLVED_REFERENCE"
    )
    if unresolved_references:
        raise ContractError(
            "unresolved reference: " + ", ".join(unresolved_references)
        )
    findings = {
        node_id for node_id, node in nodes.items() if node["kind"] == "FINDING"
    }
    unresolved_findings: list[str] = []
    missing_terminal_evidence: list[str] = []
    invalid_closures: list[str] = []
    for finding_node in sorted(findings):
        targets = [
            edge["to"]
            for edge in edges
            if edge["from"] == finding_node and edge["kind"] == "AFFECTS"
        ]
        if not targets or any(
            nodes.get(target, {}).get("kind") == "UNRESOLVED" for target in targets
        ):
            unresolved_findings.append(finding_node)
            continue
        affected = sorted(
            target
            for target in targets
            if nodes.get(target, {}).get("kind") in {"FILE", "MISSING_SOURCE"}
        )
        if not affected:
            unresolved_findings.append(finding_node)
            continue
        expected_consumers: list[str] = []
        closure_valid = True
        for target in affected:
            consumers = _reverse_consumers(nodes, edges, [target])
            if graph.get("consumer_evidence", {}).get(target) != consumers:
                closure_valid = False
            expected_consumers.extend(consumers)
            if not consumers and not _valid_no_consumer_proof(
                graph.get("no_consumer_proofs", {}).get(target),
                target,
                len(edges),
                list(graph.get("scanner_coverage", ())),
            ):
                closure_valid = False
        expected_consumers = sorted(set(expected_consumers))
        receipt_digests: list[str] = []
        for consumer in expected_consumers:
            candidates = graph.get("consumer_receipts", {}).get(consumer, [])
            passing = [
                receipt
                for receipt in candidates
                if _valid_consumer_receipt(
                    receipt, consumer, str(graph.get("subject_digest", ""))
                )
            ]
            if passing:
                receipt_digests.append(str(passing[0]["receipt_sha256"]))
        expected = {
            "status": (
                "CLOSED"
                if not expected_consumers
                or len(receipt_digests) == len(expected_consumers)
                else "OPEN_TERMINAL_EVIDENCE"
            ),
            "affected": affected,
            "consumers": expected_consumers,
            "terminal_evidence": receipt_digests,
        }
        if graph.get("finding_closure", {}).get(finding_node) != expected:
            closure_valid = False
        if not closure_valid:
            invalid_closures.append(finding_node)
        if expected_consumers and len(receipt_digests) != len(expected_consumers):
            missing_terminal_evidence.append(finding_node)
    if unresolved_findings:
        raise ContractError("unresolved impact: " + ", ".join(unresolved_findings))
    if invalid_closures:
        raise ContractError(
            "incomplete impact closure: " + ", ".join(invalid_closures)
        )
    if missing_terminal_evidence:
        raise ContractError(
            "terminal evidence missing: " + ", ".join(missing_terminal_evidence)
        )


def _roles(locator: str) -> list[str]:
    path = PurePosixPath(locator)
    parts = set(path.parts)
    roles = ["SOURCE"]
    if "tests" in parts or path.name.startswith("test_"):
        roles.append("TEST")
    if "contracts" in parts or "policies" in parts or path.suffix in {".json", ".yaml", ".yml", ".toml"}:
        roles.append("CONFIG")
    if path.name in {"SKILL.md", "operations.md"} or "references" in parts:
        roles.append("DOCUMENTATION")
    if path.name in {"release_skill.py", "package.py", "release.py", "review.py"}:
        roles.append("PUBLICATION")
    if path.name in {"repair.py", "package.py", "state_machine.py", "protected_reader.py"}:
        roles.append("ROLLBACK")
    if "_callers" in locator or "consumer" in locator:
        roles.append("CALLER")
    return roles


def cluster_roots(
    findings: list[dict[str, object]],
) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for finding in findings:
        root_id = str(finding["root_cause_id"])
        grouped.setdefault(root_id, []).append(finding)
    roots: list[dict[str, object]] = []
    for root_id in sorted(grouped):
        children = grouped[root_id]
        roots.append(
            {
                "root_id": root_id,
                "finding_ids": sorted(str(item["risk_id"]) for item in children),
                "invariant_ids": sorted(
                    {str(item["invariant_id"]) for item in children}
                ),
                "affected_refs": sorted(
                    {
                        str(ref)
                        for item in children
                        for ref in item.get("affected_refs", [])
                    }
                ),
            }
        )
    return roots
