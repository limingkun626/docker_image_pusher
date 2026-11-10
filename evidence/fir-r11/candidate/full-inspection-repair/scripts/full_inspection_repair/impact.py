from __future__ import annotations

import ast
import re
from collections import deque
from collections.abc import Iterable
from pathlib import PurePosixPath

from .adapters import Subject
from .contracts import ContractError, canonical_digest

MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
URI_SCHEME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
CONSUMER_EDGE_KINDS = frozenset({"IMPORTS", "IMPORTS_DYNAMIC", "REFERENCES"})


def _local_reference(source: str, raw_target: str, known: set[str]) -> str | None:
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
    candidate = PurePosixPath(*parts).as_posix()
    target_id = f"file:{candidate}"
    return target_id if target_id in known else None


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
) -> dict[str, object]:
    proof: dict[str, object] = {
        "schema_version": 1,
        "kind": "NO_CONSUMERS",
        "scope": scope,
        "scanner": "ast-imports+markdown-links@2",
        "scanned_sources": [
            {"locator": item.locator, "sha256": item.sha256}
            for item in subject.files
        ],
        "edge_count": len(edges),
    }
    proof["evidence_digest"] = canonical_digest(proof)
    return proof


def _valid_no_consumer_proof(
    proof: object, scope: str, edge_count: int
) -> bool:
    if not isinstance(proof, dict):
        return False
    required = {
        "schema_version",
        "kind",
        "scope",
        "scanner",
        "scanned_sources",
        "edge_count",
        "evidence_digest",
    }
    if set(proof) != required:
        return False
    if (
        proof["schema_version"] != 1
        or proof["kind"] != "NO_CONSUMERS"
        or proof["scope"] != scope
        or proof["scanner"] != "ast-imports+markdown-links@2"
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

    for item in subject.files:
        text = item.content.decode("utf-8", errors="replace")
        if item.locator.endswith(".md"):
            for match in MARKDOWN_LINK_PATTERN.finditer(text):
                target = _local_reference(item.locator, match.group(1), file_ids)
                if target:
                    edges.append(
                        {
                            "from": f"file:{item.locator}",
                            "to": target,
                            "kind": "REFERENCES",
                        }
                    )
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
                edges.append(
                    {
                        "from": f"file:{item.locator}",
                        "to": target,
                        "kind": edge_kind,
                    }
                )

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
            edges.append({"from": finding_node, "to": target, "kind": "AFFECTS"})

    consumer_evidence: dict[str, list[str]] = {}
    no_consumer_proofs: dict[str, dict[str, object]] = {}
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
                target_id, subject, edges
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
        "schema_version": 2,
        "subject_digest": subject.tree_digest,
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
