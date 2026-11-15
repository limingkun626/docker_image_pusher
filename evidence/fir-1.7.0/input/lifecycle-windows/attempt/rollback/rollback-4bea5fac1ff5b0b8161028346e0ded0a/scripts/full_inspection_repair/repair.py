from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from .adapters import AdapterError, Subject, build_subject
from .contracts import (
    canonical_digest,
    dir_hash1,
    material_digest,
    validate_contract,
)
from .strict import (
    assert_no_link_chain,
    fsync_directory,
    fsync_fd,
    write_all,
    write_json,
)


class RepairBlocked(ValueError):
    """Raised when a frozen batch cannot safely produce a candidate."""

    def __init__(self, message: str, code: str = "BLOCKED_REPAIR_PLAN") -> None:
        super().__init__(message)
        self.code = code


SAFE_OPERATION_BY_INVARIANT = {
    "TEXT-FINAL-NEWLINE-001": "APPEND_FINAL_NEWLINE",
}
SUPPORTED_OPERATION_TYPES = frozenset(
    {
        "APPEND_FINAL_NEWLINE",
        "REPLACE_BYTE_RANGE",
        "AST_RULE_REWRITE",
        "SET_JSON_POINTER",
        "CREATE_FILE_FROM_TEMPLATE",
        "MOVE_FILE_WITH_REFERENCES",
        "HUMAN_DECISION_REQUIRED",
    }
)
MUTATING_OPERATION_TYPES = SUPPORTED_OPERATION_TYPES - {"HUMAN_DECISION_REQUIRED"}


def _target_for(finding: dict[str, object]) -> str:
    refs = finding["affected_refs"]
    if not refs:
        raise RepairBlocked(f"finding {finding['risk_id']} has no affected target")
    return _normalise_relative(str(refs[0]))


def _root_for(finding: dict[str, object]) -> str:
    value = finding.get("root_cause_id")
    if value:
        return str(value)
    return "root:" + canonical_digest(
        {
            "risk_id": finding["risk_id"],
            "invariant_id": finding["invariant_id"],
        }
    )[:16]


def _normalise_relative(value: str) -> str:
    target = PurePosixPath(value)
    if (
        target.is_absolute()
        or ".." in target.parts
        or not target.parts
        or any(":" in part for part in target.parts)
    ):
        raise RepairBlocked(f"unsafe repair target: {target}")
    return target.as_posix()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _batch_digest(batch: dict[str, Any]) -> str:
    return material_digest(batch, "batch_digest")


def _operation_id(operation: dict[str, Any]) -> str:
    return canonical_digest(operation)


def _operation_parameters(operation_type: str) -> dict[str, Any]:
    if operation_type == "APPEND_FINAL_NEWLINE":
        return {}
    if operation_type == "REPLACE_BYTE_RANGE":
        return {
            "start_byte": 0,
            "end_byte": 0,
            "replacement_base64": "",
        }
    return {}


def _preconditions(operation_type: str) -> list[str]:
    return {
        "APPEND_FINAL_NEWLINE": [
            "target is a file",
            "target does not end in CR or LF",
        ],
        "REPLACE_BYTE_RANGE": [
            "target is a file",
            "declared byte range is within the preimage",
        ],
        "AST_RULE_REWRITE": [
            "planned edits exactly match the frozen rule result",
            "no unplanned match is observed",
        ],
        "SET_JSON_POINTER": [
            "target is valid JSON",
            "pointer exists and has the declared old value",
        ],
        "CREATE_FILE_FROM_TEMPLATE": [
            "target does not exist",
            "template and substitutions match the frozen plan",
        ],
        "MOVE_FILE_WITH_REFERENCES": [
            "source exists",
            "destination does not exist",
            "every reference update is declared",
        ],
        "HUMAN_DECISION_REQUIRED": ["a decision belongs to a new authorized scope"],
    }[operation_type]


def _postconditions(operation_type: str) -> list[str]:
    return {
        "APPEND_FINAL_NEWLINE": [
            "all preimage bytes are preserved",
            "exactly one final terminator is present",
        ],
        "REPLACE_BYTE_RANGE": [
            "only the declared byte range changed",
            "postimage digest equals the frozen expectation",
        ],
        "AST_RULE_REWRITE": [
            "changed ranges are exactly the planned ranges",
            "the rewritten target still parses",
        ],
        "SET_JSON_POINTER": [
            "only the declared JSON pointer changes",
            "the result is valid JSON",
        ],
        "CREATE_FILE_FROM_TEMPLATE": [
            "new file bytes equal the frozen postimage",
            "no existing file is overwritten",
        ],
        "MOVE_FILE_WITH_REFERENCES": [
            "the source is absent",
            "the destination and declared references are current",
        ],
        "HUMAN_DECISION_REQUIRED": ["no mutation occurs in the current run"],
    }[operation_type]


def _predicted_postimage(
    path: Path, operation: dict[str, Any]
) -> str | None:
    data = path.read_bytes()
    operation_type = str(operation["operation_type"])
    parameters = operation.get("parameters", {})
    if operation_type == "APPEND_FINAL_NEWLINE":
        return hashlib.sha256(data + b"\n").hexdigest()
    if operation_type == "REPLACE_BYTE_RANGE":
        start = int(parameters["start_byte"])
        end = int(parameters["end_byte"])
        replacement = _replacement_bytes(parameters)
        return hashlib.sha256(data[:start] + replacement + data[end:]).hexdigest()
    if operation_type in {"AST_RULE_REWRITE", "SET_JSON_POINTER"}:
        return hashlib.sha256(_apply_replacement(path, operation, data)).hexdigest()
    return None


def plan_batch(
    findings: list[dict[str, object]],
    subject: Subject | None = None,
    *,
    scope_id: str | None = None,
    registry_digest: str | None = None,
    policy_digest: str | None = None,
    decisions: dict[str, Any] | None = None,
) -> dict[str, object]:
    ordered = sorted(findings, key=lambda item: str(item["risk_id"]))
    if not ordered:
        raise RepairBlocked("repair plan requires a non-empty frozen issue set")
    roots = sorted({_root_for(item) for item in ordered})
    finding_root_map = {
        str(item["risk_id"]): _root_for(item) for item in ordered
    }
    root_dag = [
        {
            "root_id": root,
            "depends_on": sorted(
                {
                    str(dependency)
                    for item in ordered
                    if _root_for(item) == root
                    for dependency in item.get("repair_dependencies", [])
                    if str(dependency) in roots and str(dependency) != root
                }
            ),
        }
        for root in roots
    ]
    operations: list[dict[str, Any]] = []
    for item in ordered:
        operation_type = SAFE_OPERATION_BY_INVARIANT.get(
            str(item["invariant_id"]), "HUMAN_DECISION_REQUIRED"
        )
        target = _target_for(item)
        preimage: str | None = None
        predicted: str | None = None
        if subject is not None and operation_type != "CREATE_FILE_FROM_TEMPLATE":
            path = _safe_target(subject.root, target)
            preimage = _sha256(path)
        operation: dict[str, Any] = {
            "risk_ids": [str(item["risk_id"])],
            "operation_type": operation_type,
            "binding_id": "repair." + operation_type.lower().replace("_", "-"),
            "binding_version": "1.0.0",
            "target": target,
            "preimage_sha256": preimage,
            "parameters": _operation_parameters(operation_type),
            "preconditions": _preconditions(operation_type),
            "postconditions": _postconditions(operation_type),
        }
        if subject is not None and preimage is not None:
            predicted = _predicted_postimage(
                (subject.root / target), operation
            )
        operation["expected_postimage_sha256"] = predicted
        operation["rollback_slice"] = (
            "RB-"
            + canonical_digest(
                {
                    "target": target,
                    "preimage": preimage,
                    "operation_type": operation_type,
                }
            )[:20].upper()
        )
        operation["operation_id"] = _operation_id(operation)
        operations.append(operation)
    issue_set_digest = canonical_digest(ordered)
    batch: dict[str, Any] = {
        "schema_version": 2,
        "scope_id": scope_id
        or (
            subject.subject_id
            if subject is not None
            else f"scope:{issue_set_digest[:16]}"
        ),
        "issue_set_digest": issue_set_digest,
        "base_subject_digest": (
            subject.tree_digest
            if subject is not None
            else canonical_digest({"issue_set": issue_set_digest})
        ),
        "registry_digest": registry_digest
        or canonical_digest({"registry": "compatibility"}),
        "policy_digest": policy_digest
        or canonical_digest({"repair_policy": "1.7.0"}),
        "decision_set_digest": canonical_digest(decisions) if decisions else None,
        "candidate_generation": 1,
        "root_ids": roots,
        "root_dag": root_dag,
        "finding_root_map": finding_root_map,
        "operations": operations,
        "dependencies": [],
        "conflicts": [],
    }
    batch["batch_digest"] = _batch_digest(batch)
    validate_contract("repair-plan-v2", batch)
    return batch


def assert_batch_digest(batch: dict[str, Any]) -> None:
    if batch.get("schema_version") != 2:
        return
    if batch.get("batch_digest") != _batch_digest(batch):
        raise RepairBlocked("frozen repair batch digest mismatch")


def _byte_range(operation: dict[str, Any]) -> tuple[int, int]:
    parameters = operation.get("parameters", {})
    start = int(parameters.get("start_byte", 0))
    end = int(parameters.get("end_byte", 0))
    if start < 0 or end < start:
        raise RepairBlocked("repair byte range is invalid")
    return start, end


def _find_conflicts(
    operations: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for operation in operations:
        grouped.setdefault(str(operation["target"]), []).append(operation)
    conflicts: list[dict[str, Any]] = []
    for target, rows in grouped.items():
        if len(rows) < 2:
            continue
        for index, left in enumerate(rows):
            for right in rows[index + 1 :]:
                left_type = str(left["operation_type"])
                right_type = str(right["operation_type"])
                non_overlapping_ranges = False
                if (
                    left_type == right_type == "REPLACE_BYTE_RANGE"
                ):
                    left_start, left_end = _byte_range(left)
                    right_start, right_end = _byte_range(right)
                    non_overlapping_ranges = (
                        left_end <= right_start or right_end <= left_start
                    )
                if not non_overlapping_ranges:
                    conflicts.append(
                        {
                            "target": target,
                            "operation_ids": [
                                left.get("operation_id", left.get("risk_id")),
                                right.get("operation_id", right.get("risk_id")),
                            ],
                            "reason": "overlapping target mutations",
                        }
                    )
    return conflicts


def _assert_acyclic(dependencies: Iterable[Iterable[str]]) -> None:
    edges = [tuple(edge) for edge in dependencies]
    nodes = {node for edge in edges for node in edge}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise RepairBlocked("repair dependency graph contains a cycle")
        if node in visited:
            return
        visiting.add(node)
        for left, right in edges:
            if left == node:
                visit(right)
        visiting.remove(node)
        visited.add(node)

    for node in nodes:
        visit(node)


def preflight_batch(
    batch: dict[str, object], subject: Subject | None = None
) -> None:
    assert_batch_digest(batch)
    operations = batch.get("operations")
    if not isinstance(operations, list) or not operations:
        raise RepairBlocked("repair batch has no operations")
    operation_ids: set[str] = set()
    risk_ids: list[str] = []
    normalised: list[dict[str, Any]] = []
    for raw in operations:
        if not isinstance(raw, dict):
            raise RepairBlocked("repair operation is malformed")
        operation = dict(raw)
        operation_type = str(operation.get("operation_type"))
        if operation_type not in SUPPORTED_OPERATION_TYPES:
            raise RepairBlocked(f"unsupported operation: {operation_type}")
        target = _normalise_relative(str(operation.get("target", "")))
        operation["target"] = target
        operation_id = operation.get("operation_id")
        if operation_id is not None:
            if not isinstance(operation_id, str) or operation_id in operation_ids:
                raise RepairBlocked("repair operation IDs are missing or duplicate")
            operation_ids.add(operation_id)
        ids = operation.get("risk_ids")
        if ids is None and operation.get("risk_id") is not None:
            ids = [operation["risk_id"]]
        if not isinstance(ids, list) or not ids:
            raise RepairBlocked("repair operation has no finding binding")
        risk_ids.extend(str(item) for item in ids)
        if batch.get("schema_version") == 2:
            if operation.get("binding_id") not in {
                "repair." + operation_type.lower().replace("_", "-"),
            }:
                raise RepairBlocked("repair operation binding is not admitted")
            if (
                operation_type == "HUMAN_DECISION_REQUIRED"
                and batch.get("decision_set_digest") is None
            ):
                raise RepairBlocked(
                    "manual decision is not bound to a new authorization"
                )
        if subject is not None:
            if operation_type == "CREATE_FILE_FROM_TEMPLATE":
                destination = (subject.root / target).resolve()
                try:
                    destination.relative_to(subject.root.resolve())
                except ValueError as exc:
                    raise RepairBlocked(
                        f"repair target escapes root: {target}"
                    ) from exc
                if destination.exists():
                    raise RepairBlocked(f"repair create target already exists: {target}")
            else:
                path = _safe_target(subject.root, target)
                expected = operation.get("preimage_sha256")
                if expected is not None and _sha256(path) != expected:
                    raise RepairBlocked(
                        f"repair preimage does not match the frozen subject: {target}"
                    )
        normalised.append(operation)
    if batch.get("schema_version") == 2:
        expected_risks = sorted(str(item) for item in batch.get("finding_root_map", {}))
        if sorted(risk_ids) != expected_risks:
            raise RepairBlocked("repair operations do not equal the frozen issue set")
    conflicts = _find_conflicts(normalised)
    if conflicts or batch.get("conflicts"):
        raise RepairBlocked("repair conflict graph is non-empty", "BLOCKED_REPAIR_CONFLICT")
    dependencies = batch.get("dependencies", [])
    _assert_acyclic(dependencies)
    _assert_acyclic(
        [
            (row["root_id"], dependency)
            for row in batch.get("root_dag", [])
            for dependency in row.get("depends_on", [])
        ]
    )


def _safe_target(root: Path, relative: str) -> Path:
    resolved_root = root.resolve()
    candidate = (resolved_root / relative).resolve()
    try:
        candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise RepairBlocked(f"repair target escapes root: {relative}") from exc
    if not candidate.is_file():
        raise RepairBlocked(f"repair target is not a file: {relative}")
    return candidate


def _replacement_bytes(parameters: dict[str, Any]) -> bytes:
    if "replacement_base64" in parameters:
        try:
            return base64.b64decode(
                str(parameters["replacement_base64"]), validate=True
            )
        except (ValueError, TypeError) as exc:
            raise RepairBlocked("replacement_base64 is invalid") from exc
    if "replacement" in parameters and isinstance(parameters["replacement"], str):
        return parameters["replacement"].encode("utf-8")
    raise RepairBlocked("replacement bytes are missing")


def _atomic_write(path: Path, data: bytes) -> None:
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        try:
            write_all(fd, data)
            fsync_fd(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _apply_replacement(
    path: Path,
    operation: dict[str, Any],
    data: bytes,
) -> bytes:
    operation_type = str(operation["operation_type"])
    parameters = operation.get("parameters", {})
    if operation_type == "APPEND_FINAL_NEWLINE":
        if data.endswith((b"\n", b"\r")):
            raise RepairBlocked(f"append-final-newline operation is a no-op: {path}")
        return data + b"\n"
    if operation_type == "REPLACE_BYTE_RANGE":
        start, end = _byte_range(operation)
        if end > len(data):
            raise RepairBlocked("repair byte range exceeds the preimage")
        expected = parameters.get("expected_base64")
        if expected is not None:
            try:
                expected_bytes = base64.b64decode(str(expected), validate=True)
            except (ValueError, TypeError) as exc:
                raise RepairBlocked("expected_base64 is invalid") from exc
            if data[start:end] != expected_bytes:
                raise RepairBlocked("repair byte range preimage mismatch")
        return data[:start] + _replacement_bytes(parameters) + data[end:]
    if operation_type == "AST_RULE_REWRITE":
        rewrites = parameters.get("replacements")
        if not isinstance(rewrites, list) or not rewrites:
            raise RepairBlocked("AST rule rewrite has no frozen replacements")
        result = data
        ranges: list[tuple[int, int]] = []
        for rewrite in sorted(
            rewrites, key=lambda item: int(item["start_byte"]), reverse=True
        ):
            start = int(rewrite["start_byte"])
            end = int(rewrite["end_byte"])
            if start < 0 or end < start or end > len(result):
                raise RepairBlocked("AST rule rewrite range is invalid")
            if any(not (end <= left or start >= right) for left, right in ranges):
                raise RepairBlocked(
                    "AST rule rewrite ranges overlap",
                    "BLOCKED_REPAIR_CONFLICT",
                )
            expected = str(rewrite.get("expected", ""))
            if result[start:end] != expected.encode("utf-8"):
                raise RepairBlocked("AST rule rewrite preimage mismatch")
            replacement = str(rewrite.get("replacement", "")).encode("utf-8")
            result = result[:start] + replacement + result[end:]
            ranges.append((start, end))
        if path.suffix == ".py":
            try:
                ast.parse(result.decode("utf-8"))
            except (SyntaxError, UnicodeDecodeError) as exc:
                raise RepairBlocked("AST rule rewrite introduced a parse error") from exc
        return result
    if operation_type == "SET_JSON_POINTER":
        pointer = str(parameters.get("pointer", ""))
        old_value = parameters.get("old_value")
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RepairBlocked("SET_JSON_POINTER target is not valid JSON") from exc
        parent, key = _resolve_pointer(document, pointer)
        if not isinstance(parent, dict) or key not in parent:
            raise RepairBlocked("SET_JSON_POINTER pointer does not exist")
        if parent[key] != old_value:
            raise RepairBlocked("SET_JSON_POINTER old value mismatch")
        parent[key] = parameters.get("new_value")
        return (
            json.dumps(
                document,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    raise RepairBlocked(f"unsupported operation: {operation_type}")


def _resolve_pointer(document: Any, pointer: str) -> tuple[Any, str]:
    if not pointer.startswith("/"):
        raise RepairBlocked("JSON pointer is invalid")
    parts = [
        part.replace("~1", "/").replace("~0", "~")
        for part in pointer[1:].split("/")
    ]
    current = document
    for part in parts[:-1]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise RepairBlocked("JSON pointer does not exist")
    return current, parts[-1]


def _create_from_template(root: Path, operation: dict[str, Any]) -> Path:
    target = root / str(operation["target"])
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise RepairBlocked(f"repair create target already exists: {operation['target']}")
    parameters = operation.get("parameters", {})
    content: bytes
    if "content_base64" in parameters:
        try:
            content = base64.b64decode(
                str(parameters["content_base64"]), validate=True
            )
        except (ValueError, TypeError) as exc:
            raise RepairBlocked("template content_base64 is invalid") from exc
    elif isinstance(parameters.get("content"), str):
        content = parameters["content"].encode("utf-8")
    else:
        raise RepairBlocked("template content is missing")
    expected = parameters.get("template_sha256")
    if expected is not None and hashlib.sha256(content).hexdigest() != expected:
        raise RepairBlocked("template digest mismatch")
    _atomic_write(target, content)
    return target


def _apply_move(root: Path, operation: dict[str, Any]) -> tuple[Path, Path]:
    parameters = operation.get("parameters", {})
    source = _safe_target(root, str(operation["target"]))
    destination_relative = _normalise_relative(str(parameters.get("destination", "")))
    destination = root / destination_relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise RepairBlocked(f"move destination already exists: {destination_relative}")
    os.replace(source, destination)
    fsync_directory(source.parent)
    fsync_directory(destination.parent)
    updates = parameters.get("references")
    if not isinstance(updates, list) or not updates:
        raise RepairBlocked("move operation has no frozen reference updates")
    for update in updates:
        path = _safe_target(root, _normalise_relative(str(update["path"])))
        expected_sha = str(update.get("preimage_sha256", ""))
        original = path.read_bytes()
        if expected_sha and hashlib.sha256(original).hexdigest() != expected_sha:
            raise RepairBlocked(f"reference update preimage mismatch: {update['path']}")
        old = str(update["old"]).encode("utf-8")
        new = str(update["new"]).encode("utf-8")
        count = original.count(old)
        if count != int(update["count"]):
            raise RepairBlocked(f"reference update count mismatch: {update['path']}")
        _atomic_write(path, original.replace(old, new))
    return source, destination


def _tree_manifest(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        relative_directory = current_path.relative_to(root)
        if relative_directory.parts:
            result[relative_directory.as_posix() + "/"] = "directory"
        for name in directories:
            if (current_path / name).is_symlink():
                raise RepairBlocked(
                    f"candidate tree contains a link: {(current_path / name).relative_to(root)}"
                )
        for name in files:
            path = current_path / name
            if path.is_symlink():
                raise RepairBlocked(
                    f"candidate tree contains a link: {path.relative_to(root)}"
                )
            relative = path.relative_to(root).as_posix()
            result[relative] = _sha256(path)
    return result


def _frozen_tree_manifest(subject: Subject) -> dict[str, str]:
    result = {item.locator: item.sha256 for item in subject.files}
    for directory in subject.directories:
        relative = directory.get("relative_path", directory.get("path"))
        if relative and relative not in {".", ""}:
            result[str(relative).replace("\\", "/").rstrip("/") + "/"] = "directory"
    return result


def _assert_frozen_source(subject: Subject, *, phase: str) -> None:
    try:
        current = build_subject(subject.root, subject.subject_kind)
    except AdapterError as exc:
        raise RepairBlocked(
            f"frozen source unavailable during {phase}: {exc}",
            "BLOCKED_STALE_INPUT",
        ) from exc
    if current.tree_digest != subject.tree_digest:
        raise RepairBlocked(
            "frozen source bytes changed "
            f"during {phase}: expected {subject.tree_digest}, "
            f"found {current.tree_digest}",
            "BLOCKED_STALE_INPUT",
        )


def build_candidate_manifest(
    *,
    subject: Subject,
    candidate: Subject,
    batch_digest: str,
    operation_receipt_digests: Iterable[str],
) -> dict[str, object]:
    files = [
        {"path": item.locator, "sha256": item.sha256, "size": item.size}
        for item in candidate.files
    ]
    manifest: dict[str, object] = {
        "schema_version": 2,
        "candidate_id": canonical_digest(
            {
                "base_subject_digest": subject.tree_digest,
                "candidate_digest": candidate.tree_digest,
            }
        ),
        "base_subject_digest": subject.tree_digest,
        "candidate_digest": candidate.tree_digest,
        "candidate_dir_hash1": dir_hash1(candidate.root),
        "repair_plan_digest": batch_digest,
        "operation_receipt_digests": sorted(set(operation_receipt_digests)),
        "logical_identity": subject.subject_id,
        "generation": 1,
        "files": files,
    }
    manifest["candidate_manifest_digest"] = material_digest(
        manifest, "candidate_manifest_digest"
    )
    validate_contract("candidate-manifest-v2", manifest)
    return manifest


def apply_batch(
    subject: Subject,
    batch: dict[str, object],
    candidate_root: str | Path,
    *,
    receipt_path: str | Path | None = None,
) -> dict[str, object]:
    preflight_batch(batch, subject)
    assert_batch_digest(batch)
    operations = batch["operations"]
    if not isinstance(operations, list):
        raise RepairBlocked("repair batch operations are malformed")
    manual = [
        operation
        for operation in operations
        if operation["operation_type"] == "HUMAN_DECISION_REQUIRED"
    ]
    if manual:
        raise RepairBlocked(
            "manual decision required for: "
            + ", ".join(
                str(operation.get("risk_ids", operation.get("risk_id")))
                for operation in manual
            )
        )
    try:
        destination = assert_no_link_chain(
            Path(os.path.abspath(os.fspath(candidate_root))),
            allow_missing=True,
        )
    except OSError as exc:
        raise RepairBlocked(f"candidate root is unsafe: {exc}") from exc
    if destination.exists():
        raise RepairBlocked(f"candidate root already exists: {destination}")
    source_root = subject.root.resolve()
    if (
        destination == source_root
        or source_root in destination.parents
        or destination in source_root.parents
    ):
        raise RepairBlocked(
            "candidate root must be disjoint from the frozen source root",
            "BLOCKED_SCOPE",
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    _assert_frozen_source(subject, phase="pre-copy preimage check")
    assert_batch_digest(batch)

    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.staging-",
            dir=destination.parent,
        )
    )
    operation_receipts: list[dict[str, object]] = []
    try:
        shutil.copytree(subject.root, staging, dirs_exist_ok=True, symlinks=False)
        copied = build_subject(staging, subject.subject_kind)
        if copied.tree_digest != subject.tree_digest:
            raise RepairBlocked(
                "copied staging tree does not match the frozen subject: "
                f"expected {subject.tree_digest}, found {copied.tree_digest}",
                "BLOCKED_EVIDENCE",
            )
        if _tree_manifest(staging) != _frozen_tree_manifest(subject):
            raise RepairBlocked(
                "copied staging tree is not cache-inclusive and exact",
                "BLOCKED_EVIDENCE",
            )
        allowed_paths = {str(operation["target"]) for operation in operations}
        for operation in operations:
            if operation["operation_type"] == "CREATE_FILE_FROM_TEMPLATE":
                target = Path(str(operation["target"]))
                allowed_paths.update(
                    parent.as_posix().rstrip("/") + "/"
                    for parent in target.parents
                    if parent.as_posix() != "."
                )
            elif operation["operation_type"] == "MOVE_FILE_WITH_REFERENCES":
                destination_value = operation.get("parameters", {}).get(
                    "destination"
                )
                if destination_value:
                    target = Path(str(destination_value))
                    allowed_paths.add(target.as_posix())
                    allowed_paths.update(
                        parent.as_posix().rstrip("/") + "/"
                        for parent in target.parents
                        if parent.as_posix() != "."
                    )
        for operation in operations:
            assert_batch_digest(batch)
            operation_type = str(operation["operation_type"])
            preimage: str | None = None
            postimage: str | None = None
            if operation_type == "CREATE_FILE_FROM_TEMPLATE":
                changed = _create_from_template(staging, operation)
                changed_relative = changed.relative_to(staging).as_posix()
                postimage = _sha256(changed)
            elif operation_type == "MOVE_FILE_WITH_REFERENCES":
                _source_path, changed = _apply_move(staging, operation)
                preimage = _sha256(changed)
                postimage = preimage
                changed_relative = changed.relative_to(staging).as_posix()
                allowed_paths.add(changed_relative)
            else:
                path = _safe_target(staging, str(operation["target"]))
                preimage = _sha256(path)
                expected_preimage = operation.get("preimage_sha256")
                if expected_preimage is not None and preimage != expected_preimage:
                    raise RepairBlocked(
                        f"repair preimage changed during transaction: {operation['target']}"
                    )
                data = path.read_bytes()
                replacement = _apply_replacement(path, operation, data)
                _atomic_write(path, replacement)
                postimage = _sha256(path)
                expected_postimage = operation.get("expected_postimage_sha256")
                if (
                    expected_postimage is not None
                    and postimage != expected_postimage
                ):
                    raise RepairBlocked(
                        f"repair postimage mismatch: {operation['target']}"
                    )
                changed_relative = str(operation["target"])
            current_manifest = _tree_manifest(staging)
            baseline_manifest = _tree_manifest(subject.root)
            unplanned = sorted(
                path
                for path, digest in current_manifest.items()
                if path not in allowed_paths and baseline_manifest.get(path) != digest
            )
            unplanned.extend(
                sorted(
                    path
                    for path in baseline_manifest
                    if path not in current_manifest and path not in allowed_paths
                )
            )
            if unplanned:
                raise RepairBlocked(
                    "repair changed an unplanned path: " + ", ".join(sorted(set(unplanned)))
                )
            receipt: dict[str, object] = {
                "schema_version": 1,
                "operation_id": operation.get(
                    "operation_id",
                    canonical_digest(
                        {
                            "target": operation["target"],
                            "preimage": preimage,
                        }
                    ),
                ),
                "risk_ids": operation.get(
                    "risk_ids",
                    [operation.get("risk_id")],
                ),
                "operation_type": operation_type,
                "target": changed_relative,
                "preimage_sha256": preimage,
                "postimage_sha256": postimage,
                "batch_digest": batch["batch_digest"],
                "candidate_bytes_before_commit": True,
            }
            receipt["receipt_sha256"] = canonical_digest(receipt)
            operation_receipts.append(receipt)
            assert_batch_digest(batch)
        _assert_frozen_source(subject, phase="post-copy acceptance check")
        candidate_subject = build_subject(staging, subject.subject_kind)
        manifest = build_candidate_manifest(
            subject=subject,
            candidate=candidate_subject,
            batch_digest=str(batch["batch_digest"]),
            operation_receipt_digests=(
                str(item["receipt_sha256"]) for item in operation_receipts
            ),
        )
        assert_batch_digest(batch)
        if destination.parent != staging.parent or not destination.parent.is_dir():
            raise RepairBlocked(
                "candidate commit parent is unavailable",
                "BLOCKED_REPAIR_PLAN",
            )
        try:
            os.replace(staging, destination)
            fsync_directory(destination.parent)
        except OSError as exc:
            raise RepairBlocked(
                f"candidate atomic commit failed: {exc}",
                "BLOCKED_REPAIR_PLAN",
            ) from exc
        committed = build_subject(destination, subject.subject_kind)
        if committed.tree_digest != candidate_subject.tree_digest:
            shutil.rmtree(destination, ignore_errors=True)
            raise RepairBlocked(
                "committed candidate digest changed",
                "BLOCKED_EVIDENCE",
            )
        receipt = {
            "schema_version": 2,
            "base_subject_digest": subject.tree_digest,
            "batch_digest": batch["batch_digest"],
            "candidate_root": str(destination),
            "candidate_digest": committed.tree_digest,
            "candidate_dir_hash1": manifest["candidate_dir_hash1"],
            "logical_identity": manifest["logical_identity"],
            "operations": operation_receipts,
            "operation_receipt_digests": manifest["operation_receipt_digests"],
            "candidate_manifest": manifest,
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        if receipt_path is not None:
            write_json(Path(receipt_path), receipt)
        return receipt
    except Exception as exc:
        shutil.rmtree(staging, ignore_errors=True)
        if staging.exists():
            raise RepairBlocked(
                "staging cleanup failed", "BLOCKED_EVIDENCE"
            ) from exc
        if receipt_path is not None:
            blocked: dict[str, object] = {
                "schema_version": 2,
                "status": getattr(exc, "code", "BLOCKED_EVIDENCE"),
                "message": str(exc),
                "base_subject_digest": subject.tree_digest,
                "batch_digest": batch.get("batch_digest"),
                "operation_receipts": operation_receipts,
                "candidate_root": str(destination),
                "candidate_created": destination.exists(),
            }
            blocked["receipt_digest"] = canonical_digest(blocked)
            try:
                write_json(Path(receipt_path), blocked)
            except OSError:
                pass
        if destination.exists():
            try:
                shutil.rmtree(destination)
            except OSError:
                pass
        raise
