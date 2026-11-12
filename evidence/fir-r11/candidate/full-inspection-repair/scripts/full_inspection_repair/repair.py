from __future__ import annotations

import hashlib
import shutil
from pathlib import Path, PurePosixPath

from .adapters import AdapterError, Subject, build_subject
from .contracts import ContractError, canonical_digest


class RepairBlocked(ValueError):
    """Raised when a frozen batch cannot safely produce a candidate."""


SAFE_OPERATION_BY_INVARIANT = {
    "TEXT-FINAL-NEWLINE-001": "APPEND_FINAL_NEWLINE",
}
SUPPORTED_OPERATION_TYPES = frozenset(
    {"APPEND_FINAL_NEWLINE", "HUMAN_DECISION_REQUIRED"}
)


def _target_for(finding: dict[str, object]) -> str:
    refs = finding["affected_refs"]
    if not refs:
        raise RepairBlocked(f"finding {finding['risk_id']} has no affected target")
    target = PurePosixPath(str(refs[0]))
    if target.is_absolute() or ".." in target.parts:
        raise RepairBlocked(f"unsafe repair target: {target}")
    return target.as_posix()


def plan_batch(findings: list[dict[str, object]]) -> dict[str, object]:
    operations: list[dict[str, object]] = []
    for item in findings:
        invariant = str(item["invariant_id"])
        operation_type = SAFE_OPERATION_BY_INVARIANT.get(
            invariant, "HUMAN_DECISION_REQUIRED"
        )
        operations.append(
            {
                "risk_id": item["risk_id"],
                "operation_type": operation_type,
                "target": _target_for(item),
                "requires_manual_decision": operation_type
                == "HUMAN_DECISION_REQUIRED",
            }
        )
    batch: dict[str, object] = {
        "schema_version": 1,
        "operations": operations,
    }
    batch["batch_digest"] = canonical_digest(batch)
    return batch


def preflight_batch(batch: dict[str, object]) -> None:
    operations = batch["operations"]
    targets: dict[str, str] = {}
    for operation in operations:
        operation_type = str(operation["operation_type"])
        if operation_type not in SUPPORTED_OPERATION_TYPES:
            raise RepairBlocked(f"unsupported operation: {operation_type}")
        target = str(operation["target"])
        if target in targets and targets[target] != operation_type:
            raise RepairBlocked(f"repair conflict for target: {target}")
        targets[target] = operation_type


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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_frozen_source(subject: Subject, *, phase: str) -> None:
    try:
        current = build_subject(subject.root, subject.subject_kind)
    except AdapterError as exc:
        raise RepairBlocked(f"frozen source unavailable during {phase}: {exc}") from exc
    if current.tree_digest != subject.tree_digest:
        raise RepairBlocked(
            "frozen source bytes changed "
            f"during {phase}: expected {subject.tree_digest}, "
            f"found {current.tree_digest}"
        )


def apply_batch(
    subject: Subject, batch: dict[str, object], candidate_root: str | Path
) -> dict[str, object]:
    preflight_batch(batch)
    operations = batch["operations"]
    manual = [
        operation["risk_id"]
        for operation in operations
        if operation["requires_manual_decision"]
    ]
    if manual:
        raise RepairBlocked(
            "manual decision required for: " + ", ".join(str(item) for item in manual)
        )
    destination = Path(candidate_root).resolve()
    if destination.exists():
        raise RepairBlocked(f"candidate root already exists: {destination}")
    _assert_frozen_source(subject, phase="pre-copy preimage check")

    try:
        shutil.copytree(
            subject.root,
            destination,
            ignore=shutil.ignore_patterns(
                "__pycache__", ".pytest_cache", "*.pyc", "*.pyo"
            ),
        )
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    try:
        copied = build_subject(destination, subject.subject_kind)
        if copied.tree_digest != subject.tree_digest:
            raise RepairBlocked(
                "copied candidate does not match the frozen subject: "
                f"expected {subject.tree_digest}, found {copied.tree_digest}"
            )
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise

    frozen_files = {item.locator: item for item in subject.files}
    receipts: list[dict[str, object]] = []
    try:
        for operation in operations:
            path = _safe_target(destination, str(operation["target"]))
            preimage = _sha256(path)
            frozen = frozen_files.get(str(operation["target"]))
            if frozen is None or preimage != frozen.sha256:
                raise RepairBlocked(
                    "repair preimage does not match the frozen subject: "
                    f"{operation['target']}"
                )
            data = path.read_bytes()
            if operation["operation_type"] == "APPEND_FINAL_NEWLINE":
                if not data.endswith((b"\n", b"\r")):
                    path.write_bytes(data + b"\n")
            else:
                raise ContractError(
                    f"unsupported operation: {operation['operation_type']}"
                )
            receipts.append(
                {
                    **operation,
                    "preimage_sha256": preimage,
                    "postimage_sha256": _sha256(path),
                }
            )
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise

    try:
        _assert_frozen_source(subject, phase="post-copy acceptance check")
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    candidate_subject = build_subject(destination, subject.subject_kind)
    receipt: dict[str, object] = {
        "schema_version": 1,
        "base_subject_digest": subject.tree_digest,
        "batch_digest": batch["batch_digest"],
        "candidate_root": str(destination),
        "candidate_digest": candidate_subject.tree_digest,
        "operations": receipts,
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt
