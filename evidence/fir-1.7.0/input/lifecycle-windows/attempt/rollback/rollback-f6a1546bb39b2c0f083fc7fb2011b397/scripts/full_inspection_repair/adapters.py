from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .contracts import canonical_digest
from .file_classes import classify_file
from .protected_reader import ProtectedObjectError, public_snapshot, snapshot_tree

ALLOWED_TARGET_KINDS = frozenset({"SKILL", "PLAN", "ARTICLE", "PROJECT", "OTHER"})
EXPECTED_SKILL_SOURCES = frozenset({"SKILL.md"})


class AdapterError(ValueError):
    """Raised when a target cannot be represented by an adapter."""


@dataclass(frozen=True)
class SourceFile:
    locator: str
    absolute_path: Path
    size: int
    sha256: str
    content: bytes
    metadata: dict[str, object]


@dataclass(frozen=True)
class Subject:
    subject_id: str
    subject_kind: str
    root: Path
    files: tuple[SourceFile, ...]
    tree_digest: str
    root_generation: str
    directories: tuple[dict[str, object], ...]
    snapshot_digest: str


def build_subject(root: str | Path, subject_kind: str) -> Subject:
    kind = subject_kind.upper()
    if kind not in ALLOWED_TARGET_KINDS:
        raise AdapterError(f"unsupported target kind: {subject_kind}")

    root_path = Path(os.path.abspath(os.fspath(root)))
    if not root_path.is_dir():
        raise AdapterError(f"target root is not a directory: {root_path}")

    try:
        snapshot = snapshot_tree(root_path)
    except (OSError, ProtectedObjectError) as exc:
        raise AdapterError(f"protected target snapshot failed: {exc}") from exc
    public = public_snapshot(snapshot)
    files: list[SourceFile] = []
    for item in public["sources"]:
        relative = Path(item["relative_path"])
        locator = relative.as_posix()
        content = snapshot["_content_by_path"][locator]
        classification = classify_file(locator, content)
        files.append(
            SourceFile(
                locator=locator,
                absolute_path=root_path / locator,
                size=int(item["size"]),
                sha256=str(item["content_sha256"]),
                content=content,
                metadata={
                    **item,
                    "file_class": classification["file_class"],
                    "scanner_ids": classification["scanner_ids"],
                    "coverage_status": classification["coverage_status"],
                },
            )
        )

    tree_digest = canonical_digest(
        {item.locator: item.sha256 for item in files}
    )
    return Subject(
        subject_id=f"{kind.lower()}:{tree_digest[:16]}",
        subject_kind=kind,
        root=root_path,
        files=tuple(files),
        tree_digest=tree_digest,
        root_generation=str(public["root_generation"]),
        directories=tuple(public["directories"]),
        snapshot_digest=str(public["snapshot_digest"]),
    )


def build_required_sources(subject: Subject) -> list[dict[str, object]]:
    if subject.subject_kind != "SKILL":
        raise AdapterError(
            f"no released target-specific adapter for {subject.subject_kind}"
        )
    sources = [
        {
            "schema_version": 1,
            "source_id": f"source:{item.locator}",
            "source_type": "RESOURCE",
            "locator": item.locator,
            "applicability": "APPLICABLE",
        }
        for item in subject.files
    ]
    present = {item.locator for item in subject.files}
    if subject.subject_kind == "SKILL":
        for locator in sorted(EXPECTED_SKILL_SOURCES - present):
            sources.append(
                {
                    "schema_version": 1,
                    "source_id": f"source:{locator}",
                    "source_type": "RESOURCE",
                    "locator": locator,
                    "applicability": "REQUIRED_MISSING",
                }
            )
    return sources


def build_required_sources_v2(
    subject: Subject,
    *,
    candidate_digest: str | None = None,
    registry_snapshot: object | None = None,
) -> dict[str, object]:
    from .source_inventory import build_source_inventory

    return build_source_inventory(
        subject,
        candidate_digest=candidate_digest,
        registry_snapshot=registry_snapshot,
    )
