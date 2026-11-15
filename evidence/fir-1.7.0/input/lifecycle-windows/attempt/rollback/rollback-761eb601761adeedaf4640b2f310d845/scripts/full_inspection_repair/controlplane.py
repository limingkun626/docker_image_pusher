from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


class ControlPlaneBlocked(ValueError):
    """A layout or lifecycle failure that must fail before any run write."""

    def __init__(self, failure_code: str, message: str):
        super().__init__(message)
        self.failure_code = failure_code


@dataclass(frozen=True)
class RunLayout:
    command: str
    target: Path
    output: Path
    candidate: Path | None = None


INSPECTION_SUCCESS = frozenset(
    {"CHECKED", "REPAIRED_CANDIDATE", "CLOSED_FOR_DECLARED_UNIVERSE"}
)
INSPECTION_BLOCKED = frozenset(
    {
        "BLOCKED_SCOPE",
        "BLOCKED_ADAPTER",
        "BLOCKED_TAXONOMY",
        "BLOCKED_STALE_INPUT",
        "BLOCKED_DETECTOR",
        "BLOCKED_EVIDENCE",
        "BLOCKED_REPAIR_PLAN",
        "BLOCKED_REPAIR_CONFLICT",
        "BLOCKED_VERIFICATION",
        "BLOCKED_INDEPENDENT_REVIEW",
    }
)
RELEASE_SUCCESS = frozenset({"PASS", "RELEASE_READY"})
INSTALL_SUCCESS = frozenset({"INSTALLED", "POST_INSTALL_VERIFIED"})


def assert_phase_status(phase: str, status: str) -> None:
    allowed = {
        "inspection": INSPECTION_SUCCESS | INSPECTION_BLOCKED,
        "release": RELEASE_SUCCESS | INSPECTION_BLOCKED,
        "install": INSTALL_SUCCESS | {"BLOCKED_VERIFICATION"},
    }
    try:
        permitted = allowed[phase]
    except KeyError as exc:
        raise ControlPlaneBlocked("INVALID_LIFECYCLE_PHASE", phase) from exc
    if status not in permitted:
        raise ControlPlaneBlocked(
            "STATUS_OUTSIDE_PHASE",
            f"{status} is not valid in the {phase} lifecycle",
        )


def _resolved(path: str | os.PathLike[str]) -> Path:
    # Keep link components visible so the no-link check cannot be bypassed by
    # resolving the path before inspection.
    return Path(os.path.abspath(Path(path).expanduser()))


def _is_ancestor(left: Path, right: Path) -> bool:
    try:
        right.relative_to(left)
    except ValueError:
        return False
    return True


def _overlap(left: Path, right: Path) -> bool:
    return left == right or _is_ancestor(left, right) or _is_ancestor(right, left)


def _is_reparse_or_link(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _assert_regular_chain(path: Path, failure_code: str) -> None:
    current = path
    chain: list[Path] = []
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for item in reversed(chain):
        if _is_reparse_or_link(item):
            raise ControlPlaneBlocked(
                failure_code,
                f"link or reparse point is not allowed in run path: {item}",
            )


def _assert_new_path(path: Path, *, role: str) -> None:
    if path.exists():
        raise ControlPlaneBlocked(
            f"{role.upper()}_ALREADY_EXISTS",
            f"{role} already exists: {path}",
        )
    ancestor = path.parent
    while not ancestor.exists() and ancestor.parent != ancestor:
        ancestor = ancestor.parent
    if not ancestor.is_dir():
        raise ControlPlaneBlocked(
            "INVALID_OUTPUT_PARENT",
            f"nearest existing {role} parent is not a directory: {ancestor}",
        )


def resolve_layout(
    command: str,
    *,
    target: str | os.PathLike[str],
    output: str | os.PathLike[str],
    candidate: str | os.PathLike[str] | None = None,
) -> RunLayout:
    target_path = _resolved(target)
    output_path = _resolved(output)
    candidate_path = _resolved(candidate) if candidate is not None else None

    if not target_path.is_dir():
        raise ControlPlaneBlocked("TARGET_NOT_DIRECTORY", f"target is not a directory: {target_path}")
    _assert_regular_chain(target_path, "TARGET_LINK_UNSAFE")
    _assert_regular_chain(output_path, "OUTPUT_LINK_UNSAFE")
    if candidate_path is not None:
        _assert_regular_chain(candidate_path, "CANDIDATE_LINK_UNSAFE")

    if _overlap(target_path, output_path):
        raise ControlPlaneBlocked(
            "OUTPUT_OVERLAPS_TARGET",
            "output must be disjoint from the target",
        )
    _assert_new_path(output_path, role="output")

    if candidate_path is not None:
        if _overlap(target_path, candidate_path):
            raise ControlPlaneBlocked(
                "CANDIDATE_OVERLAPS_SOURCE",
                "candidate must be disjoint from the source target",
            )
        if _overlap(output_path, candidate_path):
            raise ControlPlaneBlocked(
                "CANDIDATE_OVERLAPS_OUTPUT",
                "candidate must be disjoint from the output directory",
            )
        _assert_new_path(candidate_path, role="candidate")

    return RunLayout(
        command=command,
        target=target_path,
        output=output_path,
        candidate=candidate_path,
    )
