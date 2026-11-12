from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .contracts import canonical_digest
from .protected_reader import public_snapshot, snapshot_tree
from .release import ReleaseBlocked, validate_claim_for_install
from .review import ReviewBlocked
from .strict import fsync_directory, fsync_fd, open_no_follow

EXCLUDED_NAMES = frozenset(
    {".git", "__pycache__", ".pytest_cache", ".ruff_cache"}
)


class PackageError(ValueError):
    """Raised when a package cannot be verified or installed safely."""


class InstallBlocked(PackageError):
    """Raised after an installation attempt fails and rollback has run."""


class RestoreBlocked(InstallBlocked):
    """Raised when installation failed and the prior target could not be restored."""


def _absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _file_digest(root: Path) -> dict[str, str]:
    return {
        str(item["path"]): str(item["sha256"])
        for item in _files(root)
    }


def _files(root: Path) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    snapshot = public_snapshot(snapshot_tree(root))
    for item in snapshot["sources"]:
        relative = Path(item["relative_path"])
        if any(part in EXCLUDED_NAMES for part in relative.parts):
            raise PackageError(f"runtime cache is not package content: {relative.as_posix()}")
        files.append(
            {
                "path": relative.as_posix(),
                "bytes": item["size"],
                "sha256": item["content_sha256"],
            }
        )
    return sorted(files, key=lambda item: item["path"])


def build_package_manifest(root: str | Path) -> dict[str, object]:
    source = _absolute(root)
    if not source.is_dir():
        raise PackageError(f"package source is not a directory: {source}")
    files = _files(source)
    manifest: dict[str, object] = {
        "schema_version": 1,
        "root_name": source.name,
        "files": files,
        "tree_digest": canonical_digest(
            {str(item["path"]): str(item["sha256"]) for item in files}
        ),
    }
    manifest["manifest_digest"] = canonical_digest(manifest)
    return manifest


def verify_package_manifest(
    root: str | Path, manifest: dict[str, object]
) -> None:
    current = build_package_manifest(root)
    if current["files"] != manifest.get("files"):
        raise PackageError("package file set or content mismatch")
    if current["tree_digest"] != manifest.get("tree_digest"):
        raise PackageError("package tree digest mismatch")
    material = dict(manifest)
    declared = material.pop("manifest_digest", None)
    if declared != canonical_digest(material):
        raise PackageError("package manifest digest mismatch")


def _is_link(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _assert_no_link_chain(path: Path, label: str) -> None:
    current = path
    while True:
        if _is_link(current):
            raise PackageError(f"{label} path is a symbolic link or reparse point: {current}")
        if current == current.parent:
            return
        current = current.parent


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _volume_identity(path: Path) -> tuple[str, str, int]:
    current = path
    while not current.exists():
        if current == current.parent:
            raise PackageError(f"cannot resolve an existing ancestor for: {path}")
        current = current.parent
    info = os.stat(current, follow_symlinks=False)
    return (os.name, current.anchor.casefold(), int(info.st_dev))


def _preflight_topology(
    source: Path, target: Path, rollback: Path
) -> dict[str, object]:
    for path, label in (
        (source, "source"),
        (target, "target"),
        (rollback, "rollback"),
    ):
        _assert_no_link_chain(path, label)
    if _overlap(source, target):
        raise PackageError("source and target roots must be disjoint")
    if _overlap(source, rollback):
        raise PackageError("source and rollback roots must be disjoint")
    if _overlap(target, rollback):
        raise PackageError("target and rollback roots must be disjoint")
    target_volume = _volume_identity(target if target.exists() else target.parent)
    rollback_volume = _volume_identity(rollback.parent)
    source_volume = _volume_identity(source)
    if len({source_volume, target_volume, rollback_volume}) != 1:
        raise PackageError("source, staging, rollback and target must be on one volume")
    return {
        "source_volume": repr(source_volume),
        "target_volume": repr(target_volume),
        "rollback_volume": repr(rollback_volume),
        "source_target_disjoint": True,
        "source_rollback_disjoint": True,
        "target_rollback_disjoint": True,
        "same_volume": True,
        "link_chain_clear": True,
    }


def _default_smoke(target: Path) -> None:
    if not (target / "SKILL.md").is_file():
        raise PackageError("installed SKILL.md is missing")


def _fsync_tree(root: Path) -> None:
    directories: list[Path] = []
    for current, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if not _is_link(current_path / name)
        )
        directories.append(current_path)
        for name in sorted(file_names):
            path = current_path / name
            if not stat.S_ISREG(os.lstat(path).st_mode):
                continue
            fd = open_no_follow(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
            try:
                fsync_fd(fd)
            finally:
                os.close(fd)
    for directory in reversed(directories):
        fsync_directory(directory)


def _durable_directory_replace(
    source: str | Path,
    destination: str | Path,
) -> None:
    source_path = _absolute(source)
    destination_path = _absolute(destination)
    source_parent = source_path.parent
    destination_parent = destination_path.parent
    _fsync_tree(source_path)
    fsync_directory(source_parent)
    fsync_directory(destination_parent)
    os.replace(source_path, destination_path)
    fsync_directory(source_parent)
    fsync_directory(destination_parent)


def _restore_after_failure(
    target: Path,
    failed: Path,
    rollback: Path | None,
) -> None:
    if target.exists() or _is_link(target):
        _durable_directory_replace(target, failed)
    if rollback is not None and rollback.exists():
        _durable_directory_replace(rollback, target)


def install_package(
    source: str | Path,
    target: str | Path,
    manifest: dict[str, object],
    *,
    claim: dict[str, Any] | None = None,
    review: dict[str, Any] | None = None,
    verification_method: str = "ed25519-detached",
    attestation_bytes: bytes | None = None,
    attestation_path: str | Path | None = None,
    signature_bytes: bytes | None = None,
    public_key_bytes: bytes | None = None,
    issuer: str | None = None,
    trust_root_id: str | None = None,
    sigstore_bundle: str | Path | None = None,
    sigstore_verifier: str | Path | None = None,
    cert_identity: str | None = None,
    oidc_issuer: str | None = None,
    trust_registry: dict[str, Any] | None = None,
    trust_registry_digest: str | None = None,
    trust_anchor: dict[str, Any] | None = None,
    evaluator_artifact_bytes: bytes | None = None,
    trust_config_path: str | Path | None = None,
    snapshot_root: str | Path | None = None,
    verification_runner=None,
    rollback_root: str | Path | None = None,
    smoke_check: Callable[[Path], None] | None = None,
    commit_callback: Callable[[dict[str, object]], None] | None = None,
) -> dict[str, object]:
    if claim is None:
        raise PackageError("install requires a current RELEASE_READY claim")
    if review is None:
        raise PackageError("install requires the independent review receipt")
    if attestation_bytes is None and attestation_path is None:
        raise PackageError("install requires reviewer attestation bytes")
    if (
        evaluator_artifact_bytes is not None
        and hashlib.sha256(evaluator_artifact_bytes).hexdigest()
        != review.get("evaluator_digest")
    ):
        raise PackageError("install evaluator artifact does not match the review")
    if verification_method == "ed25519-detached":
        if signature_bytes is None:
            raise PackageError("install requires a detached reviewer signature")
        if public_key_bytes is None:
            raise PackageError("install requires the frozen Ed25519 public key")
        if not issuer:
            raise PackageError("install requires the exact reviewer issuer")
        if not trust_root_id:
            raise PackageError("install requires the exact trust-root identity")
    elif verification_method != "sigstore-keyless":
        raise PackageError(f"unsupported verification method: {verification_method}")

    source_path = _absolute(source)
    target_path = _absolute(target)
    rollback_path = _absolute(
        rollback_root
        if rollback_root is not None
        else target_path.with_name(f".{target_path.name}.rollback")
    )
    if not source_path.is_dir():
        raise PackageError(f"package source is not a directory: {source_path}")
    verify_package_manifest(source_path, manifest)
    try:
        validate_claim_for_install(
            claim,
            review,
            verification_method=verification_method,
            attestation_bytes=attestation_bytes,
            attestation_path=attestation_path,
            signature_bytes=signature_bytes,
            public_key_bytes=public_key_bytes,
            issuer=issuer,
            candidate_digest=str(manifest["tree_digest"]),
            trust_root_id=trust_root_id,
            sigstore_bundle=sigstore_bundle,
            sigstore_verifier=sigstore_verifier,
            cert_identity=cert_identity,
            oidc_issuer=oidc_issuer,
            trust_registry=trust_registry,
            trust_registry_digest=trust_registry_digest,
            trust_anchor=trust_anchor,
            trust_config_path=trust_config_path,
            snapshot_root=snapshot_root,
            runner=verification_runner,
        )
    except (ReleaseBlocked, ReviewBlocked) as exc:
        raise PackageError(str(exc)) from exc
    if target_path.exists() and not target_path.is_dir():
        raise PackageError(f"install target is not a directory: {target_path}")
    if rollback_path.exists() or _is_link(rollback_path):
        raise PackageError(f"rollback target already exists: {rollback_path}")
    preflight = _preflight_topology(source_path, target_path, rollback_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_link_chain(target_path, "target")
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{target_path.name}.install-", dir=target_path.parent)
    )
    staged = temporary / target_path.name
    activated = False
    target_before_digest = (
        build_package_manifest(target_path)["tree_digest"]
        if target_path.exists()
        else None
    )
    check = smoke_check or _default_smoke
    try:
        shutil.copytree(source_path, staged, symlinks=True)
        _fsync_tree(staged)
        verify_package_manifest(staged, manifest)
        if target_path.exists():
            _durable_directory_replace(target_path, rollback_path)
        try:
            _durable_directory_replace(staged, target_path)
            activated = True
        except Exception as activation_exc:
            if rollback_path.exists():
                try:
                    _durable_directory_replace(rollback_path, target_path)
                except OSError as restore_exc:
                    raise RestoreBlocked(
                        "BLOCKED_RESTORE "
                        f"target={target_path} rollback={rollback_path}: "
                        f"{restore_exc}"
                    ) from activation_exc
            raise
        verify_package_manifest(target_path, manifest)
        check(target_path)
        post_install_digest = build_package_manifest(target_path)["tree_digest"]
        if post_install_digest != manifest["tree_digest"]:
            raise PackageError("post-install tree digest mismatch")
        if commit_callback is not None:
            commit_callback(
                {
                    "claim_digest": claim["claim_digest"],
                    "review_digest": review["review_digest"],
                    "candidate_digest": manifest["tree_digest"],
                    "target": str(target_path),
                    "rollback_root": (
                        str(rollback_path) if rollback_path.exists() else None
                    ),
                }
            )
    except Exception as exc:
        if activated:
            try:
                _restore_after_failure(
                    target_path,
                    temporary / "failed-target",
                    rollback_path if rollback_path.exists() else None,
                )
            except (OSError, PackageError, RuntimeError) as restore_exc:
                raise RestoreBlocked(
                    "BLOCKED_RESTORE "
                    f"target={target_path} rollback={rollback_path}: {restore_exc}"
                ) from exc
        current_digest = (
            build_package_manifest(target_path)["tree_digest"]
            if target_path.exists()
            else None
        )
        if current_digest != target_before_digest:
            raise RestoreBlocked(
                "BLOCKED_RESTORE "
                f"target={target_path} rollback={rollback_path}: "
                "target state does not match the pre-install state"
            ) from exc
        if target_before_digest is not None:
            detail = "post-install check failed and old install was restored"
        else:
            detail = "post-install check failed and the absent target state was restored"
        raise InstallBlocked(f"{detail}: {exc}") from exc
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)

    rollback_digest = (
        build_package_manifest(rollback_path)["tree_digest"]
        if rollback_path.exists()
        else None
    )
    receipt: dict[str, object] = {
        "schema_version": 2,
        "status": "INSTALLED",
        "claim_digest": claim["claim_digest"],
        "review_digest": review["review_digest"],
        "subject_digest": review["subject_digest"],
        "issuer": review["external_signature"]["issuer"],
        "trust_root_id": review["external_signature"]["trust_root_id"],
        "trust_anchor_digest": review["external_signature"]["trust_anchor_digest"],
        "history_anchor_key_sha256": review["external_signature"][
            "history_anchor_key_sha256"
        ],
        "verification_method": review["external_signature"]["verification_method"],
        "attestation_sha256": review["external_signature"]["attestation_sha256"],
        "signature_sha256": review["external_signature"]["signature_sha256"],
        "signature_verification_receipt_digest": review["external_signature"][
            "receipt_digest"
        ],
        "source": str(source_path),
        "target": str(target_path),
        "staging_root": str(temporary),
        "candidate_digest": manifest["tree_digest"],
        "source_manifest_digest": manifest["manifest_digest"],
        "target_before_digest": target_before_digest,
        "post_install_digest": post_install_digest,
        "install_digest": post_install_digest,
        "rollback_root": str(rollback_path) if rollback_path.exists() else None,
        "rollback_digest": rollback_digest,
        "rollback_retained": rollback_path.exists(),
        "preflight": preflight,
        "staged_verified": True,
        "readback_verified": True,
        "smoke_verified": True,
        "activated_atomically": True,
    }
    if verification_method == "sigstore-keyless":
        receipt["bundle_sha256"] = review["external_signature"]["bundle_sha256"]
        receipt["verifier_command_digest"] = review["external_signature"][
            "verifier_command_digest"
        ]
        receipt["trust_config_sha256"] = review["external_signature"][
            "trust_config_sha256"
        ]
        receipt["verifier_closure_digest"] = review["external_signature"][
            "verifier_closure_digest"
        ]
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt
