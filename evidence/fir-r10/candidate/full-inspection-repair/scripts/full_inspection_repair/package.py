from __future__ import annotations

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

EXCLUDED_NAMES = frozenset(
    {".git", "__pycache__", ".pytest_cache", ".ruff_cache"}
)


class PackageError(ValueError):
    """Raised when a package cannot be verified or installed safely."""


class InstallBlocked(PackageError):
    """Raised after an installation attempt fails and rollback has run."""


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


def _restore_after_failure(
    target: Path,
    failed: Path,
    rollback: Path | None,
) -> None:
    if target.exists() or _is_link(target):
        os.replace(target, failed)
    if rollback is not None and rollback.exists():
        os.replace(rollback, target)


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
    verification_runner=None,
    rollback_root: str | Path | None = None,
    smoke_check: Callable[[Path], None] | None = None,
) -> dict[str, object]:
    if claim is None:
        raise PackageError("install requires a current RELEASE_READY claim")
    if review is None:
        raise PackageError("install requires the independent review receipt")
    if attestation_bytes is None and attestation_path is None:
        raise PackageError("install requires reviewer attestation bytes")
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
        verify_package_manifest(staged, manifest)
        if target_path.exists():
            os.replace(target_path, rollback_path)
        try:
            os.replace(staged, target_path)
            activated = True
        except Exception:
            if rollback_path.exists():
                os.replace(rollback_path, target_path)
            raise
        verify_package_manifest(target_path, manifest)
        check(target_path)
        post_install_digest = build_package_manifest(target_path)["tree_digest"]
        if post_install_digest != manifest["tree_digest"]:
            raise PackageError("post-install tree digest mismatch")
    except Exception as exc:
        if activated:
            try:
                _restore_after_failure(
                    target_path,
                    temporary / "failed-target",
                    rollback_path if rollback_path.exists() else None,
                )
            except (OSError, PackageError, RuntimeError) as restore_exc:
                raise PackageError(
                    f"install failed and rollback restore failed: {restore_exc}"
                ) from exc
        raise InstallBlocked(
            f"post-install check failed and old install was restored: {exc}"
        ) from exc
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
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt
