from __future__ import annotations

import base64
import binascii
import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

from .contracts import canonical_digest
from .risk_gate import assess_release_gate
from .strict import strict_loads, write_all

REVIEW_SCHEMA_VERSION = 2
REVIEWER_ATTESTATION_SCHEMA_VERSION = 1
SIGNATURE_RECEIPT_SCHEMA_VERSION = 2
ED25519_VERIFIER = "ed25519-detached"
SIGSTORE_VERIFIER = "sigstore-keyless"
VerificationRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
MAX_REVIEW_ARTIFACT_BYTES = 64 * 1024 * 1024
TRUST_ANCHOR_SCHEMA_VERSION = 1
DEFAULT_TRUST_ANCHOR_PATH = (
    Path(__file__).resolve().parents[2] / "policies" / "trust-policy.json"
)
DEFAULT_TRUST_ANCHOR_DIGEST = (
    "bde8e6470a9776798a889945e4edb89938f0ccc5be7a9548d0ca4cf9c7bd4913"
)


class ReviewBlocked(ValueError):
    """Raised when independent review cannot issue a PASS."""


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _identity_key(value: object) -> str:
    return " ".join(str(value).strip().casefold().split())


def _bounded_read(path: Path, label: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ReviewBlocked(f"{label} cannot be read: {exc}") from exc
    if size > MAX_REVIEW_ARTIFACT_BYTES:
        raise ReviewBlocked(f"{label} exceeds size policy")
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_REVIEW_ARTIFACT_BYTES + 1)
    except OSError as exc:
        raise ReviewBlocked(f"{label} cannot be read: {exc}") from exc
    if len(data) > MAX_REVIEW_ARTIFACT_BYTES:
        raise ReviewBlocked(f"{label} exceeds size policy")
    return data


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
            raise ReviewBlocked(f"{label} path is a symbolic link or reparse point")
        if current == current.parent:
            return
        current = current.parent


def validate_trust_anchor(anchor: dict[str, Any] | None) -> dict[str, Any]:
    """Validate the separately frozen release authority document."""

    if not isinstance(anchor, dict):
        raise ReviewBlocked("protected trust anchor is required")
    if anchor.get("schema_version") != TRUST_ANCHOR_SCHEMA_VERSION:
        raise ReviewBlocked("trust anchor schema mismatch")
    if not isinstance(anchor.get("policy_id"), str) or not anchor["policy_id"].strip():
        raise ReviewBlocked("trust anchor policy identity is required")
    reviewers = anchor.get("reviewers")
    if not isinstance(reviewers, list):
        raise ReviewBlocked("trust anchor reviewers are required")
    registry = {"schema_version": 1, "reviewers": reviewers}
    if anchor.get("reviewer_registry_digest") != canonical_digest(registry):
        raise ReviewBlocked("trust anchor reviewer registry digest mismatch")
    for field in (
        "evaluator_artifacts",
        "history_anchor_key_sha256",
        "sigstore_trust_config_sha256",
    ):
        values = anchor.get(field)
        if not isinstance(values, list) or any(
            not _valid_digest(value) for value in values
        ):
            raise ReviewBlocked(f"trust anchor {field} digest list is invalid")
    for entry in reviewers:
        if not isinstance(entry, dict):
            raise ReviewBlocked("trust anchor reviewer entry is invalid")
        if entry.get("status") not in {"ACTIVE", "REVOKED"}:
            raise ReviewBlocked("trust anchor reviewer status is invalid")
        if entry.get("status") == "ACTIVE":
            if not entry.get("reviewer") or not entry.get("issuer"):
                raise ReviewBlocked("trust anchor reviewer identity is incomplete")
            if not entry.get("trust_root_id"):
                raise ReviewBlocked("trust anchor reviewer root is incomplete")
            if entry.get("verification_method") == SIGSTORE_VERIFIER:
                closure = entry.get("verifier_closure")
                if not isinstance(closure, list) or not closure:
                    raise ReviewBlocked(
                        "trust anchor verifier execution closure is required"
                    )
                for file_entry in closure:
                    if (
                        not isinstance(file_entry, dict)
                        or not isinstance(file_entry.get("path"), str)
                        or not _valid_digest(file_entry.get("sha256"))
                        or not file_entry.get("role")
                    ):
                        raise ReviewBlocked(
                            "trust anchor verifier execution closure is invalid"
                        )
    return anchor


def load_trust_anchor(
    path: str | Path = DEFAULT_TRUST_ANCHOR_PATH,
    *,
    expected_digest: str = DEFAULT_TRUST_ANCHOR_DIGEST,
) -> dict[str, Any]:
    """Load the code-frozen trust anchor rather than a caller-selected registry."""

    anchor_path = Path(path)
    _assert_no_link_chain(anchor_path, "trust anchor")
    before = _file_identity(anchor_path)
    data = _bounded_read(anchor_path, "trust anchor")
    if _file_identity(anchor_path) != before:
        raise ReviewBlocked("trust anchor changed while it was loaded")
    if hashlib.sha256(data).hexdigest() == expected_digest:
        raw_digest_matches = True
    else:
        raw_digest_matches = False
    try:
        anchor = strict_loads(data)
    except ValueError as exc:
        raise ReviewBlocked(f"trust anchor JSON is invalid: {exc}") from exc
    if not isinstance(anchor, dict):
        raise ReviewBlocked("trust anchor must be a JSON object")
    if not raw_digest_matches and canonical_digest(anchor) != expected_digest:
        raise ReviewBlocked("trust anchor digest does not match the frozen identity")
    return validate_trust_anchor(anchor)


def _trust_anchor_or_default(
    trust_anchor: dict[str, Any] | None,
) -> dict[str, Any]:
    return load_trust_anchor() if trust_anchor is None else validate_trust_anchor(trust_anchor)


def _trust_registry_for_anchor(anchor: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "reviewers": anchor["reviewers"],
    }


def _validate_anchor_registry(
    registry: dict[str, Any] | None,
    expected_digest: str | None,
    trust_anchor: dict[str, Any],
) -> dict[str, Any]:
    expected_registry = _trust_registry_for_anchor(trust_anchor)
    if not isinstance(registry, dict) or registry != expected_registry:
        raise ReviewBlocked("caller trust registry is not the frozen registry")
    if expected_digest != trust_anchor["reviewer_registry_digest"]:
        raise ReviewBlocked("caller trust registry digest is not the frozen identity")
    return registry


def validate_evaluator_artifact(
    trust_anchor: dict[str, Any],
    *,
    artifact_bytes: bytes | None,
    expected_digest: str | None,
) -> str:
    if artifact_bytes is None:
        raise ReviewBlocked("exact evaluator artifact bytes are required")
    actual = hashlib.sha256(artifact_bytes).hexdigest()
    if expected_digest is not None and actual != expected_digest:
        raise ReviewBlocked("evaluator artifact digest mismatch")
    if actual not in trust_anchor["evaluator_artifacts"]:
        raise ReviewBlocked("evaluator artifact is not approved by the trust anchor")
    return actual


def validate_trust_registry(
    registry: dict[str, Any] | None,
    expected_digest: str | None,
    *,
    trust_anchor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    anchor = _trust_anchor_or_default(trust_anchor)
    return _validate_anchor_registry(registry, expected_digest, anchor)


def _registered_identity(
    registry: dict[str, Any],
    *,
    reviewer: str,
    issuer: str,
    verification_method: str,
) -> dict[str, Any]:
    matches = [
        entry
        for entry in registry.get("reviewers", [])
        if isinstance(entry, dict)
        and _identity_key(entry.get("reviewer")) == _identity_key(reviewer)
        and entry.get("verification_method") == verification_method
    ]
    if len(matches) != 1:
        raise ReviewBlocked("reviewer is not uniquely registered in the trust registry")
    entry = matches[0]
    if str(entry.get("issuer")) != issuer:
        raise ReviewBlocked("reviewer issuer mismatch")
    if entry.get("status") != "ACTIVE":
        raise ReviewBlocked("registered reviewer is not ACTIVE")
    return entry


def _decode_signature(value: bytes) -> bytes:
    if len(value) == 64:
        return value
    try:
        decoded = base64.b64decode(value.strip(), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReviewBlocked("signature is neither raw Ed25519 bytes nor base64") from exc
    if len(decoded) != 64:
        raise ReviewBlocked("Ed25519 signature must be 64 bytes")
    return decoded


def _load_ed25519_public_key(value: bytes):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise ReviewBlocked("cryptography Ed25519 verifier is unavailable") from exc
    try:
        if b"-----BEGIN PUBLIC KEY-----" in value:
            key = serialization.load_pem_public_key(value)
        elif len(value) == 32:
            key = ed25519.Ed25519PublicKey.from_public_bytes(value)
        else:
            raise ValueError("unsupported public-key encoding")
    except (TypeError, ValueError) as exc:
        raise ReviewBlocked("frozen public key is invalid") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ReviewBlocked("frozen public key is not Ed25519")
    return key, serialization


def trust_root_id_for_public_key(public_key: bytes) -> str:
    key, serialization = _load_ed25519_public_key(public_key)
    spki = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(spki).hexdigest()


def sigstore_trust_root_id(cert_identity: str, oidc_issuer: str) -> str:
    if not cert_identity or not oidc_issuer:
        raise ReviewBlocked("Sigstore cert identity and OIDC issuer are required")
    material = {
        "verification_method": SIGSTORE_VERIFIER,
        "cert_identity": cert_identity,
        "oidc_issuer": oidc_issuer,
    }
    return "sigstore:" + canonical_digest(material)


def verify_reviewer_attestation(
    *,
    attestation_bytes: bytes,
    signature_bytes: bytes,
    public_key_bytes: bytes,
    expected_reviewer: str,
    expected_issuer: str,
    expected_trust_root_id: str,
    trust_registry: dict[str, Any] | None,
    trust_registry_digest: str | None,
    trust_anchor: dict[str, Any] | None = None,
    history_anchor_key_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify exact attestation bytes with a frozen Ed25519 public key."""

    computed_trust_root = trust_root_id_for_public_key(public_key_bytes)
    if computed_trust_root != expected_trust_root_id:
        raise ReviewBlocked("frozen public key does not match the trust root")
    anchor = _trust_anchor_or_default(trust_anchor)
    selected_history_key = history_anchor_key_sha256
    if selected_history_key is None and len(anchor["history_anchor_key_sha256"]) == 1:
        selected_history_key = anchor["history_anchor_key_sha256"][0]
    if (
        selected_history_key is not None
        and selected_history_key not in anchor["history_anchor_key_sha256"]
    ):
        raise ReviewBlocked("review history anchor key is not frozen")
    registry = validate_trust_registry(
        trust_registry,
        trust_registry_digest,
        trust_anchor=anchor,
    )
    entry = _registered_identity(
        registry,
        reviewer=expected_reviewer,
        issuer=expected_issuer,
        verification_method=ED25519_VERIFIER,
    )
    if entry.get("trust_root_id") != expected_trust_root_id:
        raise ReviewBlocked("caller trust root is not registered")
    if entry.get("public_key_sha256") != hashlib.sha256(public_key_bytes).hexdigest():
        raise ReviewBlocked("reviewer public key is not the registered key")
    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise ReviewBlocked("cryptography Ed25519 verifier is unavailable") from exc
    key, _serialization = _load_ed25519_public_key(public_key_bytes)
    signature = _decode_signature(signature_bytes)
    try:
        key.verify(signature, attestation_bytes)
    except InvalidSignature as exc:
        raise ReviewBlocked("reviewer attestation signature verification failed") from exc
    try:
        attestation = strict_loads(attestation_bytes)
    except ValueError as exc:
        raise ReviewBlocked(f"reviewer attestation JSON is invalid: {exc}") from exc
    if not isinstance(attestation, dict):
        raise ReviewBlocked("reviewer attestation must be a JSON object")
    if attestation.get("schema_version") != REVIEWER_ATTESTATION_SCHEMA_VERSION:
        raise ReviewBlocked("reviewer attestation schema mismatch")
    if attestation.get("verification_method") != ED25519_VERIFIER:
        raise ReviewBlocked("reviewer attestation verification method mismatch")
    if attestation.get("verdict") != "PASS":
        raise ReviewBlocked("reviewer attestation verdict is not PASS")
    if _identity_key(attestation.get("reviewer")) != _identity_key(expected_reviewer):
        raise ReviewBlocked("reviewer attestation identity mismatch")
    if attestation.get("issuer") != expected_issuer:
        raise ReviewBlocked("reviewer attestation issuer mismatch")
    if attestation.get("trust_root_id") != expected_trust_root_id:
        raise ReviewBlocked("reviewer attestation trust root mismatch")
    receipt: dict[str, Any] = {
        "schema_version": SIGNATURE_RECEIPT_SCHEMA_VERSION,
        "status": "VERIFIED",
        "verification_method": ED25519_VERIFIER,
        "reviewer": expected_reviewer,
        "issuer": expected_issuer,
        "trust_root_id": expected_trust_root_id,
        "attestation_sha256": hashlib.sha256(attestation_bytes).hexdigest(),
        "attestation_digest": canonical_digest(attestation),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
        "public_key_fingerprint": computed_trust_root,
        "trust_registry_digest": trust_registry_digest,
        "trust_anchor_digest": canonical_digest(anchor),
        "history_anchor_key_sha256": selected_history_key,
        "reviewer_attestation": attestation,
        "verified_at": attestation.get("reviewed_at"),
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt


def _run_sigstore(
    command: list[str], runner: VerificationRunner | None
) -> subprocess.CompletedProcess[str]:
    if runner is not None:
        try:
            return runner(command)
        except Exception as exc:
            raise ReviewBlocked(
                f"Sigstore verifier could not run against the private snapshot: {exc}"
            ) from exc
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReviewBlocked(f"Sigstore verifier could not run: {exc}") from exc


def _file_identity(path: Path) -> tuple[int, int, int, int, int]:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ReviewBlocked(f"verification input is not a regular file: {path}")
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _source_identity(path: Path) -> tuple[int, int, int, int, int]:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ReviewBlocked(f"verification source is not a regular file: {path}")
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _snapshot_file(
    source: Path,
    destination: Path,
    label: str,
    *,
    durable: bool = True,
) -> dict[str, Any]:
    _assert_no_link_chain(source, label)
    before = _source_identity(source)
    data = _bounded_read(source, label)
    after = _source_identity(source)
    if before != after:
        raise ReviewBlocked(f"{label} changed while it was snapshotted")
    destination.parent.mkdir(parents=True, exist_ok=True)
    creation_mode = 0o600 if os.name == "nt" else 0o400
    fd = os.open(
        destination,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0),
        creation_mode,
    )
    try:
        write_all(fd, data)
        if durable:
            os.fsync(fd)
    finally:
        os.close(fd)
    snapshot_bytes = _bounded_read(destination, "Sigstore snapshot")
    if snapshot_bytes != data:
        raise ReviewBlocked(f"{label} snapshot content mismatch")
    with suppress(OSError):
        os.chmod(destination, stat.S_IRUSR)
    return {
        "source": str(source),
        "snapshot": str(destination),
        "sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
        "size": len(data),
        "source_identity": before,
        "snapshot_identity": _file_identity(destination),
    }


def _assert_snapshot_unchanged(records: list[dict[str, Any]]) -> None:
    for record in records:
        source = Path(record["source"])
        snapshot = Path(record["snapshot"])
        if _source_identity(source) != record["source_identity"]:
            raise ReviewBlocked(
                f"Sigstore input changed during verification: {source.name}"
            )
        if _file_identity(snapshot) != record["snapshot_identity"]:
            raise ReviewBlocked(
                f"Sigstore executed snapshot changed during verification: "
                f"{snapshot.name}"
            )
        if hashlib.sha256(_bounded_read(snapshot, "Sigstore snapshot")).hexdigest() != (
            record["sha256"]
        ):
            raise ReviewBlocked(
                f"Sigstore executed snapshot content changed: {snapshot.name}"
            )


def _reset_private_root(path: Path) -> None:
    if not path.exists():
        return
    for directory, _names, files in os.walk(path):
        for name in files:
            with suppress(OSError):
                os.chmod(Path(directory) / name, stat.S_IWRITE | stat.S_IREAD)
    shutil.rmtree(path)


def _closure_relative_path(
    source: Path,
    file_entry: dict[str, Any],
    verifier_root: Path | None,
) -> Path:
    declared = file_entry.get("relative_path")
    if declared is not None:
        if not isinstance(declared, str) or not declared:
            raise ReviewBlocked("Sigstore closure relative path is invalid")
        relative = Path(declared)
    elif verifier_root is not None and source.is_relative_to(verifier_root):
        relative = source.relative_to(verifier_root)
    else:
        relative = Path(source.name)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or ":" in relative.parts[0]
    ):
        raise ReviewBlocked("Sigstore closure relative path escapes the snapshot")
    return relative


def _root_file_map(root: Path, label: str) -> dict[str, Path]:
    files: dict[str, Path] = {}
    if not root.is_dir():
        raise ReviewBlocked(f"{label} root is missing")
    _assert_no_link_chain(root, label)
    for directory, _names, names in os.walk(root, followlinks=False):
        for name in names:
            source = Path(directory) / name
            _assert_no_link_chain(source, label)
            if not source.is_file():
                raise ReviewBlocked(f"{label} contains a non-regular file: {source}")
            files[source.relative_to(root).as_posix()] = source
    return files


def _rewrite_snapshot_venv_config(
    config: Path,
    *,
    runtime_root: Path,
    runtime_executable: Path,
) -> dict[str, str]:
    with suppress(OSError):
        os.chmod(config, stat.S_IWRITE | stat.S_IREAD)
    try:
        text = config.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReviewBlocked(f"snapshot pyvenv.cfg cannot be read: {exc}") from exc
    fields = {
        "home": str(runtime_root),
        "executable": str(runtime_executable),
        "command": "private-sigstore-snapshot",
    }
    seen: set[str] = set()
    output: list[str] = []
    for line in text.splitlines():
        if "=" in line:
            key, _value = line.split("=", 1)
            key = key.strip()
            if key in fields:
                if key in seen:
                    raise ReviewBlocked(f"snapshot pyvenv.cfg duplicates {key}")
                output.append(f"{key} = {fields[key]}")
                seen.add(key)
                continue
        output.append(line)
    missing = sorted(set(fields) - seen)
    if missing:
        raise ReviewBlocked(
            "snapshot pyvenv.cfg is missing: " + ", ".join(missing)
        )
    payload = ("\n".join(output) + "\n").encode("utf-8")
    fd = os.open(
        config,
        os.O_WRONLY | os.O_TRUNC | getattr(os, "O_BINARY", 0),
    )
    try:
        write_all(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    with suppress(OSError):
        os.chmod(config, stat.S_IRUSR)
    return {
        "path": str(config),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "home": str(runtime_root),
        "executable": str(runtime_executable),
    }


def verify_sigstore_attestation(
    *,
    attestation_path: str | Path,
    bundle_path: str | Path,
    verifier_executable: str | Path,
    cert_identity: str,
    oidc_issuer: str,
    trust_registry: dict[str, Any] | None,
    trust_registry_digest: str | None,
    trust_anchor: dict[str, Any] | None = None,
    history_anchor_key_sha256: str | None = None,
    trust_config_path: str | Path | None = None,
    snapshot_root: str | Path | None = None,
    runner: VerificationRunner | None = None,
) -> dict[str, Any]:
    """Verify Sigstore evidence from one private, identity-checked snapshot."""

    attestation_file = Path(attestation_path)
    bundle = Path(bundle_path)
    verifier = Path(verifier_executable)
    trust_config = Path(trust_config_path) if trust_config_path is not None else None
    _assert_no_link_chain(attestation_file, "reviewer attestation")
    _assert_no_link_chain(bundle, "Sigstore bundle")
    _assert_no_link_chain(verifier, "Sigstore verifier")
    if not attestation_file.is_file():
        raise ReviewBlocked("reviewer attestation file is missing")
    if not bundle.is_file():
        raise ReviewBlocked("Sigstore bundle is missing")
    if not verifier.is_file():
        raise ReviewBlocked("Sigstore verifier executable is missing")
    if not cert_identity or not oidc_issuer:
        raise ReviewBlocked("Sigstore cert identity and OIDC issuer are required")
    anchor = _trust_anchor_or_default(trust_anchor)
    selected_history_key = history_anchor_key_sha256
    if selected_history_key is None and len(anchor["history_anchor_key_sha256"]) == 1:
        selected_history_key = anchor["history_anchor_key_sha256"][0]
    if (
        selected_history_key is not None
        and selected_history_key not in anchor["history_anchor_key_sha256"]
    ):
        raise ReviewBlocked("review history anchor key is not frozen")
    registry = validate_trust_registry(
        trust_registry,
        trust_registry_digest,
        trust_anchor=anchor,
    )
    entry = _registered_identity(
        registry,
        reviewer=cert_identity,
        issuer=oidc_issuer,
        verification_method=SIGSTORE_VERIFIER,
    )
    trust_root_id = sigstore_trust_root_id(cert_identity, oidc_issuer)
    if entry.get("trust_root_id") != trust_root_id:
        raise ReviewBlocked("Sigstore identity is not registered")
    actual_verifier_sha256 = hashlib.sha256(
        _bounded_read(verifier, "Sigstore verifier")
    ).hexdigest()
    if entry.get("verifier_sha256") != actual_verifier_sha256:
        raise ReviewBlocked("Sigstore verifier content identity mismatch")
    declared_closure = entry.get("verifier_closure")
    verifier_root_value = entry.get("verifier_root")
    verifier_root = (
        Path(str(verifier_root_value))
        if isinstance(verifier_root_value, str) and verifier_root_value
        else None
    )
    if verifier_root is not None:
        verifier_root = verifier_root.resolve()
        _assert_no_link_chain(verifier_root, "Sigstore verifier root")
        if not verifier.is_relative_to(verifier_root):
            raise ReviewBlocked("Sigstore verifier is outside its declared root")
    if verifier.suffix.lower() in {".cmd", ".bat", ".ps1", ".py", ".sh"}:
        roles = (
            {
                str(item.get("role"))
                for item in declared_closure
                if isinstance(item, dict)
            }
            if isinstance(declared_closure, list)
            else set()
        )
        if not {"helper", "runtime"}.issubset(roles):
            raise ReviewBlocked(
                "Sigstore wrapper verifier requires pinned helper and runtime closure"
            )
    verifier_version = str(entry.get("verifier_version", "")).strip()
    if not verifier_version:
        raise ReviewBlocked("registered Sigstore verifier version is required")
    if trust_config is None or not trust_config.is_file():
        raise ReviewBlocked("Sigstore trust configuration is required")
    trust_config_bytes = _bounded_read(trust_config, "Sigstore trust configuration")
    trust_config_sha256 = hashlib.sha256(trust_config_bytes).hexdigest()
    if trust_config_sha256 not in anchor["sigstore_trust_config_sha256"]:
        raise ReviewBlocked("Sigstore trust configuration is not frozen")
    root = (
        Path(snapshot_root)
        if snapshot_root is not None
        else Path(tempfile.gettempdir()) / "full-inspection-repair-sigstore"
    )
    root.mkdir(parents=True, exist_ok=True)
    _assert_no_link_chain(root, "Sigstore snapshot root")
    snapshot_id = canonical_digest(
        {
            "attestation": str(attestation_file.resolve()),
            "bundle": str(bundle.resolve()),
            "verifier": str(verifier.resolve()),
            "trust_config": str(trust_config.resolve()),
        }
    )[:32]
    private_root = root / f"sigstore-{snapshot_id}"
    if private_root.exists():
        if private_root.parent != root:
            raise ReviewBlocked("Sigstore snapshot path escaped its run root")
        _reset_private_root(private_root)
    private_root.mkdir(mode=0o700)
    os.chmod(private_root, 0o700)
    try:
        records = [
            _snapshot_file(
                attestation_file,
                private_root / "reviewer-attestation.json",
                "reviewer attestation",
            ),
            _snapshot_file(bundle, private_root / "bundle.json", "Sigstore bundle"),
            _snapshot_file(
                trust_config,
                private_root / "trust-config.json",
                "Sigstore trust configuration",
            ),
        ]
        closure = entry.get("verifier_closure")
        if not isinstance(closure, list) or not closure:
            raise ReviewBlocked("Sigstore verifier execution closure is missing")
        declared_relative_paths = {
            str(item["relative_path"])
            for item in closure
            if isinstance(item, dict) and item.get("relative_path") is not None
        }
        for field in (
            "venv_config_relative_path",
            "venv_runtime_executable_relative_path",
        ):
            value = entry.get(field)
            if value is not None and str(value) not in declared_relative_paths:
                raise ReviewBlocked(
                    f"Sigstore venv runtime closure is incomplete: {field}"
                )
        runtime_prefix = entry.get("venv_runtime_relative_path")
        if runtime_prefix is not None and not any(
            path.startswith(str(runtime_prefix).rstrip("/") + "/")
            for path in declared_relative_paths
        ):
            raise ReviewBlocked(
                "Sigstore venv runtime closure is incomplete: runtime directory"
            )
        if verifier_root is not None:
            root_files = _root_file_map(verifier_root, "Sigstore verifier root")
            closure_root_files = {
                Path(str(item["path"])).resolve()
                for item in closure
                if isinstance(item, dict)
                and Path(str(item.get("path", ""))).resolve().is_relative_to(
                    verifier_root
                )
            }
            if closure_root_files != set(root_files.values()):
                raise ReviewBlocked(
                    "Sigstore verifier root closure is incomplete or contains foreign files"
                )
        closure_root = private_root / "closure"
        execution_files: list[dict[str, str]] = []
        private_verifier: Path | None = None
        for file_entry in closure:
            source = Path(str(file_entry["path"]))
            if not source.is_absolute():
                source = (
                    verifier_root / source
                    if verifier_root is not None
                    else verifier.parent / source
                )
            relative = _closure_relative_path(source, file_entry, verifier_root)
            destination = closure_root / relative
            if destination.exists():
                raise ReviewBlocked(
                    "Sigstore verifier execution closure has duplicate paths"
                )
            record = _snapshot_file(
                source,
                destination,
                "Sigstore execution closure",
                durable=False,
            )
            if record["sha256"] != file_entry["sha256"]:
                raise ReviewBlocked(
                    f"Sigstore verifier execution closure mismatch: {source.name}"
                )
            records.append(record)
            execution_files.append(
                {
                    "role": str(file_entry["role"]),
                    "source": str(source),
                    "snapshot": str(destination),
                    "relative_path": relative.as_posix(),
                    "sha256": record["sha256"],
                }
            )
            if (
                file_entry.get("role") == "verifier"
                or source.resolve() == verifier.resolve()
            ):
                private_verifier = destination
        if private_verifier is None:
            raise ReviewBlocked(
                "Sigstore verifier execution closure does not pin the executable"
            )
        expected_verifier_relative = entry.get("verifier_executable_relative_path")
        if expected_verifier_relative is not None and (
            private_verifier
            != closure_root / Path(str(expected_verifier_relative))
        ):
            raise ReviewBlocked(
                "Sigstore verifier executable does not match its declared relative path"
            )
        transformed_files: list[dict[str, str]] = []
        config_relative = entry.get("venv_config_relative_path")
        runtime_relative = entry.get("venv_runtime_relative_path")
        runtime_executable_relative = entry.get(
            "venv_runtime_executable_relative_path"
        )
        if any(
            value is not None
            for value in (
                config_relative,
                runtime_relative,
                runtime_executable_relative,
            )
        ):
            if not all(
                isinstance(value, str) and value
                for value in (
                    config_relative,
                    runtime_relative,
                    runtime_executable_relative,
                )
            ):
                raise ReviewBlocked(
                    "Sigstore venv runtime closure declaration is incomplete"
                )
            config_path = closure_root / Path(str(config_relative))
            runtime_root = closure_root / Path(str(runtime_relative))
            runtime_executable = closure_root / Path(
                str(runtime_executable_relative)
            )
            if (
                not config_path.is_file()
                or not runtime_root.is_dir()
                or not runtime_executable.is_file()
            ):
                raise ReviewBlocked(
                    "Sigstore copied venv runtime closure is incomplete"
                )
            transformed = _rewrite_snapshot_venv_config(
                config_path,
                runtime_root=runtime_root,
                runtime_executable=runtime_executable,
            )
            transformed_files.append(transformed)
            for record in records:
                if Path(record["snapshot"]) == config_path:
                    record["sha256"] = transformed["sha256"]
                    record["size"] = config_path.stat().st_size
                    record["snapshot_identity"] = _file_identity(config_path)
            for execution_file in execution_files:
                if Path(execution_file["snapshot"]) == config_path:
                    execution_file["sha256"] = transformed["sha256"]
        private_attestation = private_root / "reviewer-attestation.json"
        private_bundle = private_root / "bundle.json"
        private_trust_config = private_root / "trust-config.json"
        version_result = _run_sigstore([str(private_verifier), "--version"], runner)
        version_output = (
            (version_result.stdout or "") + "\n" + (version_result.stderr or "")
        ).strip()
        if version_result.returncode != 0 or verifier_version not in version_output:
            raise ReviewBlocked("Sigstore verifier version identity mismatch")
        command = [
            str(private_verifier),
            "verify",
            "identity",
            "--offline",
            "--bundle",
            str(private_bundle),
            "--cert-identity",
            cert_identity,
            "--cert-oidc-issuer",
            oidc_issuer,
            "--trust-config",
            str(private_trust_config),
            str(private_attestation),
        ]
        completed = _run_sigstore(command, runner)
        _assert_snapshot_unchanged(records)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise ReviewBlocked(
                f"Sigstore verification failed with rc={completed.returncode}: {detail}"
            )
    finally:
        if os.name != "nt":
            with suppress(OSError):
                os.chmod(private_root, 0o700)
        for directory, names, _files in os.walk(private_root):
            if os.name != "nt":
                with suppress(OSError):
                    os.chmod(directory, 0o700)
            for name in names:
                if os.name != "nt":
                    with suppress(OSError):
                        os.chmod(Path(directory) / name, 0o700)
    attestation_bytes = _bounded_read(private_attestation, "reviewer attestation")
    version_output = (
        (version_result.stdout or "") + "\n" + (version_result.stderr or "")
    ).strip()
    try:
        attestation = strict_loads(attestation_bytes)
    except ValueError as exc:
        raise ReviewBlocked(f"reviewer attestation JSON is invalid: {exc}") from exc
    if not isinstance(attestation, dict):
        raise ReviewBlocked("reviewer attestation must be a JSON object")
    if attestation.get("schema_version") != REVIEWER_ATTESTATION_SCHEMA_VERSION:
        raise ReviewBlocked("reviewer attestation schema mismatch")
    if attestation.get("verification_method") != SIGSTORE_VERIFIER:
        raise ReviewBlocked("reviewer attestation verification method mismatch")
    if attestation.get("verdict") != "PASS":
        raise ReviewBlocked("reviewer attestation verdict is not PASS")
    if _identity_key(attestation.get("reviewer")) != _identity_key(cert_identity):
        raise ReviewBlocked("Sigstore cert identity does not match reviewer")
    if attestation.get("issuer") != oidc_issuer:
        raise ReviewBlocked("Sigstore OIDC issuer does not match attestation")
    if attestation.get("trust_root_id") != trust_root_id:
        raise ReviewBlocked("Sigstore trust-root identity mismatch")
    receipt: dict[str, Any] = {
        "schema_version": SIGNATURE_RECEIPT_SCHEMA_VERSION,
        "status": "VERIFIED",
        "verification_method": SIGSTORE_VERIFIER,
        "reviewer": cert_identity,
        "issuer": oidc_issuer,
        "trust_root_id": trust_root_id,
        "attestation_sha256": hashlib.sha256(attestation_bytes).hexdigest(),
        "attestation_digest": canonical_digest(attestation),
        "signature_sha256": None,
        "bundle_sha256": records[1]["sha256"],
        "verifier_executable": str(private_verifier),
        "verifier_sha256": actual_verifier_sha256,
        "verifier_version": verifier_version,
        "verifier_exit_code": 0,
        "trust_registry_digest": trust_registry_digest,
        "trust_anchor_digest": canonical_digest(anchor),
        "history_anchor_key_sha256": selected_history_key,
        "trust_config_sha256": trust_config_sha256,
        "verifier_closure_digest": canonical_digest(execution_files),
        "execution_files": execution_files,
        "transformed_files": transformed_files,
        "snapshot_digest": canonical_digest(
            [
                {
                    "source": record["source"],
                    "snapshot": record["snapshot"],
                    "sha256": record["sha256"],
                    "size": record["size"],
                }
                for record in records
            ]
        ),
        "verifier_command_digest": canonical_digest(command),
        "verifier_stdout_sha256": hashlib.sha256(
            (completed.stdout or "").encode("utf-8")
        ).hexdigest(),
        "verifier_stderr_sha256": hashlib.sha256(
            (completed.stderr or "").encode("utf-8")
        ).hexdigest(),
        "reviewer_attestation": attestation,
        "verified_at": attestation.get("reviewed_at"),
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt


def _validate_attestation_claims(
    receipt: dict[str, Any],
    *,
    packet: dict[str, object],
    producer: str,
    reviewer: str,
    issuer: str,
    trust_root_id: str,
) -> None:
    if receipt.get("schema_version") != SIGNATURE_RECEIPT_SCHEMA_VERSION:
        raise ReviewBlocked("signature verification receipt schema mismatch")
    if receipt.get("status") != "VERIFIED":
        raise ReviewBlocked("external signature is not verified")
    if receipt.get("verification_method") not in (ED25519_VERIFIER, SIGSTORE_VERIFIER):
        raise ReviewBlocked("unsupported signature verifier")
    if receipt.get("reviewer") != reviewer or receipt.get("issuer") != issuer:
        raise ReviewBlocked("signature verification identity mismatch")
    if receipt.get("trust_root_id") != trust_root_id:
        raise ReviewBlocked("signature verification trust root mismatch")
    if (
        receipt["verification_method"] == ED25519_VERIFIER
        and receipt.get("public_key_fingerprint") != trust_root_id
    ):
        raise ReviewBlocked("signature verification trust root mismatch")
    material = dict(receipt)
    declared = material.pop("receipt_digest", None)
    if canonical_digest(material) != declared:
        raise ReviewBlocked("signature verification receipt digest mismatch")
    attestation = receipt.get("reviewer_attestation")
    if not isinstance(attestation, dict):
        raise ReviewBlocked("reviewer attestation is missing")
    subject = packet["subject"]
    expected = {
        "producer": producer,
        "reviewer": reviewer,
        "verification_method": receipt["verification_method"],
        "verdict": "PASS",
        "trust_anchor_digest": receipt["trust_anchor_digest"],
        "history_anchor_key_sha256": receipt["history_anchor_key_sha256"],
        "subject_digest": packet["subject_digest"],
        "scope_digest": subject["scope_digest"],
        "candidate_digest": subject["candidate_digest"],
        "verification_digest": subject["verification_digest"],
        "ledger_digest": subject["ledger_digest"],
        "evaluator_digest": subject["evaluator_digest"],
        "matrix_digest": subject["matrix"]["matrix_digest"],
        "coverage_digest": subject["coverage"]["coverage_digest"],
        "domains_digest": canonical_digest(subject["domains"]),
        "findings_digest": canonical_digest(subject["findings"]),
        "reviewed_at": subject["reviewed_at"],
    }
    for field, value in expected.items():
        actual = attestation.get(field)
        if field in ("producer", "reviewer"):
            if _identity_key(actual) != _identity_key(value):
                raise ReviewBlocked(f"reviewer attestation mismatch: {field}")
        elif actual != value:
            raise ReviewBlocked(f"reviewer attestation mismatch: {field}")
    if canonical_digest(attestation) != receipt["attestation_digest"]:
        raise ReviewBlocked("reviewer attestation digest mismatch")


def build_review_packet(subject: dict[str, object]) -> dict[str, object]:
    return {
        "subject": subject,
        "subject_digest": canonical_digest(subject),
    }


def _review_base(
    *,
    producer: str,
    reviewer: str,
    packet: dict[str, object],
) -> dict[str, Any]:
    subject = packet["subject"]
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "producer": producer,
        "reviewer": reviewer,
        "verdict": "PASS",
        "state": "INDEPENDENT_REVIEW",
        "subject_digest": packet["subject_digest"],
        "subject": subject,
        "scope_digest": subject["scope_digest"],
        "candidate_digest": subject["candidate_digest"],
        "verification_digest": subject["verification_digest"],
        "ledger_digest": subject["ledger_digest"],
        "evaluator_digest": subject["evaluator_digest"],
        "trust_anchor_digest": subject.get("trust_anchor_digest"),
        "history_anchor_key_sha256": subject.get("history_anchor_key_sha256"),
        "matrix_digest": subject["matrix"]["matrix_digest"],
        "coverage_digest": subject["coverage"]["coverage_digest"],
        "domains_digest": canonical_digest(subject["domains"]),
        "findings_digest": canonical_digest(subject["findings"]),
        "findings": subject["findings"],
        "limitations": subject["limitations"],
        "unverified_claims": subject["unverified_claims"],
        "not_run": subject["not_run"],
        "non_blocking_observations": subject["non_blocking_observations"],
        "open_count": subject["open_count"],
        "residual_risks": subject["residual_risks"],
        "reviewed_at": subject["reviewed_at"],
    }


_BASE_FIELDS = frozenset(
    {
        "schema_version",
        "producer",
        "reviewer",
        "verdict",
        "state",
        "subject_digest",
        "subject",
        "scope_digest",
        "candidate_digest",
        "verification_digest",
        "ledger_digest",
        "evaluator_digest",
        "trust_anchor_digest",
        "history_anchor_key_sha256",
        "matrix_digest",
        "coverage_digest",
        "domains_digest",
        "findings_digest",
        "findings",
        "limitations",
        "unverified_claims",
        "not_run",
        "non_blocking_observations",
        "open_count",
        "residual_risks",
        "reviewed_at",
    }
)


def _recompute_gate(review: dict[str, Any]) -> dict[str, Any]:
    subject = review["subject"]
    base = {field: review[field] for field in _BASE_FIELDS}
    return assess_release_gate(
        findings=subject["findings"],
        review=base,
        domains=subject["domains"],
        coverage=subject["coverage"],
        matrix=subject["matrix"],
        expected_candidate_digest=subject["candidate_digest"],
        expected_scope_digest=subject["scope_digest"],
        expected_verification_digest=subject["verification_digest"],
        require_evidence_binding=True,
    )


def review_packet(
    *,
    producer: str,
    reviewer: str,
    packet: dict[str, object],
    verification_method: str = ED25519_VERIFIER,
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
    runner: VerificationRunner | None = None,
) -> dict[str, object]:
    if _identity_key(producer) == _identity_key(reviewer):
        raise ReviewBlocked("reviewer must be independent from producer")
    if issuer and _identity_key(producer) == _identity_key(issuer):
        raise ReviewBlocked("issuer must be independent from producer")
    subject = packet["subject"]
    if canonical_digest(subject) != packet["subject_digest"]:
        raise ReviewBlocked("review packet digest mismatch")
    anchor = _trust_anchor_or_default(trust_anchor)
    expected_anchor_digest = canonical_digest(anchor)
    if (
        subject.get("trust_anchor_digest") is not None
        and subject.get("trust_anchor_digest") != expected_anchor_digest
    ):
        raise ReviewBlocked("review subject trust anchor mismatch")
    selected_history_key = subject.get("history_anchor_key_sha256")
    if selected_history_key is None and len(anchor["history_anchor_key_sha256"]) == 1:
        selected_history_key = anchor["history_anchor_key_sha256"][0]
    if (
        selected_history_key is not None
        and selected_history_key not in anchor["history_anchor_key_sha256"]
    ):
        raise ReviewBlocked("review subject history anchor key is not frozen")
    validate_evaluator_artifact(
        anchor,
        artifact_bytes=evaluator_artifact_bytes,
        expected_digest=str(subject.get("evaluator_digest")),
    )
    if _identity_key(reviewer) == _identity_key(subject["evaluator_digest"]):
        raise ReviewBlocked("reviewer must be independent from evaluator")
    required = {
        "scope_digest",
        "candidate_digest",
        "verification_digest",
        "ledger_digest",
        "evaluator_digest",
        "findings",
        "coverage",
        "matrix",
        "domains",
        "limitations",
        "unverified_claims",
        "not_run",
        "non_blocking_observations",
        "open_count",
        "residual_risks",
        "reviewed_at",
    }
    missing = sorted(required - set(subject))
    if missing:
        raise ReviewBlocked("review subject missing: " + ", ".join(missing))
    if verification_method == ED25519_VERIFIER:
        if (
            attestation_bytes is None
            or signature_bytes is None
            or public_key_bytes is None
            or not issuer
            or not trust_root_id
        ):
            raise ReviewBlocked("Ed25519 verification material is incomplete")
        receipt = verify_reviewer_attestation(
            attestation_bytes=attestation_bytes,
            signature_bytes=signature_bytes,
            public_key_bytes=public_key_bytes,
            expected_reviewer=reviewer,
            expected_issuer=issuer,
            expected_trust_root_id=trust_root_id,
            trust_registry=trust_registry,
            trust_registry_digest=trust_registry_digest,
            trust_anchor=anchor,
            history_anchor_key_sha256=selected_history_key,
        )
    elif verification_method == SIGSTORE_VERIFIER:
        if (
            not attestation_path
            or not sigstore_bundle
            or not sigstore_verifier
            or not cert_identity
            or not oidc_issuer
        ):
            raise ReviewBlocked("Sigstore verification material is incomplete")
        if _identity_key(cert_identity) != _identity_key(reviewer):
            raise ReviewBlocked("Sigstore cert identity must equal reviewer")
        receipt = verify_sigstore_attestation(
            attestation_path=attestation_path,
            bundle_path=sigstore_bundle,
            verifier_executable=sigstore_verifier,
            cert_identity=cert_identity,
            oidc_issuer=oidc_issuer,
            trust_registry=trust_registry,
            trust_registry_digest=trust_registry_digest,
            trust_anchor=anchor,
            history_anchor_key_sha256=selected_history_key,
            trust_config_path=trust_config_path,
            snapshot_root=snapshot_root,
            runner=runner,
        )
    else:
        raise ReviewBlocked(f"unsupported verification method: {verification_method}")
    _validate_attestation_claims(
        receipt,
        packet=packet,
        producer=producer,
        reviewer=reviewer,
        issuer=receipt["issuer"],
        trust_root_id=receipt["trust_root_id"],
    )
    base = _review_base(producer=producer, reviewer=reviewer, packet=packet)
    base["trust_anchor_digest"] = receipt["trust_anchor_digest"]
    base["history_anchor_key_sha256"] = receipt["history_anchor_key_sha256"]
    gate = _recompute_gate(base)
    if gate["status"] != "PASS" or gate["release_ready"] is not True:
        raise ReviewBlocked("strict risk gate blocked: " + ", ".join(gate["blockers"]))
    result = {**base, "risk_gate": gate, "external_signature": receipt}
    result["review_digest"] = canonical_digest(result)
    return result


def validate_review_receipt(review: dict[str, Any]) -> dict[str, Any]:
    missing = sorted(_BASE_FIELDS - set(review))
    missing.extend(
        field
        for field in ("risk_gate", "external_signature", "review_digest")
        if field not in review
    )
    if missing:
        raise ReviewBlocked("review receipt missing: " + ", ".join(sorted(set(missing))))
    material = dict(review)
    declared = material.pop("review_digest", None)
    if canonical_digest(material) != declared:
        raise ReviewBlocked("review receipt digest mismatch")
    if review["state"] != "INDEPENDENT_REVIEW":
        raise ReviewBlocked("review state is not INDEPENDENT_REVIEW")
    if _identity_key(review["producer"]) == _identity_key(review["reviewer"]):
        raise ReviewBlocked("review is not independent")
    subject = review["subject"]
    if canonical_digest(subject) != review["subject_digest"]:
        raise ReviewBlocked("reviewed subject digest mismatch")
    receipt = review["external_signature"]
    packet = {
        "subject": subject,
        "subject_digest": review["subject_digest"],
    }
    _validate_attestation_claims(
        receipt,
        packet=packet,
        producer=review["producer"],
        reviewer=review["reviewer"],
        issuer=receipt["issuer"],
        trust_root_id=receipt["trust_root_id"],
    )
    recomputed = _recompute_gate(review)
    if recomputed != review["risk_gate"]:
        raise ReviewBlocked("review risk gate is not current or was not recomputed")
    if recomputed["status"] != "PASS" or recomputed["release_ready"] is not True:
        raise ReviewBlocked("strict risk gate is not PASS")
    return review
