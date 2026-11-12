from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from .contracts import canonical_digest
from .review import (
    ED25519_VERIFIER,
    SIGSTORE_VERIFIER,
    ReviewBlocked,
    VerificationRunner,
    load_trust_anchor,
    validate_review_receipt,
    verify_reviewer_attestation,
    verify_sigstore_attestation,
)
from .state_machine import advance
from .strict import fsync_directory, strict_loads, write_all

MAX_RELEASE_ARTIFACT_BYTES = 64 * 1024 * 1024
RELEASE_HISTORY_LOCK_SECONDS = 60.0
RELEASE_LIFECYCLE_EVENTS = (
    "FREEZE",
    "FINAL_REVIEW",
    "CLAIM_INTENT",
    "CLAIM_COMMIT",
    "INSTALL",
    "POST_INSTALL_REPLAY",
)


class ReleaseBlocked(ValueError):
    """Raised when release evidence is incomplete or inconsistent."""


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


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
    current = path.absolute()
    while True:
        if _is_link(current):
            raise ReleaseBlocked(f"{label} path is a symbolic link or reparse point")
        if current == current.parent:
            return
        current = current.parent


def _read_bounded(path: Path, label: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ReleaseBlocked(f"{label} cannot be read: {exc}") from exc
    if size > MAX_RELEASE_ARTIFACT_BYTES:
        raise ReleaseBlocked(f"{label} exceeds size policy")
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_RELEASE_ARTIFACT_BYTES + 1)
    except OSError as exc:
        raise ReleaseBlocked(f"{label} cannot be read: {exc}") from exc
    if len(data) > MAX_RELEASE_ARTIFACT_BYTES:
        raise ReleaseBlocked(f"{label} exceeds size policy")
    return data


def _anchor_path(history_path: Path) -> Path:
    return history_path.with_name(f"{history_path.name}.anchor.json")


@contextmanager
def _history_lock(path: Path):
    lock_path = path.with_name(f"{path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_link_chain(lock_path, "release history lock")
    deadline = time.monotonic() + RELEASE_HISTORY_LOCK_SECONDS
    fd: int | None = None
    while fd is None:
        try:
            fd = os.open(
                lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except (FileExistsError, PermissionError) as exc:
            if time.monotonic() >= deadline:
                raise ReleaseBlocked("release history lock timeout") from exc
            time.sleep(0.02)
    try:
        write_all(fd, f"{os.getpid()}\n".encode("ascii"))
        os.fsync(fd)
        yield
    finally:
        if fd is not None:
            os.close(fd)
        with suppress(FileNotFoundError):
            lock_path.unlink()


def _write_anchor(
    history_path: Path,
    *,
    history_bytes: bytes,
    records: list[dict[str, Any]],
    anchor_path: Path | None,
    anchor_key: bytes,
) -> dict[str, Any]:
    path = anchor_path or _anchor_path(history_path)
    anchor: dict[str, Any] = {
        "schema_version": 1,
        "history_name": history_path.name,
        "anchor_key_sha256": hashlib.sha256(anchor_key).hexdigest(),
        "record_count": len(records),
        "head_digest": records[-1]["record_digest"] if records else None,
        "history_sha256": hashlib.sha256(history_bytes).hexdigest(),
    }
    anchor["mac"] = hmac.new(
        anchor_key,
        canonical_digest(anchor).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    anchor["anchor_digest"] = canonical_digest(anchor)
    payload = (
        json.dumps(anchor, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        .encode("utf-8")
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_link_chain(path, "release history anchor")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if _is_link(temporary):
        raise ReleaseBlocked("release history anchor temporary path is a link")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()
    return anchor


def _verify_review_bundle(
    review: dict[str, Any],
    *,
    verification_method: str,
    attestation_bytes: bytes | None,
    attestation_path: str | Path | None,
    signature_bytes: bytes | None,
    public_key_bytes: bytes | None,
    issuer: str | None,
    trust_root_id: str | None,
    sigstore_bundle: str | Path | None,
    sigstore_verifier: str | Path | None,
    cert_identity: str | None,
    oidc_issuer: str | None,
    trust_registry: dict[str, Any] | None,
    trust_registry_digest: str | None,
    trust_anchor: dict[str, Any] | None,
    history_anchor_key_sha256: str | None,
    trust_config_path: str | Path | None,
    snapshot_root: str | Path | None,
    runner: VerificationRunner | None,
) -> dict[str, Any]:
    try:
        validate_review_receipt(review)
    except ReviewBlocked as exc:
        raise ReleaseBlocked(str(exc)) from exc
    if verification_method == ED25519_VERIFIER:
        if (
            attestation_bytes is None
            or signature_bytes is None
            or public_key_bytes is None
            or not issuer
            or not trust_root_id
        ):
            raise ReleaseBlocked("Ed25519 verification material is incomplete")
        verified = verify_reviewer_attestation(
            attestation_bytes=attestation_bytes,
            signature_bytes=signature_bytes,
            public_key_bytes=public_key_bytes,
            expected_reviewer=review["reviewer"],
            expected_issuer=issuer,
            expected_trust_root_id=trust_root_id,
            trust_registry=trust_registry,
            trust_registry_digest=trust_registry_digest,
            trust_anchor=trust_anchor,
            history_anchor_key_sha256=history_anchor_key_sha256,
        )
    elif verification_method == SIGSTORE_VERIFIER:
        if (
            not attestation_path
            or not sigstore_bundle
            or not sigstore_verifier
            or not cert_identity
            or not oidc_issuer
        ):
            raise ReleaseBlocked("Sigstore verification material is incomplete")
        verified = verify_sigstore_attestation(
            attestation_path=attestation_path,
            bundle_path=sigstore_bundle,
            verifier_executable=sigstore_verifier,
            cert_identity=cert_identity,
            oidc_issuer=oidc_issuer,
            trust_registry=trust_registry,
            trust_registry_digest=trust_registry_digest,
            trust_anchor=trust_anchor,
            history_anchor_key_sha256=history_anchor_key_sha256,
            trust_config_path=trust_config_path,
            snapshot_root=snapshot_root,
            runner=runner,
        )
        if (
            attestation_bytes is not None
            and hashlib.sha256(attestation_bytes).hexdigest()
            != verified["attestation_sha256"]
        ):
            raise ReleaseBlocked("Sigstore attestation digest changed during verification")
    else:
        raise ReleaseBlocked(f"unsupported verification method: {verification_method}")
    stored = review["external_signature"]
    fields = [
        "reviewer",
        "issuer",
        "trust_root_id",
        "verification_method",
        "attestation_sha256",
        "attestation_digest",
        "signature_sha256",
        "receipt_digest",
        "trust_registry_digest",
        "trust_anchor_digest",
    ]
    if verification_method == ED25519_VERIFIER:
        fields.append("public_key_fingerprint")
    else:
        fields.extend(
            [
                "bundle_sha256",
                "verifier_executable",
                "verifier_exit_code",
                "verifier_command_digest",
                "verifier_sha256",
                "verifier_version",
                "trust_config_sha256",
                "verifier_closure_digest",
            ]
        )
    for field in fields:
        if verified.get(field) != stored.get(field):
            raise ReleaseBlocked(f"signature verification receipt mismatch: {field}")
    return stored


def build_release_claim(
    review: dict[str, object],
    *,
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
    anchor = load_trust_anchor() if trust_anchor is None else trust_anchor
    if (
        evaluator_artifact_bytes is not None
        and hashlib.sha256(evaluator_artifact_bytes).hexdigest()
        != review.get("evaluator_digest")
    ):
        raise ReleaseBlocked("evaluator artifact does not match the review")
    receipt = _verify_review_bundle(
        review,
        verification_method=verification_method,
        attestation_bytes=attestation_bytes,
        attestation_path=attestation_path,
        signature_bytes=signature_bytes,
        public_key_bytes=public_key_bytes,
        issuer=issuer,
        trust_root_id=trust_root_id,
        sigstore_bundle=sigstore_bundle,
        sigstore_verifier=sigstore_verifier,
        cert_identity=cert_identity,
        oidc_issuer=oidc_issuer,
        trust_registry=trust_registry,
        trust_registry_digest=trust_registry_digest,
        trust_anchor=anchor,
        history_anchor_key_sha256=review.get("history_anchor_key_sha256"),
        trust_config_path=trust_config_path,
        snapshot_root=snapshot_root,
        runner=runner,
    )
    if review.get("state") != "INDEPENDENT_REVIEW":
        raise ReleaseBlocked("review is not at the independent-review boundary")
    claimed_state = advance("INDEPENDENT_REVIEW", "claim")
    claim: dict[str, object] = {
        "schema_version": 2,
        "status": "RELEASE_READY",
        "state": claimed_state,
        "subject_digest": review["subject_digest"],
        "scope_digest": review["scope_digest"],
        "candidate_digest": review["candidate_digest"],
        "verification_digest": review["verification_digest"],
        "ledger_digest": review["ledger_digest"],
        "evaluator_digest": review["evaluator_digest"],
        "matrix_digest": review["matrix_digest"],
        "coverage_digest": review["coverage_digest"],
        "domains_digest": review["domains_digest"],
        "findings_digest": review["findings_digest"],
        "review_digest": review["review_digest"],
        "producer": review["producer"],
        "reviewer": review["reviewer"],
        "issuer": receipt["issuer"],
        "trust_root_id": receipt["trust_root_id"],
        "verification_method": receipt["verification_method"],
        "attestation_digest": receipt["attestation_digest"],
        "attestation_sha256": receipt["attestation_sha256"],
        "signature_sha256": receipt["signature_sha256"],
        "signature_verification_receipt_digest": receipt["receipt_digest"],
        "trust_registry_digest": receipt["trust_registry_digest"],
        "trust_anchor_digest": receipt["trust_anchor_digest"],
        "history_anchor_key_sha256": receipt["history_anchor_key_sha256"],
        "risk_gate_digest": review["risk_gate"]["gate_digest"],
        "issued_at": review["reviewed_at"],
        "finding_count": len(review["findings"]),
        "open_count": 0,
    }
    if receipt["verification_method"] == SIGSTORE_VERIFIER:
        claim["bundle_sha256"] = receipt["bundle_sha256"]
        claim["verifier_command_digest"] = receipt["verifier_command_digest"]
        claim["verifier_sha256"] = receipt["verifier_sha256"]
        claim["verifier_version"] = receipt["verifier_version"]
        claim["trust_config_sha256"] = receipt["trust_config_sha256"]
        claim["verifier_closure_digest"] = receipt["verifier_closure_digest"]
    claim["claim_digest"] = canonical_digest(claim)
    return claim


def validate_release_claim(
    claim: dict[str, Any],
    *,
    expected_candidate_digest: str | None = None,
    expected_review_digest: str | None = None,
    expected_trust_root_id: str | None = None,
    expected_trust_anchor_digest: str | None = None,
) -> dict[str, Any]:
    required = {
        "schema_version",
        "status",
        "state",
        "subject_digest",
        "scope_digest",
        "candidate_digest",
        "verification_digest",
        "ledger_digest",
        "evaluator_digest",
        "matrix_digest",
        "coverage_digest",
        "domains_digest",
        "findings_digest",
        "review_digest",
        "producer",
        "reviewer",
        "issuer",
        "trust_root_id",
        "verification_method",
        "attestation_digest",
        "attestation_sha256",
        "signature_sha256",
        "signature_verification_receipt_digest",
        "trust_registry_digest",
        "trust_anchor_digest",
        "history_anchor_key_sha256",
        "risk_gate_digest",
        "issued_at",
        "finding_count",
        "open_count",
        "claim_digest",
    }
    missing = sorted(required - set(claim))
    if missing:
        raise ReleaseBlocked("release claim missing: " + ", ".join(missing))
    if claim["schema_version"] != 2:
        raise ReleaseBlocked("release claim schema mismatch")
    if claim["status"] != "RELEASE_READY":
        raise ReleaseBlocked("release claim is not RELEASE_READY")
    if claim["state"] != "RELEASE_CLAIMED":
        raise ReleaseBlocked("release state machine is not claimed")
    if claim["verification_method"] not in (ED25519_VERIFIER, SIGSTORE_VERIFIER):
        raise ReleaseBlocked("release claim verification method is unsupported")
    if claim["verification_method"] == SIGSTORE_VERIFIER:
        for field in ("bundle_sha256", "verifier_command_digest"):
            if not claim.get(field):
                raise ReleaseBlocked(f"release claim missing: {field}")
        for field in (
            "verifier_sha256",
            "verifier_version",
            "trust_config_sha256",
            "verifier_closure_digest",
        ):
            if not claim.get(field):
                raise ReleaseBlocked(f"release claim missing: {field}")
    if claim["open_count"] != 0:
        raise ReleaseBlocked("release claim has open risk")
    material = dict(claim)
    declared = material.pop("claim_digest", None)
    if canonical_digest(material) != declared:
        raise ReleaseBlocked("release claim digest mismatch")
    if expected_candidate_digest is not None and (
        claim["candidate_digest"] != expected_candidate_digest
    ):
        raise ReleaseBlocked("release claim is for a foreign candidate")
    if expected_review_digest is not None and (
        claim["review_digest"] != expected_review_digest
    ):
        raise ReleaseBlocked("release claim is stale for the supplied review")
    if expected_trust_root_id is not None and (
        claim["trust_root_id"] != expected_trust_root_id
    ):
        raise ReleaseBlocked("release claim trust root mismatch")
    if expected_trust_anchor_digest is not None and (
        claim["trust_anchor_digest"] != expected_trust_anchor_digest
    ):
        raise ReleaseBlocked("release claim trust anchor mismatch")
    return claim


def validate_claim_for_install(
    claim: dict[str, Any],
    review: dict[str, Any],
    *,
    verification_method: str,
    attestation_bytes: bytes | None,
    attestation_path: str | Path | None,
    signature_bytes: bytes | None,
    public_key_bytes: bytes | None,
    issuer: str | None,
    candidate_digest: str,
    trust_root_id: str | None,
    sigstore_bundle: str | Path | None,
    sigstore_verifier: str | Path | None,
    cert_identity: str | None,
    oidc_issuer: str | None,
    trust_registry: dict[str, Any] | None,
    trust_registry_digest: str | None,
    trust_anchor: dict[str, Any] | None = None,
    trust_config_path: str | Path | None = None,
    snapshot_root: str | Path | None = None,
    runner: VerificationRunner | None = None,
) -> dict[str, Any]:
    anchor = load_trust_anchor() if trust_anchor is None else trust_anchor
    validate_review_receipt(review)
    validate_release_claim(
        claim,
        expected_candidate_digest=candidate_digest,
        expected_review_digest=review["review_digest"],
        expected_trust_root_id=trust_root_id,
        expected_trust_anchor_digest=canonical_digest(anchor),
    )
    stored = _verify_review_bundle(
        review,
        verification_method=verification_method,
        attestation_bytes=attestation_bytes,
        attestation_path=attestation_path,
        signature_bytes=signature_bytes,
        public_key_bytes=public_key_bytes,
        issuer=issuer,
        trust_root_id=trust_root_id,
        sigstore_bundle=sigstore_bundle,
        sigstore_verifier=sigstore_verifier,
        cert_identity=cert_identity,
        oidc_issuer=oidc_issuer,
        trust_registry=trust_registry,
        trust_registry_digest=trust_registry_digest,
        trust_anchor=anchor,
        history_anchor_key_sha256=claim["history_anchor_key_sha256"],
        trust_config_path=trust_config_path,
        snapshot_root=snapshot_root,
        runner=runner,
    )
    if trust_root_id is not None and stored["trust_root_id"] != trust_root_id:
        raise ReleaseBlocked("review attestation trust root mismatch")
    claim_bindings = {
        "reviewer": "reviewer",
        "issuer": "issuer",
        "trust_root_id": "trust_root_id",
        "verification_method": "verification_method",
        "attestation_digest": "attestation_digest",
        "attestation_sha256": "attestation_sha256",
        "signature_sha256": "signature_sha256",
        "receipt_digest": "signature_verification_receipt_digest",
        "trust_registry_digest": "trust_registry_digest",
        "trust_anchor_digest": "trust_anchor_digest",
        "history_anchor_key_sha256": "history_anchor_key_sha256",
    }
    for stored_field, claim_field in claim_bindings.items():
        if stored.get(stored_field) != claim.get(claim_field):
            raise ReleaseBlocked(f"claim signature receipt mismatch: {stored_field}")
    if verification_method == SIGSTORE_VERIFIER:
        if stored["bundle_sha256"] != claim["bundle_sha256"]:
            raise ReleaseBlocked("claim Sigstore bundle mismatch")
        if stored["verifier_command_digest"] != claim["verifier_command_digest"]:
            raise ReleaseBlocked("claim Sigstore verifier command mismatch")
        if stored["verifier_sha256"] != claim["verifier_sha256"]:
            raise ReleaseBlocked("claim Sigstore verifier content mismatch")
        if stored["verifier_version"] != claim["verifier_version"]:
            raise ReleaseBlocked("claim Sigstore verifier version mismatch")
        if stored["trust_config_sha256"] != claim["trust_config_sha256"]:
            raise ReleaseBlocked("claim Sigstore trust configuration mismatch")
        if stored["verifier_closure_digest"] != claim["verifier_closure_digest"]:
            raise ReleaseBlocked("claim Sigstore verifier closure mismatch")
    if review["candidate_digest"] != candidate_digest:
        raise ReleaseBlocked("review candidate digest mismatch")
    return claim


def replay_release_history(
    history_path: str | Path,
    *,
    anchor_path: str | Path | None = None,
    expected_anchor_digest: str | None = None,
    expected_key_sha256: str | None = None,
    anchor_key: bytes | None = None,
) -> list[dict[str, Any]]:
    path = Path(history_path)
    anchor = Path(anchor_path) if anchor_path is not None else _anchor_path(path)
    _assert_no_link_chain(path, "release history")
    _assert_no_link_chain(anchor, "release history anchor")
    if not path.exists():
        if anchor.exists():
            raise ReleaseBlocked("release history is missing but its high-water exists")
        return []
    if not anchor.is_file():
        raise ReleaseBlocked("release history high-water is missing")
    if anchor_key is None or len(anchor_key) < 32:
        raise ReleaseBlocked("release history anchor key is required")
    history_bytes = _read_bounded(path, "release history")
    anchor_bytes = _read_bounded(anchor, "release history anchor")
    try:
        anchor_value = strict_loads(anchor_bytes)
    except ValueError as exc:
        raise ReleaseBlocked("release history high-water is invalid") from exc
    if not isinstance(anchor_value, dict):
        raise ReleaseBlocked("release history high-water is not an object")
    anchor_material = dict(anchor_value)
    anchor_material.pop("anchor_digest", None)
    declared_mac = anchor_material.pop("mac", None)
    expected_mac = hmac.new(
        anchor_key,
        canonical_digest(anchor_material).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(str(declared_mac), expected_mac):
        raise ReleaseBlocked("release history high-water authentication failed")
    declared_anchor_digest = anchor_value.get("anchor_digest")
    if declared_anchor_digest != canonical_digest(
        {**anchor_material, "mac": declared_mac}
    ):
        raise ReleaseBlocked("release history high-water digest mismatch")
    if expected_anchor_digest is not None and (
        declared_anchor_digest != expected_anchor_digest
    ):
        raise ReleaseBlocked("release history high-water is foreign")
    actual_key_sha256 = hashlib.sha256(anchor_key).hexdigest()
    if anchor_value.get("anchor_key_sha256") != actual_key_sha256:
        raise ReleaseBlocked("release history anchor key identity mismatch")
    if expected_key_sha256 is not None and (
        actual_key_sha256 != expected_key_sha256
    ):
        raise ReleaseBlocked("release history anchor key is not externally frozen")
    records: list[dict[str, Any]] = []
    previous: str | None = None
    for number, line in enumerate(history_bytes.splitlines(), start=1):
        if not line.strip():
            raise ReleaseBlocked(f"release history has a blank record at line {number}")
        try:
            record = strict_loads(line)
        except ValueError as exc:
            raise ReleaseBlocked(f"release history is invalid at line {number}") from exc
        if record.get("sequence") != number:
            raise ReleaseBlocked(f"release history sequence mismatch at line {number}")
        if record.get("previous_record_digest") != previous:
            raise ReleaseBlocked(f"release history chain mismatch at line {number}")
        material = dict(record)
        declared = material.pop("record_digest", None)
        if canonical_digest(material) != declared:
            raise ReleaseBlocked(f"release history digest mismatch at line {number}")
        previous = str(declared)
        records.append(record)
    if anchor_value.get("history_name") != path.name:
        raise ReleaseBlocked("release history high-water name mismatch")
    if anchor_value.get("record_count") != len(records):
        raise ReleaseBlocked("release history high-water record count mismatch")
    if anchor_value.get("head_digest") != previous:
        raise ReleaseBlocked("release history high-water head mismatch")
    if anchor_value.get("history_sha256") != hashlib.sha256(history_bytes).hexdigest():
        raise ReleaseBlocked("release history high-water digest mismatch")
    return records


def release_id_for(scope_id: str, candidate_digest: str) -> str:
    if not scope_id or not _valid_digest(candidate_digest):
        raise ReleaseBlocked("release identity inputs are incomplete")
    return f"{scope_id}:{candidate_digest}"


def validate_release_lifecycle(
    records: list[dict[str, Any]],
    *,
    release_id: str,
    scope_id: str,
    candidate_digest: str,
    required_through: str | None = None,
) -> list[dict[str, Any]]:
    """Validate one release lifecycle inside an append-only global history."""

    if required_through is not None and required_through not in RELEASE_LIFECYCLE_EVENTS:
        raise ReleaseBlocked("unknown required release lifecycle event")
    selected = [item for item in records if item.get("release_id") == release_id]
    if not selected:
        raise ReleaseBlocked("release lifecycle is missing")
    expected: list[str] = []
    claim_aborted = False
    for record in selected:
        if record.get("scope_id") != scope_id:
            raise ReleaseBlocked("release lifecycle contains a foreign scope")
        if record.get("candidate_digest") != candidate_digest:
            raise ReleaseBlocked("release lifecycle contains a foreign candidate")
        event = str(record.get("event"))
        if claim_aborted:
            raise ReleaseBlocked("release lifecycle continues after claim abort")
        if event == "CLAIM_ABORT":
            if expected[-1:] != ["CLAIM_INTENT"]:
                raise ReleaseBlocked("claim abort is not preceded by claim intent")
            expected.append(event)
            claim_aborted = True
            continue
        if event not in RELEASE_LIFECYCLE_EVENTS:
            raise ReleaseBlocked(f"unknown release lifecycle event: {event}")
        if expected.count(event) or (
            event == "CLAIM_INTENT" and "CLAIM_COMMIT" in expected
        ):
            raise ReleaseBlocked("release lifecycle event is duplicated")
        if expected and RELEASE_LIFECYCLE_EVENTS.index(event) <= (
            RELEASE_LIFECYCLE_EVENTS.index(expected[-1])
            if expected[-1] in RELEASE_LIFECYCLE_EVENTS
            else len(RELEASE_LIFECYCLE_EVENTS)
        ):
            raise ReleaseBlocked("release lifecycle events are out of order")
        expected.append(event)
    if claim_aborted and expected[-1] != "CLAIM_ABORT":
        raise ReleaseBlocked("release lifecycle abort state is invalid")
    if required_through is not None:
        index = RELEASE_LIFECYCLE_EVENTS.index(required_through)
        required_prefix = list(RELEASE_LIFECYCLE_EVENTS[: index + 1])
        if claim_aborted or expected[: len(required_prefix)] != required_prefix:
            raise ReleaseBlocked(
                f"release lifecycle has not reached {required_through}"
            )
        if expected != required_prefix:
            raise ReleaseBlocked(
                f"release lifecycle contains events after {required_through}"
            )
    return selected


def latest_release_record(
    records: list[dict[str, Any]],
    *,
    release_id: str,
    event: str,
) -> dict[str, Any]:
    matches = [
        item
        for item in records
        if item.get("release_id") == release_id and item.get("event") == event
    ]
    if len(matches) != 1:
        raise ReleaseBlocked(f"release lifecycle requires exactly one {event} record")
    return matches[0]


def append_release_record(
    history_path: str | Path,
    record: dict[str, Any],
    *,
    anchor_path: str | Path | None = None,
    expected_key_sha256: str | None = None,
    anchor_key: bytes | None = None,
) -> dict[str, Any]:
    if not record.get("event") or not record.get("status"):
        raise ReleaseBlocked("release history record requires event and status")
    path = Path(history_path)
    anchor = Path(anchor_path) if anchor_path is not None else _anchor_path(path)
    if anchor_key is None or len(anchor_key) < 32:
        raise ReleaseBlocked("release history anchor key is required")
    path.parent.mkdir(parents=True, exist_ok=True)
    with _history_lock(path):
        records = replay_release_history(
            path,
            anchor_path=anchor,
            expected_key_sha256=expected_key_sha256,
            anchor_key=anchor_key,
        )
        item = dict(record)
        item.pop("sequence", None)
        item.pop("previous_record_digest", None)
        item.pop("record_digest", None)
        item["sequence"] = len(records) + 1
        item["previous_record_digest"] = (
            records[-1]["record_digest"] if records else None
        )
        item["record_digest"] = canonical_digest(item)
        payload = json.dumps(
            item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        created = not path.exists()
        _assert_no_link_chain(path, "release history")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        if created:
            fsync_directory(path.parent)
        records.append(item)
        history_bytes = _read_bounded(path, "release history")
        _write_anchor(
            path,
            history_bytes=history_bytes,
            records=records,
            anchor_path=anchor,
            anchor_key=anchor_key,
        )
        return item
