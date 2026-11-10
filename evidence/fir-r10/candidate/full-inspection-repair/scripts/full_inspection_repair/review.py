from __future__ import annotations

import base64
import binascii
import hashlib
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .contracts import canonical_digest
from .risk_gate import assess_release_gate
from .strict import strict_loads

REVIEW_SCHEMA_VERSION = 2
REVIEWER_ATTESTATION_SCHEMA_VERSION = 1
SIGNATURE_RECEIPT_SCHEMA_VERSION = 2
ED25519_VERIFIER = "ed25519-detached"
SIGSTORE_VERIFIER = "sigstore-keyless"
VerificationRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


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
) -> dict[str, Any]:
    """Verify exact attestation bytes with a frozen Ed25519 public key."""

    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise ReviewBlocked("cryptography Ed25519 verifier is unavailable") from exc
    key, _serialization = _load_ed25519_public_key(public_key_bytes)
    computed_trust_root = trust_root_id_for_public_key(public_key_bytes)
    if computed_trust_root != expected_trust_root_id:
        raise ReviewBlocked("frozen public key does not match the trust root")
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
        "reviewer_attestation": attestation,
        "verified_at": attestation.get("reviewed_at"),
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt


def _run_sigstore(
    command: list[str], runner: VerificationRunner | None
) -> subprocess.CompletedProcess[str]:
    if runner is not None:
        return runner(command)
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


def verify_sigstore_attestation(
    *,
    attestation_path: str | Path,
    bundle_path: str | Path,
    verifier_executable: str | Path,
    cert_identity: str,
    oidc_issuer: str,
    runner: VerificationRunner | None = None,
) -> dict[str, Any]:
    """Verify a keyless Sigstore bundle with the external sigstore CLI."""

    attestation_file = Path(attestation_path)
    bundle = Path(bundle_path)
    verifier = Path(verifier_executable)
    if not attestation_file.is_file():
        raise ReviewBlocked("reviewer attestation file is missing")
    if not bundle.is_file():
        raise ReviewBlocked("Sigstore bundle is missing")
    if not verifier.is_file():
        raise ReviewBlocked("Sigstore verifier executable is missing")
    if not cert_identity or not oidc_issuer:
        raise ReviewBlocked("Sigstore cert identity and OIDC issuer are required")
    command = [
        str(verifier),
        "verify",
        "identity",
        "--offline",
        "--bundle",
        str(bundle),
        "--cert-identity",
        cert_identity,
        "--cert-oidc-issuer",
        oidc_issuer,
        str(attestation_file),
    ]
    completed = _run_sigstore(command, runner)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise ReviewBlocked(
            f"Sigstore verification failed with rc={completed.returncode}: {detail}"
        )
    attestation_bytes = attestation_file.read_bytes()
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
    trust_root_id = sigstore_trust_root_id(cert_identity, oidc_issuer)
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
        "bundle_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
        "verifier_executable": str(verifier),
        "verifier_exit_code": 0,
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
    runner: VerificationRunner | None = None,
) -> dict[str, object]:
    if _identity_key(producer) == _identity_key(reviewer):
        raise ReviewBlocked("reviewer must be independent from producer")
    if issuer and _identity_key(producer) == _identity_key(issuer):
        raise ReviewBlocked("issuer must be independent from producer")
    subject = packet["subject"]
    if canonical_digest(subject) != packet["subject_digest"]:
        raise ReviewBlocked("review packet digest mismatch")
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
            runner=runner,
        )
        actual_bytes = Path(attestation_path).read_bytes()
        if attestation_bytes is not None and actual_bytes != attestation_bytes:
            raise ReviewBlocked("Sigstore attestation bytes changed during review")
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
