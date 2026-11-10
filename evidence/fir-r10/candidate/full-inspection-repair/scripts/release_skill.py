#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.package import (
    InstallBlocked,
    PackageError,
    build_package_manifest,
    install_package,
    verify_package_manifest,
)
from full_inspection_repair.release import (
    ReleaseBlocked,
    append_release_record,
    build_release_claim,
)
from full_inspection_repair.review import (
    ReviewBlocked,
    build_review_packet,
    review_packet,
)
from full_inspection_repair.strict import StrictJSONError, read_json


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _require_record_digest(value: dict[str, object], field: str, label: str) -> str:
    declared = value.get(field)
    material = dict(value)
    material.pop(field, None)
    if declared != canonical_digest(material):
        raise ReleaseBlocked(f"{label} digest mismatch")
    return str(declared)


def _validate_evidence(
    verification: dict[str, object],
    ledger: dict[str, object],
) -> None:
    if verification.get("status") != "PASS" or verification.get("failure_count") != 0:
        raise ReleaseBlocked("verification is not PASS")
    _require_record_digest(verification, "verification_digest", "verification")
    if ledger.get("open_count") != 0 or ledger.get("residual_risks"):
        raise ReleaseBlocked("ledger does not close all risk")
    for field in ("missing_sources", "unexpected_sources", "unresolved_ids"):
        if ledger.get(field):
            raise ReleaseBlocked(f"ledger field is not empty: {field}")
    _require_record_digest(ledger, "ledger_digest", "ledger")


def _verification_material(args) -> dict[str, object]:
    attestation_path = Path(args.attestation).resolve()
    attestation_bytes = attestation_path.read_bytes()
    if args.verification_method == "ed25519-detached":
        if not args.signature or not args.public_key or not args.issuer or not args.trust_root:
            raise ReleaseBlocked(
                "Ed25519 requires --signature, --public-key, --issuer and --trust-root"
            )
        return {
            "verification_method": args.verification_method,
            "attestation_bytes": attestation_bytes,
            "attestation_path": attestation_path,
            "signature_bytes": Path(args.signature).read_bytes(),
            "public_key_bytes": Path(args.public_key).read_bytes(),
            "issuer": args.issuer,
            "trust_root_id": args.trust_root,
        }
    if args.verification_method == "sigstore-keyless":
        if not args.sigstore_bundle or not args.sigstore_verifier:
            raise ReleaseBlocked(
                "Sigstore requires --sigstore-bundle and --sigstore-verifier"
            )
        if not args.cert_identity or not args.oidc_issuer:
            raise ReleaseBlocked(
                "Sigstore requires --cert-identity and --oidc-issuer"
            )
        return {
            "verification_method": args.verification_method,
            "attestation_bytes": attestation_bytes,
            "attestation_path": attestation_path,
            "sigstore_bundle": Path(args.sigstore_bundle).resolve(),
            "sigstore_verifier": Path(args.sigstore_verifier).resolve(),
            "cert_identity": args.cert_identity,
            "oidc_issuer": args.oidc_issuer,
        }
    raise ReleaseBlocked(f"unsupported verification method: {args.verification_method}")


def _package(args) -> int:
    output = Path(args.output).resolve()
    manifest = build_package_manifest(args.source)
    _write_json(output / "package-manifest.json", manifest)
    return 0


def _review(args) -> int:
    output = Path(args.output).resolve()
    manifest = read_json(Path(args.manifest))
    verification = read_json(Path(args.verification))
    ledger = read_json(Path(args.ledger))
    evidence = read_json(Path(args.review_evidence))
    verification_material = _verification_material(args)
    verify_package_manifest(args.source, manifest)
    _validate_evidence(verification, ledger)
    finding_rows = evidence["findings"]
    ledger_rows = ledger["items"]
    projection = lambda rows: [
        (str(row.get("finding_id", row.get("risk_id"))), row.get("status"))
        for row in rows
    ]
    if projection(finding_rows) != projection(ledger_rows):
        raise ReleaseBlocked("risk-gate findings do not match the issue ledger")
    if evidence["matrix"].get("verification_digest") != verification["verification_digest"]:
        raise ReleaseBlocked("verification matrix is not bound to verification")
    subject = {
        "scope_digest": ledger["scope_digest"],
        "candidate_digest": manifest["tree_digest"],
        "verification_digest": verification["verification_digest"],
        "ledger_digest": ledger["ledger_digest"],
        "evaluator_digest": args.evaluator,
        "findings": finding_rows,
        "coverage": evidence["coverage"],
        "matrix": evidence["matrix"],
        "domains": evidence["domains"],
        "limitations": evidence["limitations"],
        "unverified_claims": evidence["unverified_claims"],
        "not_run": evidence["not_run"],
        "non_blocking_observations": evidence["non_blocking_observations"],
        "risk_gate": evidence.get("risk_gate"),
        "open_count": ledger["open_count"],
        "residual_risks": ledger["residual_risks"],
        "reviewed_at": evidence["reviewed_at"],
    }
    packet = build_review_packet(subject)
    review = review_packet(
        producer=args.producer,
        reviewer=args.reviewer,
        packet=packet,
        **verification_material,
    )
    _write_json(output / "review-packet.json", packet)
    _write_json(output / "independent-review.json", review)
    return 0


def _claim(args) -> int:
    output = Path(args.output).resolve()
    verification_material = _verification_material(args)
    claim = build_release_claim(
        read_json(Path(args.review)),
        **verification_material,
    )
    _write_json(output / "release-claim.json", claim)
    append_release_record(
        output / "release-history.jsonl",
        {
            "event": "CLAIM",
            "status": claim["status"],
            "claim_digest": claim["claim_digest"],
            "candidate_digest": claim["candidate_digest"],
            "review_digest": claim["review_digest"],
            "trust_root_id": claim["trust_root_id"],
        },
    )
    return 0


def _install(args) -> int:
    output = Path(args.output).resolve()
    manifest = read_json(Path(args.manifest))
    claim = read_json(Path(args.claim))
    review = read_json(Path(args.review))
    verification_material = _verification_material(args)
    receipt = install_package(
        args.source,
        args.target,
        manifest,
        claim=claim,
        review=review,
        **verification_material,
        rollback_root=args.rollback,
    )
    history_record = append_release_record(
        output / "release-history.jsonl",
        {
            "event": "INSTALL",
            "status": receipt["status"],
            "claim_digest": receipt["claim_digest"],
            "review_digest": receipt["review_digest"],
            "candidate_digest": receipt["candidate_digest"],
            "target": receipt["target"],
            "rollback_root": receipt["rollback_root"],
        },
    )
    receipt["release_history_sequence"] = history_record["sequence"]
    receipt["release_history_record_digest"] = history_record["record_digest"]
    receipt.pop("receipt_digest", None)
    receipt["receipt_digest"] = canonical_digest(receipt)
    _write_json(output / "install-receipt.json", receipt)
    return 0


def _add_verification_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--attestation", required=True)
    parser.add_argument(
        "--verification-method",
        choices=("sigstore-keyless", "ed25519-detached"),
        default="sigstore-keyless",
    )
    parser.add_argument("--signature")
    parser.add_argument("--public-key")
    parser.add_argument("--issuer")
    parser.add_argument("--trust-root")
    parser.add_argument("--sigstore-bundle")
    parser.add_argument("--sigstore-verifier")
    parser.add_argument("--cert-identity")
    parser.add_argument("--oidc-issuer")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="release-skill")
    subparsers = parser.add_subparsers(dest="command", required=True)

    package = subparsers.add_parser("package")
    package.add_argument("--source", required=True)
    package.add_argument("--output", required=True)
    package.set_defaults(handler=_package)

    review = subparsers.add_parser("review")
    review.add_argument("--manifest", required=True)
    review.add_argument("--source", required=True)
    review.add_argument("--verification", required=True)
    review.add_argument("--ledger", required=True)
    review.add_argument("--review-evidence", required=True)
    _add_verification_arguments(review)
    review.add_argument("--evaluator", required=True)
    review.add_argument("--producer", required=True)
    review.add_argument("--reviewer", required=True)
    review.add_argument("--output", required=True)
    review.set_defaults(handler=_review)

    claim = subparsers.add_parser("claim")
    claim.add_argument("--review", required=True)
    _add_verification_arguments(claim)
    claim.add_argument("--output", required=True)
    claim.set_defaults(handler=_claim)

    install = subparsers.add_parser("install")
    install.add_argument("--source", required=True)
    install.add_argument("--target", required=True)
    install.add_argument("--manifest", required=True)
    install.add_argument("--claim", required=True)
    install.add_argument("--review", required=True)
    _add_verification_arguments(install)
    install.add_argument("--output", required=True)
    install.add_argument("--rollback")
    install.set_defaults(handler=_install)
    return parser


def _failure_code(exc: Exception) -> str:
    if isinstance(exc, StrictJSONError):
        return "EVIDENCE_PARSE"
    if isinstance(exc, InstallBlocked):
        return "INSTALL_BLOCKED"
    if isinstance(exc, PackageError):
        return "CANDIDATE_MANIFEST"
    if isinstance(exc, ReviewBlocked):
        return "REVIEW_RECEIPT"
    if isinstance(exc, ReleaseBlocked):
        return "RELEASE_GATE"
    return "UNEXPECTED_EXCEPTION"


def _blocked_receipt(command: str, exc: Exception) -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema_version": 1,
        "status": "BLOCKED_VERIFICATION",
        "release_ready": False,
        "state": "BLOCKED_VERIFICATION",
        "command": command,
        "failure_code": _failure_code(exc),
        "failures": [
            {
                "type": type(exc).__name__,
                "message": str(exc),
            }
        ],
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt


def run() -> int:
    args = _parser().parse_args()
    try:
        return args.handler(args)
    except Exception as exc:  # noqa: BLE001 - CLI must convert every failure to a receipt
        output = Path(args.output).resolve()
        output.mkdir(parents=True, exist_ok=True)
        receipt = _blocked_receipt(args.command, exc)
        if args.command == "install":
            history_record = append_release_record(
                output / "release-history.jsonl",
                {
                    "event": "INSTALL_BLOCKED",
                    "status": receipt["status"],
                    "failure_code": receipt["failure_code"],
                },
            )
            receipt["release_history_sequence"] = history_record["sequence"]
            receipt["release_history_record_digest"] = history_record["record_digest"]
            receipt.pop("receipt_digest", None)
            receipt["receipt_digest"] = canonical_digest(receipt)
        _write_json(output / f"blocked-{args.command}.json", receipt)
        print(f"{args.command}: {_failure_code(exc)}: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
