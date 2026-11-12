#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import stat
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from full_inspection_repair.contracts import (
    ContractError,
    assert_zero_open_risk,
    canonical_digest,
    validate_risk_ledger_consistency,
)
from full_inspection_repair.observation import ObservationJournal
from full_inspection_repair.package import (
    InstallBlocked,
    PackageError,
    RestoreBlocked,
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
from full_inspection_repair.state_machine import advance
from full_inspection_repair.strict import (
    StrictJSONError,
    fsync_directory,
    read_json,
    write_all,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        write_all(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _require_record_digest(value: dict[str, object], field: str, label: str) -> str:
    declared = value.get(field)
    material = dict(value)
    material.pop(field, None)
    if declared != canonical_digest(material):
        raise ReleaseBlocked(f"{label} digest mismatch")
    return str(declared)


def _optional_json_object(path: Path) -> dict[str, object]:
    try:
        value = read_json(path)
    except (OSError, StrictJSONError):
        return {}
    return value if isinstance(value, dict) else {}


def _validate_evidence(
    verification: dict[str, object],
    ledger: dict[str, object],
    *,
    candidate_digest: str,
    ledger_path: Path,
) -> None:
    if verification.get("status") != "PASS" or verification.get("failure_count") != 0:
        raise ReleaseBlocked("verification is not PASS")
    _require_record_digest(verification, "verification_digest", "verification")
    try:
        validate_risk_ledger_consistency(ledger)
        assert_zero_open_risk(
            ledger,
            expected_candidate_digest=candidate_digest,
        )
    except ContractError as exc:
        raise ReleaseBlocked(f"risk ledger contract violation: {exc}") from exc
    base = ledger_path.resolve().parent
    for item in ledger["items"]:
        for reference in item["evidence_refs"]:
            if reference.startswith("candidate:"):
                if reference.removeprefix("candidate:") != candidate_digest:
                    raise ReleaseBlocked("finding candidate evidence is foreign")
                continue
            if not reference.startswith(("evidence:", "receipt:")):
                raise ReleaseBlocked(f"unsupported evidence reference: {reference}")
            relative = reference.split(":", 1)[1]
            evidence_path = (base / relative).resolve()
            try:
                evidence_path.relative_to(base)
            except ValueError as exc:
                raise ReleaseBlocked("evidence reference escapes the ledger directory") from exc
            if not evidence_path.is_file():
                raise ReleaseBlocked(f"evidence reference is missing: {reference}")
            evidence = read_json(evidence_path)
            digest_fields = (
                "receipt_digest",
                "evidence_digest",
                "verification_digest",
                "ledger_digest",
            )
            declared = next(
                (
                    evidence[field]
                    for field in digest_fields
                    if isinstance(evidence.get(field), str)
                ),
                None,
            )
            if declared is None:
                raise ReleaseBlocked(f"evidence reference has no digest: {reference}")
            field = next(
                field for field in digest_fields if evidence.get(field) == declared
            )
            material = dict(evidence)
            material.pop(field, None)
            if canonical_digest(material) != declared:
                raise ReleaseBlocked(f"evidence reference digest mismatch: {reference}")


def _load_run_state(path: str | Path, output: Path) -> dict[str, object]:
    state_path = Path(path).resolve()
    if state_path != (output / "run-state.json").resolve():
        raise ReleaseBlocked("release run state must be the command output run-state.json")
    value = read_json(state_path)
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ReleaseBlocked("release run state schema mismatch")
    if not value.get("run_id") or not value.get("current_state"):
        raise ReleaseBlocked("release run state identity is incomplete")
    return value


def _require_run_state(
    path: str | Path,
    output: Path,
    *,
    expected_state: str,
    candidate_digest: str,
) -> dict[str, object]:
    state = _load_run_state(path, output)
    if state["current_state"] != expected_state:
        raise ReleaseBlocked(
            f"release run state must be {expected_state}, "
            f"not {state['current_state']}"
        )
    bound_candidate = state.get("candidate_digest")
    if bound_candidate not in (None, candidate_digest):
        raise ReleaseBlocked("release run state belongs to a foreign candidate")
    return state


def _history_anchor_key(path: str | Path, output: Path) -> bytes:
    key_path = Path(path).resolve()
    try:
        key_path.relative_to(output)
    except ValueError:
        outside_output = True
    else:
        outside_output = False
    if not outside_output:
        raise ReleaseBlocked("release history anchor key must be outside output")
    current = key_path
    while True:
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ReleaseBlocked("release history anchor key path contains a link")
        if current == current.parent:
            break
        current = current.parent
    if not key_path.is_file():
        raise ReleaseBlocked("release history anchor key is missing")
    if not 32 <= key_path.stat().st_size <= 4096:
        raise ReleaseBlocked("release history anchor key size is invalid")
    return key_path.read_bytes()


def _advance_run_state(
    state: dict[str, object],
    path: str | Path,
    event: str,
    **bindings: object,
) -> None:
    next_state = advance(str(state["current_state"]), event)
    history = list(state.get("history", []))
    history.append(
        {
            "from": state["current_state"],
            "event": event,
            "to": next_state,
        }
    )
    updated = {
        **state,
        **bindings,
        "current_state": next_state,
        "history": history,
    }
    _write_json(Path(path), updated)


def _verification_material(args) -> dict[str, object]:
    attestation_path = Path(args.attestation).resolve()
    attestation_bytes = attestation_path.read_bytes()
    trust_registry = read_json(Path(args.trust_registry))
    trust_registry_digest = canonical_digest(trust_registry)
    if trust_registry_digest != args.trust_registry_digest:
        raise ReleaseBlocked("trust registry digest mismatch")
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
            "trust_registry": trust_registry,
            "trust_registry_digest": trust_registry_digest,
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
            "trust_registry": trust_registry,
            "trust_registry_digest": trust_registry_digest,
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
    candidate_digest = str(manifest["tree_digest"])
    _validate_evidence(
        verification,
        ledger,
        candidate_digest=candidate_digest,
        ledger_path=Path(args.ledger),
    )
    state = _require_run_state(
        args.run_state,
        output,
        expected_state="FULL_VERIFICATION",
        candidate_digest=candidate_digest,
    )
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
        "findings": ledger_rows,
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
    _advance_run_state(
        state,
        args.run_state,
        "review",
        candidate_digest=candidate_digest,
        review_digest=review["review_digest"],
    )
    return 0


def _claim(args) -> int:
    output = Path(args.output).resolve()
    verification_material = _verification_material(args)
    anchor_key = _history_anchor_key(args.history_anchor_key, output)
    review = read_json(Path(args.review))
    state = _require_run_state(
        args.run_state,
        output,
        expected_state="INDEPENDENT_REVIEW",
        candidate_digest=review["candidate_digest"],
    )
    claim = build_release_claim(
        review,
        **verification_material,
    )
    history_record = append_release_record(
        output / "release-history.jsonl",
        {
            "event": "CLAIM",
            "status": claim["status"],
            "claim_digest": claim["claim_digest"],
            "candidate_digest": claim["candidate_digest"],
            "review_digest": claim["review_digest"],
            "trust_root_id": claim["trust_root_id"],
            "trust_registry_digest": claim["trust_registry_digest"],
        },
        anchor_key=anchor_key,
    )
    _write_json(output / "release-claim.json", claim)
    _write_json(
        Path(args.run_state),
        {
            **state,
            "claim_digest": claim["claim_digest"],
            "claim_history_record_digest": history_record["record_digest"],
        },
    )
    return 0


def _install(args) -> int:
    output = Path(args.output).resolve()
    manifest = read_json(Path(args.manifest))
    claim = read_json(Path(args.claim))
    review = read_json(Path(args.review))
    verification_material = _verification_material(args)
    anchor_key = _history_anchor_key(args.history_anchor_key, output)
    state = _require_run_state(
        args.run_state,
        output,
        expected_state="INDEPENDENT_REVIEW",
        candidate_digest=str(manifest["tree_digest"]),
    )
    history_record: dict[str, object] | None = None

    def commit_install(binding: dict[str, object]) -> None:
        nonlocal history_record
        history_record = append_release_record(
            output / "release-history.jsonl",
            {
                "event": "INSTALL",
                "status": "INSTALLED",
                **binding,
            },
            anchor_key=anchor_key,
        )

    receipt = install_package(
        args.source,
        args.target,
        manifest,
        claim=claim,
        review=review,
        **verification_material,
        rollback_root=args.rollback,
        commit_callback=commit_install,
    )
    if history_record is None:
        raise ReleaseBlocked("install history commit did not run")
    receipt["release_history_sequence"] = history_record["sequence"]
    receipt["release_history_record_digest"] = history_record["record_digest"]
    receipt.pop("receipt_digest", None)
    receipt["receipt_digest"] = canonical_digest(receipt)
    _write_json(output / "install-receipt.json", receipt)
    _advance_run_state(
        state,
        args.run_state,
        "close",
        claim_digest=claim["claim_digest"],
        install_receipt_digest=receipt["receipt_digest"],
    )
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
    parser.add_argument("--trust-registry", required=True)
    parser.add_argument("--trust-registry-digest", required=True)
    parser.add_argument("--run-state", required=True)


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
    claim.add_argument("--history-anchor-key", required=True)
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
    install.add_argument("--history-anchor-key", required=True)
    install.set_defaults(handler=_install)
    return parser


def _failure_code(exc: Exception) -> str:
    if isinstance(exc, StrictJSONError):
        return "EVIDENCE_PARSE"
    if isinstance(exc, InstallBlocked):
        if isinstance(exc, RestoreBlocked):
            return "BLOCKED_RESTORE"
        return "INSTALL_BLOCKED"
    if isinstance(exc, ContractError):
        return "RISK_CONTRACT"
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


def _record_review_failure(args, exc: Exception) -> None:
    state = _optional_json_object(Path(args.run_state))
    manifest = _optional_json_object(Path(args.manifest))
    journal_path = Path(args.run_state).with_name("observations.jsonl")
    journal = ObservationJournal(journal_path)
    policy_digest = canonical_digest({"review_observation_policy": "1"})
    if journal_path.exists() and journal_path.stat().st_size:
        first = journal_path.read_text(encoding="utf-8").splitlines()[0]
        existing = json.loads(first)
        policy_digest = str(existing["redaction_policy_digest"])
    message = f"independent review blocked: {type(exc).__name__}: {exc}"
    evidence = [
        f"command:release-skill:{args.command}",
        f"error:{_failure_code(exc)}",
    ]
    subject_digest = manifest.get("tree_digest")
    if not isinstance(subject_digest, str) or len(subject_digest) != 64:
        subject_digest = canonical_digest(
            {"unavailable_manifest": Path(args.manifest).name}
        )
    journal.append(
        {
            "source_run_id": str(state.get("run_id", "run:unavailable")),
            "source_phase": "REVIEW",
            "producer_id": "full-inspection-repair",
            "subject_id": str(manifest.get("subject_id", f"skill:{subject_digest[:16]}")),
            "subject_kind": "SKILL",
            "subject_digest": subject_digest,
            "invariant_id": "REVIEW-FAILURE-001",
            "defect_class_id": "review.blocked",
            "taxonomy_category_id": "EXCEPTION_PATH",
            "fingerprint": str(_failure_code(exc)),
            "fingerprint_version": "1.0.0",
            "message": message,
            "mechanism": str(exc),
            "root_cause_hypothesis": type(exc).__name__,
            "evidence_refs": evidence,
            "evidence_sha256": canonical_digest(evidence),
            "redaction_policy_digest": policy_digest,
            "severity": "High",
            "analogous_surfaces": [],
            "status": "CONFIRMED",
            "safe_feedback": "Block release until the review failure is resolved.",
            "recorded_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        }
    )
    checkpoint = journal.checkpoint()
    _write_json(
        journal_path.with_name("observation-journal-manifest.json"),
        {
            "schema_version": 1,
            "status": "PASS",
            "record_count": checkpoint["record_count"],
            "head_digest": checkpoint["head_digest"],
            "journal_sha256": canonical_digest(
                journal_path.read_text(encoding="utf-8").splitlines()
            ),
            "checkpoint": checkpoint,
            "verified_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        },
    )


def run() -> int:
    args = _parser().parse_args()
    try:
        return args.handler(args)
    except Exception as exc:  # noqa: BLE001 - CLI must convert every failure to a receipt
        output = Path(args.output).resolve()
        output.mkdir(parents=True, exist_ok=True)
        if args.command == "review":
            _record_review_failure(args, exc)
        receipt = _blocked_receipt(args.command, exc)
        if args.command == "install":
            anchor_key = _history_anchor_key(
                args.history_anchor_key,
                output,
            )
            history_record = append_release_record(
                output / "release-history.jsonl",
                {
                    "event": "INSTALL_BLOCKED",
                    "status": receipt["status"],
                    "failure_code": receipt["failure_code"],
                },
                anchor_key=anchor_key,
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
