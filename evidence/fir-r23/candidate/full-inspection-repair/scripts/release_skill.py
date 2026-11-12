#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True

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
    RELEASE_LIFECYCLE_EVENTS,
    ReleaseBlocked,
    append_release_record,
    build_release_claim,
    latest_release_record,
    release_id_for,
    replay_release_history,
    validate_release_lifecycle,
)
from full_inspection_repair.review import (
    ReviewBlocked,
    build_review_packet,
    load_trust_anchor,
    review_packet,
    validate_evaluator_artifact,
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


def _release_scope_id(review: dict[str, object]) -> str:
    subject = review.get("subject")
    if isinstance(subject, dict):
        value = subject.get("scope_id")
        if isinstance(value, str) and value:
            return value
    value = review.get("scope_id")
    if isinstance(value, str) and value:
        return value
    raise ReleaseBlocked("review does not bind a release scope")


def _release_history_path(output: Path) -> Path:
    return output / "release-history.jsonl"


def _history_records(
    output: Path,
    *,
    anchor_key: bytes,
    key_sha256: str,
) -> list[dict[str, object]]:
    return replay_release_history(
        _release_history_path(output),
        expected_key_sha256=key_sha256,
        anchor_key=anchor_key,
    )


def _append_history(
    output: Path,
    record: dict[str, object],
    *,
    anchor_key: bytes,
    key_sha256: str,
) -> dict[str, object]:
    return append_release_record(
        _release_history_path(output),
        record,
        expected_key_sha256=key_sha256,
        anchor_key=anchor_key,
    )


def _load_release_trust_anchor() -> dict[str, object]:
    return load_trust_anchor()


def _trust_registry(anchor: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "reviewers": anchor["reviewers"],
    }


def _history_anchor_key(
    path: str | Path,
    output: Path,
    *,
    trust_anchor: dict[str, object],
) -> bytes:
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
    key_bytes = key_path.read_bytes()
    key_sha256 = hashlib.sha256(key_bytes).hexdigest()
    if key_sha256 not in trust_anchor["history_anchor_key_sha256"]:
        raise ReleaseBlocked(
            "release history anchor key is not frozen by the trust anchor"
        )
    return key_bytes


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


def _verification_material(
    args,
    *,
    trust_anchor: dict[str, object] | None = None,
) -> dict[str, object]:
    anchor = trust_anchor or _load_release_trust_anchor()
    attestation_path = Path(args.attestation).resolve()
    attestation_bytes = attestation_path.read_bytes()
    trust_registry = _trust_registry(anchor)
    trust_registry_digest = canonical_digest(trust_registry)
    if trust_registry_digest != anchor["reviewer_registry_digest"]:
        raise ReleaseBlocked("trust anchor registry digest mismatch")
    supplied_registry = read_json(Path(args.trust_registry))
    if supplied_registry != trust_registry:
        raise ReleaseBlocked("caller trust registry is not the frozen registry")
    if args.trust_registry_digest != trust_registry_digest:
        raise ReleaseBlocked("caller trust registry digest is not the frozen identity")
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
            "trust_anchor": anchor,
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
        if not getattr(args, "sigstore_trust_config", None):
            raise ReleaseBlocked("Sigstore requires --sigstore-trust-config")
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
            "trust_anchor": anchor,
            "trust_config_path": Path(args.sigstore_trust_config).resolve(),
            "snapshot_root": Path(args.output).resolve() / ".sigstore-snapshots",
        }
    raise ReleaseBlocked(f"unsupported verification method: {args.verification_method}")


def _package(args) -> int:
    output = Path(args.output).resolve()
    manifest = build_package_manifest(args.source)
    _write_json(output / "package-manifest.json", manifest)
    return 0


def _review(args) -> int:
    output = Path(args.output).resolve()
    trust_anchor = _load_release_trust_anchor()
    manifest = read_json(Path(args.manifest))
    verification = read_json(Path(args.verification))
    ledger = read_json(Path(args.ledger))
    evidence = read_json(Path(args.review_evidence))
    verification_material = _verification_material(
        args,
        trust_anchor=trust_anchor,
    )
    if not getattr(args, "evaluator_artifact", None):
        raise ReleaseBlocked("review requires --evaluator-artifact")
    evaluator_artifact = Path(args.evaluator_artifact).read_bytes()
    evaluator_digest = validate_evaluator_artifact(
        trust_anchor,
        artifact_bytes=evaluator_artifact,
        expected_digest=getattr(args, "evaluator", None),
    )
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
        "scope_id": str(state.get("scope_id") or state["run_id"]),
        "review_kind": "FINAL_REVIEW",
        "freeze_digest": state.get("freeze_digest"),
        "scope_digest": ledger["scope_digest"],
        "candidate_digest": manifest["tree_digest"],
        "verification_digest": verification["verification_digest"],
        "ledger_digest": ledger["ledger_digest"],
        "evaluator_digest": evaluator_digest,
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
        evaluator_artifact_bytes=evaluator_artifact,
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
    trust_anchor = _load_release_trust_anchor()
    verification_material = _verification_material(
        args,
        trust_anchor=trust_anchor,
    )
    anchor_key = _history_anchor_key(
        args.history_anchor_key,
        output,
        trust_anchor=trust_anchor,
    )
    key_sha256 = hashlib.sha256(anchor_key).hexdigest()
    review = read_json(Path(args.review))
    subject = review.get("subject")
    review_kind = (
        review.get("review_kind")
        or (subject.get("review_kind") if isinstance(subject, dict) else None)
    )
    if review_kind != "FINAL_REVIEW":
        raise ReleaseBlocked("claim requires a final review")
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
    if claim["history_anchor_key_sha256"] != key_sha256:
        raise ReleaseBlocked("claim history anchor key is not externally frozen")
    scope_id = _release_scope_id(review)
    release_id = release_id_for(scope_id, str(claim["candidate_digest"]))
    claim["release_id"] = release_id
    claim.pop("claim_digest", None)
    claim["claim_digest"] = canonical_digest(claim)
    claim_path = output / "release-claim.json"

    records = _history_records(
        output,
        anchor_key=anchor_key,
        key_sha256=key_sha256,
    )
    selected = [
        record for record in records if record.get("release_id") == release_id
    ]
    if not selected:
        freeze_digest = review.get("subject", {}).get("freeze_digest")
        if not isinstance(freeze_digest, str) or len(freeze_digest) != 64:
            raise ReleaseBlocked("claim requires a candidate freeze digest")
        _append_history(
            output,
            {
                "event": "FREEZE",
                "status": "FROZEN",
                "release_id": release_id,
                "scope_id": scope_id,
                "candidate_digest": claim["candidate_digest"],
                "freeze_digest": freeze_digest,
                "history_anchor_key_sha256": key_sha256,
            },
            anchor_key=anchor_key,
            key_sha256=key_sha256,
        )
        records = _history_records(
            output,
            anchor_key=anchor_key,
            key_sha256=key_sha256,
        )
        selected = [
            record for record in records if record.get("release_id") == release_id
        ]
    if [str(record.get("event")) for record in selected] == list(
        RELEASE_LIFECYCLE_EVENTS[:4]
    ):
        if not claim_path.is_file():
            raise ReleaseBlocked("committed claim is missing its claim receipt")
        stored_claim = read_json(claim_path)
        if stored_claim.get("claim_digest") != claim["claim_digest"]:
            raise ReleaseBlocked("committed claim receipt is stale")
        _advance_run_state(
            state,
            args.run_state,
            "claim",
            claim_digest=claim["claim_digest"],
            claim_history_record_digest=selected[3]["record_digest"],
            release_id=release_id,
        )
        return 0
    if not selected or selected[0].get("event") != "FREEZE":
        raise ReleaseBlocked("release lifecycle must begin with FREEZE")
    final_reviews = [
        record for record in selected if record.get("event") == "FINAL_REVIEW"
    ]
    if not final_reviews:
        _append_history(
            output,
            {
                "event": "FINAL_REVIEW",
                "status": "PASS",
                "release_id": release_id,
                "scope_id": scope_id,
                "candidate_digest": claim["candidate_digest"],
                "review_digest": review["review_digest"],
                "matrix_digest": review.get("matrix_digest"),
                "risk_gate_digest": (
                    claim.get("risk_gate_digest")
                    or review.get("risk_gate", {}).get("gate_digest")
                ),
                "history_anchor_key_sha256": key_sha256,
            },
            anchor_key=anchor_key,
            key_sha256=key_sha256,
        )
        records = _history_records(
            output,
            anchor_key=anchor_key,
            key_sha256=key_sha256,
        )
        selected = [
            record for record in records if record.get("release_id") == release_id
        ]
    final_review = latest_release_record(
        records,
        release_id=release_id,
        event="FINAL_REVIEW",
    )
    if final_review.get("review_digest") != review["review_digest"]:
        raise ReleaseBlocked("release lifecycle final review is stale")
    events = [str(record.get("event")) for record in selected]
    if events == list(RELEASE_LIFECYCLE_EVENTS[:2]):
        validate_release_lifecycle(
            records,
            release_id=release_id,
            scope_id=scope_id,
            candidate_digest=str(claim["candidate_digest"]),
            required_through="FINAL_REVIEW",
        )
    elif events != ["FREEZE", "FINAL_REVIEW", "CLAIM_INTENT"]:
        raise ReleaseBlocked("release lifecycle is not claimable")

    intents = [
        record
        for record in records
        if record.get("release_id") == release_id
        and record.get("event") == "CLAIM_INTENT"
    ]
    if intents:
        intent = intents[0]
        if intent.get("claim_digest") != claim["claim_digest"]:
            raise ReleaseBlocked("claim intent digest is stale")
    else:
        intent = _append_history(
            output,
            {
                "event": "CLAIM_INTENT",
                "status": "PREPARED",
                "release_id": release_id,
                "scope_id": scope_id,
                "claim_digest": claim["claim_digest"],
                "candidate_digest": claim["candidate_digest"],
                "review_digest": claim["review_digest"],
                "trust_root_id": claim["trust_root_id"],
                "reviewer_identity_domain_id": claim["trust_root_id"],
                "trust_registry_digest": claim["trust_registry_digest"],
                "trust_anchor_digest": claim["trust_anchor_digest"],
                "history_anchor_key_sha256": key_sha256,
            },
            anchor_key=anchor_key,
            key_sha256=key_sha256,
        )
    committed = False
    try:
        _write_json(claim_path, claim)
        commit = _append_history(
            output,
            {
                "event": "CLAIM_COMMIT",
                "status": "RELEASE_READY",
                "release_id": release_id,
                "scope_id": scope_id,
                "candidate_digest": claim["candidate_digest"],
                "claim_digest": claim["claim_digest"],
                "intent_record_digest": intent["record_digest"],
                "review_digest": claim["review_digest"],
                "trust_anchor_digest": claim["trust_anchor_digest"],
                "history_anchor_key_sha256": key_sha256,
            },
            anchor_key=anchor_key,
            key_sha256=key_sha256,
        )
        committed = True
        _advance_run_state(
            state,
            args.run_state,
            "claim",
            claim_digest=claim["claim_digest"],
            claim_history_record_digest=commit["record_digest"],
            release_id=release_id,
        )
    except Exception:
        if not committed:
            with suppress(FileNotFoundError):
                claim_path.unlink()
            with suppress(Exception):
                _append_history(
                    output,
                    {
                        "event": "CLAIM_ABORT",
                        "status": "ABORTED",
                        "release_id": release_id,
                        "scope_id": scope_id,
                        "candidate_digest": claim["candidate_digest"],
                        "claim_digest": claim["claim_digest"],
                        "intent_record_digest": intent["record_digest"],
                        "review_digest": claim["review_digest"],
                    },
                    anchor_key=anchor_key,
                    key_sha256=key_sha256,
                )
        raise
    return 0


def _install(args) -> int:
    output = Path(args.output).resolve()
    trust_anchor = _load_release_trust_anchor()
    manifest = read_json(Path(args.manifest))
    claim = read_json(Path(args.claim))
    review = read_json(Path(args.review))
    verification_material = _verification_material(
        args,
        trust_anchor=trust_anchor,
    )
    anchor_key = _history_anchor_key(
        args.history_anchor_key,
        output,
        trust_anchor=trust_anchor,
    )
    key_sha256 = hashlib.sha256(anchor_key).hexdigest()
    state = _require_run_state(
        args.run_state,
        output,
        expected_state="RELEASE_CLAIMED",
        candidate_digest=str(manifest["tree_digest"]),
    )
    if claim["history_anchor_key_sha256"] != key_sha256:
        raise ReleaseBlocked("claim history anchor key does not match install authority")
    scope_id = _release_scope_id(review)
    release_id = str(
        claim.get("release_id")
        or review.get("subject", {}).get("release_id")
        or release_id_for(scope_id, str(manifest["tree_digest"]))
    )
    if release_id != release_id_for(scope_id, str(manifest["tree_digest"])):
        raise ReleaseBlocked("claim release ID does not match the install scope")
    records = _history_records(
        output,
        anchor_key=anchor_key,
        key_sha256=key_sha256,
    )
    validate_release_lifecycle(
        records,
        release_id=release_id,
        scope_id=scope_id,
        candidate_digest=str(manifest["tree_digest"]),
        required_through="CLAIM_COMMIT",
    )
    commit = latest_release_record(
        records,
        release_id=release_id,
        event="CLAIM_COMMIT",
    )
    if commit.get("claim_digest") != claim["claim_digest"]:
        raise ReleaseBlocked("install history claim does not match the release claim")

    target = Path(args.target).resolve()
    rollback = (
        Path(args.rollback).resolve()
        if args.rollback
        else target.with_name(f".{target.name}.rollback")
    )
    transaction_path = output / "install-transaction.json"
    installed_records = [
        record
        for record in records
        if record.get("release_id") == release_id
        and record.get("event") == "INSTALL"
    ]

    def finalize_installed(
        receipt: dict[str, object],
        history_record: dict[str, object],
    ) -> None:
        receipt["release_id"] = release_id
        receipt["release_history_sequence"] = history_record["sequence"]
        receipt["release_history_record_digest"] = history_record["record_digest"]
        receipt.pop("receipt_digest", None)
        receipt["receipt_digest"] = canonical_digest(receipt)
        _write_json(output / "install-receipt.json", receipt)
        _write_json(
            transaction_path,
            {
                "schema_version": 1,
                "status": "COMPLETE",
                "release_id": release_id,
                "candidate_digest": manifest["tree_digest"],
                "install_receipt_digest": receipt["receipt_digest"],
                "install_history_record_digest": history_record["record_digest"],
            },
        )
        _advance_run_state(
            state,
            args.run_state,
            "install",
            release_id=release_id,
            claim_digest=claim["claim_digest"],
            install_receipt_digest=receipt["receipt_digest"],
        )

    if installed_records:
        if len(installed_records) != 1:
            raise ReleaseBlocked("release lifecycle contains duplicate INSTALL records")
        if (
            target.is_dir()
            and manifest.get("tree_digest")
            == build_package_manifest(target)["tree_digest"]
        ):
            history_record = installed_records[0]
            receipt: dict[str, object] = {
                "schema_version": 2,
                "status": "INSTALLED",
                "recovered_after_interruption": True,
                "claim_digest": claim["claim_digest"],
                "review_digest": review["review_digest"],
                "subject_digest": review["subject_digest"],
                "issuer": review["external_signature"]["issuer"],
                "trust_root_id": review["external_signature"]["trust_root_id"],
                "history_anchor_key_sha256": key_sha256,
                "verification_method": review["external_signature"][
                    "verification_method"
                ],
                "candidate_digest": manifest["tree_digest"],
                "source_manifest_digest": manifest["manifest_digest"],
                "post_install_digest": manifest["tree_digest"],
                "install_digest": manifest["tree_digest"],
                "target": str(target),
                "rollback_root": str(rollback) if rollback.exists() else None,
                "rollback_digest": (
                    build_package_manifest(rollback)["tree_digest"]
                    if rollback.exists()
                    else None
                ),
                "rollback_retained": rollback.exists(),
                "readback_verified": True,
                "smoke_verified": True,
                "activated_atomically": True,
            }
            finalize_installed(receipt, history_record)
            return 0
        raise ReleaseBlocked("INSTALL history exists but target readback is not the candidate")

    target_before_digest = (
        build_package_manifest(target)["tree_digest"] if target.exists() else None
    )
    _write_json(
        transaction_path,
        {
            "schema_version": 1,
            "status": "PREPARED",
            "release_id": release_id,
            "scope_id": scope_id,
            "candidate_digest": manifest["tree_digest"],
            "claim_digest": claim["claim_digest"],
            "target": str(target),
            "rollback_root": str(rollback),
            "target_before_digest": target_before_digest,
        },
    )

    history_record: dict[str, object] | None = None

    def commit_install(binding: dict[str, object]) -> None:
        nonlocal history_record
        history_record = _append_history(
            output,
            {
                "event": "INSTALL",
                "status": "INSTALLED",
                "release_id": release_id,
                "scope_id": scope_id,
                **binding,
                "history_anchor_key_sha256": key_sha256,
            },
            anchor_key=anchor_key,
            key_sha256=key_sha256,
        )

    try:
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
    except Exception as exc:
        current_digest = (
            build_package_manifest(target)["tree_digest"]
            if target.exists()
            else None
        )
        if (
            current_digest == manifest["tree_digest"]
            and history_record is None
        ):
            history_record = _append_history(
                output,
                {
                    "event": "INSTALL",
                    "status": "INSTALLED_RECONCILED",
                    "release_id": release_id,
                    "scope_id": scope_id,
                    "claim_digest": claim["claim_digest"],
                    "review_digest": review["review_digest"],
                    "candidate_digest": manifest["tree_digest"],
                    "target": str(target),
                    "rollback_root": str(rollback) if rollback.exists() else None,
                    "history_anchor_key_sha256": key_sha256,
                },
                anchor_key=anchor_key,
                key_sha256=key_sha256,
            )
        _write_json(
            transaction_path,
            {
                "schema_version": 1,
                "status": "FAILED",
                "release_id": release_id,
                "candidate_digest": manifest["tree_digest"],
                "target_digest": current_digest,
                "failure": f"{type(exc).__name__}: {exc}",
            },
        )
        raise
    if history_record is None:
        raise ReleaseBlocked("install history commit did not run")
    finalize_installed(receipt, history_record)
    return 0


def _postinstall(args) -> int:
    output = Path(args.output).resolve()
    manifest = read_json(Path(args.manifest))
    claim = read_json(Path(args.claim))
    review = read_json(Path(args.review))
    state = _require_run_state(
        args.run_state,
        output,
        expected_state="INSTALLED",
        candidate_digest=str(manifest["tree_digest"]),
    )
    target = Path(args.target).resolve()
    if not target.is_dir():
        raise ReleaseBlocked("installed target is missing")
    verify_package_manifest(target, manifest)
    installed_digest = build_package_manifest(target)["tree_digest"]
    if installed_digest != manifest["tree_digest"]:
        raise ReleaseBlocked("installed tree digest changed after install")
    verification_path = Path(args.post_install_verification).resolve()
    verification = read_json(verification_path)
    if (
        verification.get("status") != "PASS"
        or verification.get("candidate_digest") != manifest["tree_digest"]
        or verification.get("installed_digest") != installed_digest
        or verification.get("failure_count") not in (0, None)
    ):
        raise ReleaseBlocked("post-install verification receipt is not PASS")
    trust_anchor = _load_release_trust_anchor()
    anchor_key = _history_anchor_key(
        args.history_anchor_key,
        output,
        trust_anchor=trust_anchor,
    )
    key_sha256 = hashlib.sha256(anchor_key).hexdigest()
    scope_id = _release_scope_id(review)
    release_id = str(
        claim.get("release_id")
        or review.get("subject", {}).get("release_id")
        or release_id_for(scope_id, str(manifest["tree_digest"]))
    )
    records = _history_records(
        output,
        anchor_key=anchor_key,
        key_sha256=key_sha256,
    )
    validate_release_lifecycle(
        records,
        release_id=release_id,
        scope_id=scope_id,
        candidate_digest=str(manifest["tree_digest"]),
        required_through="INSTALL",
    )
    existing = [
        record
        for record in records
        if record.get("release_id") == release_id
        and record.get("event") == "POST_INSTALL_REPLAY"
    ]
    if existing:
        if len(existing) != 1:
            raise ReleaseBlocked("post-install replay is duplicated")
        history_record = existing[0]
    else:
        history_record = _append_history(
            output,
            {
                "event": "POST_INSTALL_REPLAY",
                "status": "PASS",
                "release_id": release_id,
                "scope_id": scope_id,
                "candidate_digest": manifest["tree_digest"],
                "installed_digest": installed_digest,
                "claim_digest": claim["claim_digest"],
                "review_digest": review["review_digest"],
                "verification_receipt_sha256": hashlib.sha256(
                    verification_path.read_bytes()
                ).hexdigest(),
                "history_anchor_key_sha256": key_sha256,
            },
            anchor_key=anchor_key,
            key_sha256=key_sha256,
        )
    all_records = _history_records(
        output,
        anchor_key=anchor_key,
        key_sha256=key_sha256,
    )
    validate_release_lifecycle(
        all_records,
        release_id=release_id,
        scope_id=scope_id,
        candidate_digest=str(manifest["tree_digest"]),
        required_through="POST_INSTALL_REPLAY",
    )
    receipt: dict[str, object] = {
        "schema_version": 1,
        "status": "POST_INSTALL_VERIFIED",
        "release_id": release_id,
        "scope_id": scope_id,
        "candidate_digest": manifest["tree_digest"],
        "installed_digest": installed_digest,
        "target": str(target),
        "verification_receipt": str(verification_path),
        "verification_receipt_sha256": hashlib.sha256(
            verification_path.read_bytes()
        ).hexdigest(),
        "release_history_sequence": history_record["sequence"],
        "release_history_record_digest": history_record["record_digest"],
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    _write_json(output / "post-install-receipt.json", receipt)
    _advance_run_state(
        state,
        args.run_state,
        "post_install",
        release_id=release_id,
        post_install_receipt_digest=receipt["receipt_digest"],
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
    parser.add_argument("--sigstore-trust-config")
    parser.add_argument("--cert-identity")
    parser.add_argument("--oidc-issuer")
    parser.add_argument("--trust-registry", required=True)
    parser.add_argument("--trust-registry-digest", required=True)
    parser.add_argument("--run-state", required=True)


class _ReleaseArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ReleaseBlocked(f"CLI arguments invalid: {message}")


def _parser() -> argparse.ArgumentParser:
    parser = _ReleaseArgumentParser(prog="release-skill")
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
    review.add_argument("--evaluator-artifact")
    review.add_argument("--evaluator")
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

    postinstall = subparsers.add_parser("postinstall")
    postinstall.add_argument("--target", required=True)
    postinstall.add_argument("--manifest", required=True)
    postinstall.add_argument("--claim", required=True)
    postinstall.add_argument("--review", required=True)
    postinstall.add_argument("--run-state", required=True)
    postinstall.add_argument("--post-install-verification", required=True)
    postinstall.add_argument("--output", required=True)
    postinstall.add_argument("--history-anchor-key", required=True)
    postinstall.set_defaults(handler=_postinstall)
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
    args = None
    try:
        args = _parser().parse_args()
        return args.handler(args)
    except Exception as exc:  # noqa: BLE001 - CLI must convert every failure to a receipt
        command = (
            str(getattr(args, "command", ""))
            if args is not None
            else next(
                (
                    item
                    for item in sys.argv[1:]
                    if item in {"package", "review", "claim", "install", "postinstall"}
                ),
                "unknown",
            )
        )
        receipt = _blocked_receipt(command, exc)
        output: Path | None = None
        if args is not None and getattr(args, "output", None):
            try:
                candidate_output = Path(args.output).resolve()
                if candidate_output.exists() and not candidate_output.is_dir():
                    raise ReleaseBlocked("release output path is not a directory")
                candidate_output.mkdir(parents=True, exist_ok=True)
                output = candidate_output
            except Exception as output_exc:  # noqa: BLE001
                receipt["receipt_write_error"] = str(output_exc)
        if output is not None:
            if args.command == "review":
                with suppress(Exception):
                    _record_review_failure(args, exc)
            if args.command == "install":
                try:
                    trust_anchor = _load_release_trust_anchor()
                    anchor_key = _history_anchor_key(
                        args.history_anchor_key,
                        output,
                        trust_anchor=trust_anchor,
                    )
                    key_sha256 = hashlib.sha256(anchor_key).hexdigest()
                    manifest = read_json(Path(args.manifest))
                    review = read_json(Path(args.review))
                    claim = read_json(Path(args.claim))
                    scope_id = _release_scope_id(review)
                    candidate_digest = str(manifest["tree_digest"])
                    release_id = str(
                        claim.get("release_id")
                        or release_id_for(scope_id, candidate_digest)
                    )
                    history_record = append_release_record(
                        output / "release-history.jsonl",
                        {
                            "event": "INSTALL_BLOCKED",
                            "status": receipt["status"],
                            "failure_code": receipt["failure_code"],
                            "release_id": release_id,
                            "scope_id": scope_id,
                            "candidate_digest": candidate_digest,
                            "claim_digest": claim.get("claim_digest"),
                            "history_anchor_key_sha256": key_sha256,
                        },
                        expected_key_sha256=key_sha256,
                        anchor_key=anchor_key,
                    )
                    receipt["release_history_sequence"] = history_record["sequence"]
                    receipt["release_history_record_digest"] = history_record[
                        "record_digest"
                    ]
                except Exception as history_exc:  # noqa: BLE001
                    receipt["history_write_error"] = str(history_exc)
            receipt.pop("receipt_digest", None)
            receipt["receipt_digest"] = canonical_digest(receipt)
            try:
                _write_json(output / f"blocked-{args.command}.json", receipt)
            except Exception as write_exc:  # noqa: BLE001
                receipt["receipt_write_error"] = str(write_exc)
                receipt.pop("receipt_digest", None)
                receipt["receipt_digest"] = canonical_digest(receipt)
        elif "receipt_write_error" not in receipt:
            receipt["receipt_write_error"] = "release output directory is unavailable"
            receipt.pop("receipt_digest", None)
            receipt["receipt_digest"] = canonical_digest(receipt)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
