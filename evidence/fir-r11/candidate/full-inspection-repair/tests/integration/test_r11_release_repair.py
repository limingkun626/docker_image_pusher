from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import full_inspection_repair.package as package_module
import full_inspection_repair.release as release_module
import release_skill
from full_inspection_repair.contracts import (
    CLOSED_FINDING_STATUSES,
    canonical_digest,
    canonical_json,
    schema_digest,
)
from full_inspection_repair.coverage import build_complete_coverage
from full_inspection_repair.package import (
    InstallBlocked,
    RestoreBlocked,
    build_package_manifest,
    install_package,
)
from full_inspection_repair.release import (
    ReleaseBlocked,
    append_release_record,
    replay_release_history,
)
from full_inspection_repair.review import (
    ED25519_VERIFIER,
    REVIEWER_ATTESTATION_SCHEMA_VERSION,
    SIGSTORE_VERIFIER,
    ReviewBlocked,
    sigstore_trust_root_id,
    trust_root_id_for_public_key,
    verify_reviewer_attestation,
    verify_sigstore_attestation,
)
from full_inspection_repair.risk_gate import (
    CLOSED_STATUSES,
    REQUIRED_DOMAINS,
    assess_release_gate,
)

HISTORY_KEY = b"r11-release-history-anchor-key-0001"


def _record(event: str) -> dict[str, object]:
    return {"event": event, "status": "VERIFIED", "candidate_digest": "a" * 64}


def _rehash_history(path: Path) -> None:
    previous = None
    lines = []
    for number, line in enumerate(path.read_bytes().splitlines(), start=1):
        record = json.loads(line)
        record["status"] = "REWRITTEN"
        record["sequence"] = number
        record["previous_record_digest"] = previous
        material = dict(record)
        material.pop("record_digest", None)
        record["record_digest"] = canonical_digest(material)
        previous = record["record_digest"]
        lines.append(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
    path.write_bytes(b"\n".join(lines) + b"\n")


def test_history_rewrite_truncation_foreign_key_and_limits_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    history = tmp_path / "release-history.jsonl"
    append_release_record(history, _record("CLAIM"), anchor_key=HISTORY_KEY)
    append_release_record(history, _record("INSTALL"), anchor_key=HISTORY_KEY)

    _rehash_history(history)
    with pytest.raises(ReleaseBlocked, match="high-water"):
        replay_release_history(history, anchor_key=HISTORY_KEY)
    with pytest.raises(ReleaseBlocked, match="authentication"):
        replay_release_history(history, anchor_key=b"x" * 32)

    lines = history.read_bytes().splitlines()
    history.write_bytes(lines[0] + b"\n")
    with pytest.raises(ReleaseBlocked, match="high-water"):
        replay_release_history(history, anchor_key=HISTORY_KEY)

    monkeypatch.setattr(release_module, "MAX_RELEASE_ARTIFACT_BYTES", 16)
    with pytest.raises(ReleaseBlocked, match="size policy"):
        replay_release_history(history, anchor_key=HISTORY_KEY)


def test_history_concurrent_append_retains_every_sequence(tmp_path: Path) -> None:
    history = tmp_path / "release-history.jsonl"

    def append(number: int) -> None:
        append_release_record(
            history,
            {
                "event": "PROBE",
                "status": "VERIFIED",
                "probe": number,
            },
            anchor_key=HISTORY_KEY,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(20)))

    records = replay_release_history(history, anchor_key=HISTORY_KEY)
    assert [record["sequence"] for record in records] == list(range(1, 21))
    assert {record["probe"] for record in records} == set(range(20))


def test_history_rejects_symlink_and_fsyncs_first_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = tmp_path / "real-history.jsonl"
    append_release_record(real, _record("CLAIM"), anchor_key=HISTORY_KEY)
    link = tmp_path / "linked-history.jsonl"
    try:
        os.symlink(real, link)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")
    with pytest.raises(ReleaseBlocked, match="symbolic link"):
        replay_release_history(link, anchor_key=HISTORY_KEY)

    calls = []
    monkeypatch.setattr(
        release_module,
        "fsync_directory",
        lambda path: calls.append(path),
    )
    append_release_record(
        tmp_path / "fresh" / "release-history.jsonl",
        _record("CLAIM"),
        anchor_key=HISTORY_KEY,
    )
    assert calls


def test_claim_append_failure_leaves_no_claim(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "release"
    output.mkdir()
    review = output / "independent-review.json"
    review.write_text(
        json.dumps(
            {
                "candidate_digest": "a" * 64,
                "review_digest": "b" * 64,
            }
        ),
        encoding="utf-8",
    )
    state = output / "run-state.json"
    state.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "run:claim",
                "current_state": "INDEPENDENT_REVIEW",
                "candidate_digest": "a" * 64,
                "history": [],
            }
        ),
        encoding="utf-8",
    )
    key = tmp_path / "history.key"
    key.write_bytes(HISTORY_KEY)
    monkeypatch.setattr(release_skill, "_verification_material", lambda args: {})
    monkeypatch.setattr(
        release_skill,
        "build_release_claim",
        lambda review, **kwargs: {
            "status": "RELEASE_READY",
            "claim_digest": "c" * 64,
            "candidate_digest": "a" * 64,
            "review_digest": "b" * 64,
            "trust_root_id": "sha256:" + "d" * 64,
            "trust_registry_digest": "e" * 64,
        },
    )

    def fail_append(*args, **kwargs):
        raise OSError("injected append failure")

    monkeypatch.setattr(release_skill, "append_release_record", fail_append)
    args = SimpleNamespace(
        output=str(output),
        review=str(review),
        run_state=str(state),
        history_anchor_key=str(key),
    )
    with pytest.raises(OSError, match="injected"):
        release_skill._claim(args)
    assert not (output / "release-claim.json").exists()


def _install_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# New\n", encoding="utf-8")
    target = tmp_path / "installed"
    target.mkdir()
    (target / "SKILL.md").write_text("# Old\n", encoding="utf-8")
    monkeypatch.setattr(
        package_module,
        "validate_claim_for_install",
        lambda *args, **kwargs: {},
    )
    return source, target


def test_install_commit_failure_restores_prior_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, target = _install_probe(tmp_path, monkeypatch)

    def fail_commit(binding: dict[str, object]) -> None:
        raise OSError("injected history failure")

    with pytest.raises(InstallBlocked, match="old install was restored"):
        install_package(
            source,
            target,
            build_package_manifest(source),
            claim={"claim_digest": "a" * 64},
            review={"review_digest": "b" * 64},
            attestation_bytes=b"attestation",
            signature_bytes=b"signature",
            public_key_bytes=b"public",
            issuer="issuer",
            trust_root_id="trust",
            commit_callback=fail_commit,
        )
    assert (target / "SKILL.md").read_text(encoding="utf-8") == "# Old\n"


def test_restore_failure_reports_blocked_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, target = _install_probe(tmp_path, monkeypatch)
    rollback = tmp_path / "rollback"

    def fail_smoke(path: Path) -> None:
        raise RuntimeError("smoke failed")

    def fail_restore(*args, **kwargs) -> None:
        raise OSError("restore failed")

    monkeypatch.setattr(package_module, "_restore_after_failure", fail_restore)
    with pytest.raises(RestoreBlocked, match="BLOCKED_RESTORE") as caught:
        install_package(
            source,
            target,
            build_package_manifest(source),
            claim={"claim_digest": "a" * 64},
            review={"review_digest": "b" * 64},
            attestation_bytes=b"attestation",
            signature_bytes=b"signature",
            public_key_bytes=b"public",
            issuer="issuer",
            trust_root_id="trust",
            rollback_root=rollback,
            smoke_check=fail_smoke,
        )
    assert str(target) in str(caught.value)
    assert str(rollback) in str(caught.value)


def test_unregistered_reviewer_key_blocks() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust_root = trust_root_id_for_public_key(public_key)
    registry = {
        "schema_version": 1,
        "reviewers": [
            {
                "reviewer": "reviewer",
                "issuer": "issuer",
                "verification_method": ED25519_VERIFIER,
                "trust_root_id": trust_root,
                "public_key_sha256": "0" * 64,
                "status": "ACTIVE",
            }
        ],
    }
    attestation = {
        "schema_version": REVIEWER_ATTESTATION_SCHEMA_VERSION,
        "reviewer": "reviewer",
        "issuer": "issuer",
        "trust_root_id": trust_root,
        "verification_method": ED25519_VERIFIER,
        "verdict": "PASS",
    }
    payload = canonical_json(attestation).encode("utf-8")
    with pytest.raises(ReviewBlocked, match="not the registered key"):
        verify_reviewer_attestation(
            attestation_bytes=payload,
            signature_bytes=private_key.sign(payload),
            public_key_bytes=public_key,
            expected_reviewer="reviewer",
            expected_issuer="issuer",
            expected_trust_root_id=trust_root,
            trust_registry=registry,
            trust_registry_digest=canonical_digest(registry),
        )


def _sigstore_fixture(tmp_path: Path) -> tuple[dict[str, object], Path, Path, Path]:
    identity = "reviewer.example/workflow"
    issuer = "https://issuer.example"
    trust_root = sigstore_trust_root_id(identity, issuer)
    verifier = tmp_path / "sigstore"
    verifier.write_bytes(b"trusted-verifier")
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(b'{"bundle":true}')
    attestation = tmp_path / "attestation.json"
    attestation.write_bytes(
        canonical_json(
            {
                "schema_version": REVIEWER_ATTESTATION_SCHEMA_VERSION,
                "reviewer": identity,
                "issuer": issuer,
                "trust_root_id": trust_root,
                "verification_method": SIGSTORE_VERIFIER,
                "verdict": "PASS",
            }
        ).encode("utf-8")
    )
    registry = {
        "schema_version": 1,
        "reviewers": [
            {
                "reviewer": identity,
                "issuer": issuer,
                "verification_method": SIGSTORE_VERIFIER,
                "trust_root_id": trust_root,
                "verifier_sha256": "0" * 64,
                "verifier_version": "4.5.1",
                "status": "ACTIVE",
            }
        ],
    }
    return {
        "registry": registry,
        "digest": canonical_digest(registry),
        "identity": identity,
        "issuer": issuer,
    }, attestation, bundle, verifier


def test_sigstore_verifier_content_and_version_are_pinned(tmp_path: Path) -> None:
    material, attestation, bundle, verifier = _sigstore_fixture(tmp_path)
    calls = []

    def runner(command: list[str]):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "sigstore 9.9.9", "")

    with pytest.raises(ReviewBlocked, match="content identity"):
        verify_sigstore_attestation(
            attestation_path=attestation,
            bundle_path=bundle,
            verifier_executable=verifier,
            cert_identity=str(material["identity"]),
            oidc_issuer=str(material["issuer"]),
            trust_registry=material["registry"],
            trust_registry_digest=material["digest"],
            runner=runner,
        )
    assert calls == []

    material["registry"]["reviewers"][0]["verifier_sha256"] = __import__(
        "hashlib"
    ).sha256(verifier.read_bytes()).hexdigest()
    material["digest"] = canonical_digest(material["registry"])

    def wrong_version(command: list[str]):
        return subprocess.CompletedProcess(command, 0, "sigstore 9.9.9", "")

    with pytest.raises(ReviewBlocked, match="version identity"):
        verify_sigstore_attestation(
            attestation_path=attestation,
            bundle_path=bundle,
            verifier_executable=verifier,
            cert_identity=str(material["identity"]),
            oidc_issuer=str(material["issuer"]),
            trust_registry=material["registry"],
            trust_registry_digest=material["digest"],
            runner=wrong_version,
        )


def test_sigstore_replacement_between_verify_and_hash_blocks(tmp_path: Path) -> None:
    material, attestation, bundle, verifier = _sigstore_fixture(tmp_path)
    material["registry"]["reviewers"][0]["verifier_sha256"] = __import__(
        "hashlib"
    ).sha256(verifier.read_bytes()).hexdigest()
    material["digest"] = canonical_digest(material["registry"])

    def runner(command: list[str]):
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, "sigstore 4.5.1", "")
        attestation.write_bytes(b'{"replaced":true}')
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(ReviewBlocked, match="changed during verification"):
        verify_sigstore_attestation(
            attestation_path=attestation,
            bundle_path=bundle,
            verifier_executable=verifier,
            cert_identity=str(material["identity"]),
            oidc_issuer=str(material["issuer"]),
            trust_registry=material["registry"],
            trust_registry_digest=material["digest"],
            runner=runner,
        )


def test_risk_gate_rejects_synthetic_summary_evidence() -> None:
    domains: dict[str, dict[str, str]] = {}
    for dotted, status in REQUIRED_DOMAINS.items():
        group, key = dotted.split(".")
        domains.setdefault(group, {})[key] = status
    coverage = build_complete_coverage({"SKILL.md": b"# Demo\n"})
    matrix = {
        "status": "PASS",
        "failed_count": 0,
        "candidate_digest": "a" * 64,
        "scope_digest": "b" * 64,
        "verification_digest": "c" * 64,
        "evaluator_digest": "d" * 64,
        "coverage_digest": coverage["coverage_digest"],
        "domains_digest": canonical_digest(domains),
    }
    matrix["matrix_digest"] = canonical_digest(matrix)
    finding = {
        "finding_id": "F-1",
        "status": "FIXED",
        "impact": "none",
        "impact_proof": "missing",
        "verification_evidence": "summary",
    }
    gate = assess_release_gate(
        findings=[finding],
        review={
            "verdict": "PASS",
            "open_count": 0,
            "residual_risks": [],
            "limitations": [],
            "unverified_claims": [],
            "not_run": [],
            "non_blocking_observations": [],
            "findings": [finding],
            "scope_digest": "b" * 64,
            "candidate_digest": "a" * 64,
            "verification_digest": "c" * 64,
            "ledger_digest": "e" * 64,
            "evaluator_digest": "d" * 64,
            "matrix_digest": matrix["matrix_digest"],
        },
        domains=domains,
        coverage=coverage,
        matrix=matrix,
        expected_candidate_digest="a" * 64,
        expected_scope_digest="b" * 64,
        expected_verification_digest="c" * 64,
        require_evidence_binding=True,
    )
    assert gate["release_ready"] is False
    assert "MATRIX_CHECKS_MISSING" in gate["blockers"]
    assert "DOMAIN_EVIDENCE_UNBOUND:trust.external_trust_root" in gate["blockers"]


def test_contract_and_gate_share_terminal_vocabulary() -> None:
    assert CLOSED_STATUSES == CLOSED_FINDING_STATUSES
    assert "FALSE_POSITIVE" not in CLOSED_STATUSES
    assert "PREVENTED_BY_GUARD" not in CLOSED_STATUSES


def _ledger(candidate: str, evidence_ref: str) -> dict[str, object]:
    item = {
        "schema_version": 1,
        "risk_id": "F-1",
        "invariant_id": "release",
        "defect_class_id": "release",
        "taxonomy_category_id": "VULNERABILITY",
        "subject_id": "release",
        "source_id": "source:F-1",
        "severity": "High",
        "message": "probe",
        "mechanism": "probe",
        "affected_refs": ["release.py"],
        "root_cause_id": "ROOT",
        "status": "FIXED",
        "evidence_refs": [f"candidate:{candidate}", evidence_ref],
        "evidence_sha256": candidate,
        "closed_by": candidate,
        "closed_at": "2026-11-10T00:00:00+00:00",
        "verification_check": "test:release",
        "residual_risk": None,
    }
    value = {
        "schema_version": 1,
        "scope_digest": "b" * 64,
        "finding_schema_digest": schema_digest("finding"),
        "risk_ledger_schema_digest": schema_digest("risk-ledger"),
        "required_sources": ["source:F-1"],
        "required_sources_digest": canonical_digest(["source:F-1"]),
        "observed_sources": ["source:F-1"],
        "items": [item],
        "open_count": 0,
        "closed_count": 1,
        "missing_sources": [],
        "unexpected_sources": [],
        "residual_risks": [],
        "unresolved_ids": [],
    }
    value["ledger_digest"] = canonical_digest(value)
    return value


def test_release_evidence_requires_resolvable_bound_receipt(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.json"
    candidate = "a" * 64
    verification = {"status": "PASS", "failure_count": 0}
    verification["verification_digest"] = canonical_digest(verification)
    missing = _ledger(candidate, "receipt:missing.json")
    with pytest.raises(ReleaseBlocked, match="missing"):
        release_skill._validate_evidence(
            verification,
            missing,
            candidate_digest=candidate,
            ledger_path=ledger_path,
        )

    receipt = tmp_path / "receipt.json"
    receipt_value = {"status": "VERIFIED"}
    receipt_value["receipt_digest"] = canonical_digest(receipt_value)
    receipt.write_text(json.dumps(receipt_value), encoding="utf-8")
    valid = _ledger(candidate, "receipt:receipt.json")
    release_skill._validate_evidence(
        verification,
        valid,
        candidate_digest=candidate,
        ledger_path=ledger_path,
    )


def test_release_run_state_is_authoritative(tmp_path: Path) -> None:
    output = tmp_path / "release"
    output.mkdir()
    state = output / "run-state.json"
    state.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "run:terminal",
                "current_state": "CLOSED_FOR_DECLARED_UNIVERSE",
                "candidate_digest": "a" * 64,
                "history": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReleaseBlocked, match="must be FULL_VERIFICATION"):
        release_skill._require_run_state(
            state,
            output,
            expected_state="FULL_VERIFICATION",
            candidate_digest="a" * 64,
        )
    with pytest.raises(ReleaseBlocked, match="foreign candidate"):
        release_skill._require_run_state(
            state,
            output,
            expected_state="CLOSED_FOR_DECLARED_UNIVERSE",
            candidate_digest="b" * 64,
        )
