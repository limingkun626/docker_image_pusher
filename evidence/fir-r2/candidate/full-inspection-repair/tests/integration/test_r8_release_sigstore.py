from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import canonical_digest, canonical_json
from full_inspection_repair.coverage import build_complete_coverage
from full_inspection_repair.package import (
    PackageError,
    build_package_manifest,
    install_package,
)
from full_inspection_repair.release import build_release_claim
from full_inspection_repair.review import (
    SIGSTORE_VERIFIER,
    ReviewBlocked,
    build_review_packet,
    review_packet,
    sigstore_trust_root_id,
)
from full_inspection_repair.risk_gate import REQUIRED_DOMAINS

IDENTITY = (
    "https://github.com/example/release/.github/workflows/publish.yml"
    "@refs/tags/v1.0.0"
)
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PRODUCER = "producer-a"
EVALUATOR_BYTES = canonical_json({"evaluator": "r8-sigstore"}).encode("utf-8")
EVALUATOR = hashlib.sha256(EVALUATOR_BYTES).hexdigest()
HISTORY_KEY = b"r12-sigstore-test-history-anchor-0001"


def _client_trust_config_bytes() -> bytes:
    return canonical_json(
        {
            "mediaType": "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json",
            "trustedRoot": {
                "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                "tlogs": [{"baseUrl": "https://rekor.invalid"}],
                "certificateAuthorities": [{"uri": "https://fulcio.invalid"}],
            },
            "signingConfig": {
                "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
                "caUrls": [{"url": "https://fulcio.invalid", "majorApiVersion": 1}],
                "rekorTlogUrls": [
                    {"url": "https://rekor.invalid", "majorApiVersion": 1}
                ],
            },
        }
    ).encode("utf-8")


def _domains(scope: str) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for dotted, status in REQUIRED_DOMAINS.items():
        group, key = dotted.split(".")
        receipt = {"status": status, "scope_digest": scope}
        result.setdefault(group, {})[key] = {
            "status": status,
            "scope_digest": scope,
            "runner": "r11-domain-runner",
            "environment": "linux+windows+macos",
            "receipt": receipt,
            "receipt_sha256": canonical_digest(receipt),
        }
    return result


def _subject(source: Path) -> tuple[dict[str, object], dict[str, object]]:
    manifest = build_package_manifest(source)
    candidate = manifest["tree_digest"]
    scope = canonical_digest({"scope": "r8-sigstore"})
    verification = canonical_digest({"verification": "r8-sigstore"})
    ledger = canonical_digest({"ledger": "r8-sigstore"})
    evaluator = EVALUATOR
    coverage = build_complete_coverage({"SKILL.md": b"# Demo\n"})
    domains = _domains(scope)
    matrix: dict[str, object] = {
        "schema_version": 1,
        "status": "PASS",
        "failed_count": 0,
        "scope_digest": scope,
        "candidate_digest": candidate,
        "verification_digest": verification,
        "evaluator_digest": evaluator,
        "coverage_digest": coverage["coverage_digest"],
        "domains_digest": canonical_digest(domains),
        "requested_cases": ["F-1"],
        "checks": [
            {
                "check_id": "F-1",
                "status": "PASS",
                "candidate_digest": candidate,
                "runner": "r11-matrix-runner",
                "environment": "linux+windows+macos",
                "receipt": {"case": "F-1", "status": "PASS"},
                "receipt_sha256": canonical_digest(
                    {"case": "F-1", "status": "PASS"}
                ),
            }
        ],
    }
    matrix["matrix_digest"] = canonical_digest(matrix)
    finding = {
        "finding_id": "F-1",
        "status": "FIXED",
        "impact": "NO_OBSERVED_EFFECT",
        "impact_proof": "negative-control.json",
        "verification_evidence": "test-r8-sigstore",
        "evidence_refs": [f"candidate:{candidate}"],
        "evidence_sha256": candidate,
        "closed_by": candidate,
        "closed_at": "2026-11-10T00:00:00+00:00",
    }
    subject = {
        "scope_digest": scope,
        "candidate_digest": candidate,
        "verification_digest": verification,
        "ledger_digest": ledger,
        "evaluator_digest": evaluator,
        "findings": [finding],
        "coverage": coverage,
        "matrix": matrix,
        "domains": domains,
        "limitations": [],
        "unverified_claims": [],
        "not_run": [],
        "non_blocking_observations": [],
        "open_count": 0,
        "residual_risks": [],
        "reviewed_at": "2026-11-10T00:00:00+00:00",
    }
    return manifest, subject


def _material(tmp_path: Path, subject: dict[str, object]) -> dict[str, object]:
    packet = build_review_packet(subject)
    bundle = tmp_path / "review.sigstore"
    bundle.write_bytes(b'{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}')
    verifier = tmp_path / "sigstore"
    verifier.write_bytes(b"external-verifier")
    trust_config_bytes = _client_trust_config_bytes()
    trust_config = tmp_path / "trust-config.json"
    trust_config.write_bytes(trust_config_bytes)
    trust_root = sigstore_trust_root_id(IDENTITY, OIDC_ISSUER)
    registry = {
        "schema_version": 1,
        "reviewers": [
            {
                "reviewer": IDENTITY,
                "issuer": OIDC_ISSUER,
                "verification_method": SIGSTORE_VERIFIER,
                "trust_root_id": trust_root,
                "verifier_sha256": hashlib.sha256(verifier.read_bytes()).hexdigest(),
                "verifier_version": "4.5.1",
                "verifier_closure": [
                    {
                        "path": str(verifier),
                        "sha256": hashlib.sha256(verifier.read_bytes()).hexdigest(),
                        "role": "verifier",
                    }
                ],
                "status": "ACTIVE",
            }
        ],
    }
    trust_anchor = {
        "schema_version": 1,
        "policy_id": "r8-sigstore-test-anchor",
        "reviewers": registry["reviewers"],
        "reviewer_registry_digest": canonical_digest(registry),
        "evaluator_artifacts": [EVALUATOR],
        "history_anchor_key_sha256": [hashlib.sha256(HISTORY_KEY).hexdigest()],
        "sigstore_trust_config_sha256": [
            hashlib.sha256(trust_config_bytes).hexdigest()
        ],
    }
    attestation = {
        "schema_version": 1,
        "producer": PRODUCER,
        "reviewer": IDENTITY,
        "verification_method": SIGSTORE_VERIFIER,
        "issuer": OIDC_ISSUER,
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
        "trust_root_id": trust_root,
        "trust_anchor_digest": canonical_digest(trust_anchor),
        "history_anchor_key_sha256": hashlib.sha256(HISTORY_KEY).hexdigest(),
    }
    attestation_path = tmp_path / "reviewer-attestation.json"
    attestation_path.write_bytes(canonical_json(attestation).encode("utf-8"))
    return {
        "packet": packet,
        "attestation_bytes": attestation_path.read_bytes(),
        "attestation_path": attestation_path,
        "sigstore_bundle": bundle,
        "sigstore_verifier": verifier,
        "cert_identity": IDENTITY,
        "oidc_issuer": OIDC_ISSUER,
        "trust_registry": registry,
        "trust_registry_digest": canonical_digest(registry),
        "trust_anchor": trust_anchor,
        "evaluator_artifact_bytes": EVALUATOR_BYTES,
        "trust_config_path": trust_config,
        "snapshot_root": tmp_path / "sigstore-snapshots",
    }


def _completed(
    command: list[str],
    returncode: int = 0,
    stdout: str = "",
):
    return subprocess.CompletedProcess(command, returncode, stdout, "")


def _review(tmp_path: Path, returncode: int = 0):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    manifest, subject = _subject(source)
    material = _material(tmp_path, subject)
    commands: list[list[str]] = []

    def runner(command: list[str]):
        commands.append(command)
        if command[-1] == "--version":
            return _completed(command, 0, "sigstore 4.5.1")
        return _completed(command, returncode)

    review = review_packet(
        producer=PRODUCER,
        reviewer=IDENTITY,
        packet=material["packet"],
        verification_method=SIGSTORE_VERIFIER,
        attestation_bytes=material["attestation_bytes"],
        attestation_path=material["attestation_path"],
        sigstore_bundle=material["sigstore_bundle"],
        sigstore_verifier=material["sigstore_verifier"],
        cert_identity=IDENTITY,
        oidc_issuer=OIDC_ISSUER,
        trust_registry=material["trust_registry"],
        trust_registry_digest=material["trust_registry_digest"],
        trust_anchor=material["trust_anchor"],
        evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        trust_config_path=material["trust_config_path"],
        snapshot_root=material["snapshot_root"],
        runner=runner,
    )
    return source, manifest, material, review, commands, runner


def test_sigstore_cli_protocol_and_claim_install(tmp_path: Path) -> None:
    source, manifest, material, review, commands, runner = _review(tmp_path)
    claim = build_release_claim(
        review,
        verification_method=SIGSTORE_VERIFIER,
        attestation_bytes=material["attestation_bytes"],
        attestation_path=material["attestation_path"],
        sigstore_bundle=material["sigstore_bundle"],
        sigstore_verifier=material["sigstore_verifier"],
        cert_identity=IDENTITY,
        oidc_issuer=OIDC_ISSUER,
        trust_registry=material["trust_registry"],
        trust_registry_digest=material["trust_registry_digest"],
        trust_anchor=material["trust_anchor"],
        evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        trust_config_path=material["trust_config_path"],
        snapshot_root=material["snapshot_root"],
        runner=runner,
    )
    target = tmp_path / "installed"
    receipt = install_package(
        source,
        target,
        manifest,
        claim=claim,
        review=review,
        verification_method=SIGSTORE_VERIFIER,
        attestation_bytes=material["attestation_bytes"],
        attestation_path=material["attestation_path"],
        sigstore_bundle=material["sigstore_bundle"],
        sigstore_verifier=material["sigstore_verifier"],
        cert_identity=IDENTITY,
        oidc_issuer=OIDC_ISSUER,
        trust_registry=material["trust_registry"],
        trust_registry_digest=material["trust_registry_digest"],
        trust_anchor=material["trust_anchor"],
        evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        trust_config_path=material["trust_config_path"],
        snapshot_root=material["snapshot_root"],
        verification_runner=runner,
    )

    assert claim["verification_method"] == SIGSTORE_VERIFIER
    assert claim["bundle_sha256"] == review["external_signature"]["bundle_sha256"]
    assert receipt["status"] == "INSTALLED"
    assert receipt["bundle_sha256"] == claim["bundle_sha256"]
    verification_commands = [command for command in commands if command[-1] != "--version"]
    assert len(verification_commands) == 3
    for command in verification_commands:
        assert command[1] == "--trust-config"
        assert command[3:5] == ["verify", "identity"]
        assert Path(command[0]) != material["sigstore_verifier"]
        assert Path(command[command.index("--bundle") + 1]) != material["sigstore_bundle"]
        assert Path(command[command.index("--trust-config") + 1]) != material[
            "trust_config_path"
        ]
        assert Path(command[-1]) != material["attestation_path"]
        assert str(material["snapshot_root"]) in command[0]


def test_sigstore_nonzero_exit_cannot_create_verified_receipt(
    tmp_path: Path,
) -> None:
    with pytest.raises(ReviewBlocked, match="rc=1"):
        _review(tmp_path, returncode=1)


def test_sigstore_claim_binds_bundle_digest_to_install(tmp_path: Path) -> None:
    source, manifest, material, review, _, runner = _review(tmp_path)
    claim = build_release_claim(
        review,
        verification_method=SIGSTORE_VERIFIER,
        attestation_bytes=material["attestation_bytes"],
        attestation_path=material["attestation_path"],
        sigstore_bundle=material["sigstore_bundle"],
        sigstore_verifier=material["sigstore_verifier"],
        cert_identity=IDENTITY,
        oidc_issuer=OIDC_ISSUER,
        trust_registry=material["trust_registry"],
        trust_registry_digest=material["trust_registry_digest"],
        trust_anchor=material["trust_anchor"],
        evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        trust_config_path=material["trust_config_path"],
        snapshot_root=material["snapshot_root"],
        runner=runner,
    )
    claim["bundle_sha256"] = "0" * 64
    claim.pop("claim_digest")
    claim["claim_digest"] = canonical_digest(claim)

    with pytest.raises(PackageError, match="Sigstore bundle"):
        install_package(
            source,
            tmp_path / "installed",
            manifest,
            claim=claim,
            review=review,
            verification_method=SIGSTORE_VERIFIER,
            attestation_bytes=material["attestation_bytes"],
            attestation_path=material["attestation_path"],
            sigstore_bundle=material["sigstore_bundle"],
            sigstore_verifier=material["sigstore_verifier"],
            cert_identity=IDENTITY,
            oidc_issuer=OIDC_ISSUER,
            trust_registry=material["trust_registry"],
            trust_registry_digest=material["trust_registry_digest"],
            trust_anchor=material["trust_anchor"],
            evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
            trust_config_path=material["trust_config_path"],
            snapshot_root=material["snapshot_root"],
            verification_runner=runner,
        )


def test_real_sigstore_verifier_offline_bundle() -> None:
    verifier = os.environ.get("FIR_R8_SIGSTORE_VERIFIER")
    bundle = os.environ.get("FIR_R8_SIGSTORE_BUNDLE")
    artifact = os.environ.get("FIR_R8_SIGSTORE_ARTIFACT")
    identity = os.environ.get("FIR_R8_SIGSTORE_IDENTITY")
    issuer = os.environ.get("FIR_R8_SIGSTORE_ISSUER")
    if not all((verifier, bundle, artifact, identity, issuer)):
        pytest.skip("real Sigstore bundle environment is not configured")
    command = [
        verifier,
        "verify",
        "identity",
        "--offline",
        "--bundle",
        bundle,
        "--cert-identity",
        identity,
        "--cert-oidc-issuer",
        issuer,
        artifact,
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)

    assert completed.returncode == 0, completed.stderr
