from __future__ import annotations

import copy
import hashlib
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import full_inspection_repair.package as package_module
from full_inspection_repair.contracts import canonical_digest, canonical_json
from full_inspection_repair.coverage import build_complete_coverage
from full_inspection_repair.package import (
    PackageError,
    build_package_manifest,
    install_package,
    verify_package_manifest,
)
from full_inspection_repair.release import build_release_claim
from full_inspection_repair.review import (
    build_review_packet,
    review_packet,
    trust_root_id_for_public_key,
)
from full_inspection_repair.risk_gate import REQUIRED_DOMAINS

ISSUER = "issuer.example/package-review"
EVALUATOR_BYTES = canonical_json({"evaluator": "package-install"}).encode("utf-8")
EVALUATOR = hashlib.sha256(EVALUATOR_BYTES).hexdigest()
HISTORY_KEY = b"r12-package-test-history-anchor-0001"


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


def _signing_material(
    packet: dict[str, object],
    *,
    producer: str = "producer-a",
    reviewer: str = "reviewer-b",
) -> dict[str, object]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    subject = packet["subject"]
    trust_root = trust_root_id_for_public_key(public_key)
    registry = {
        "schema_version": 1,
        "reviewers": [
            {
                "reviewer": reviewer,
                "issuer": ISSUER,
                "verification_method": "ed25519-detached",
                "trust_root_id": trust_root,
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "status": "ACTIVE",
            }
        ],
    }
    trust_anchor = {
        "schema_version": 1,
        "policy_id": "package-install-test-anchor",
        "reviewers": registry["reviewers"],
        "reviewer_registry_digest": canonical_digest(registry),
        "evaluator_artifacts": [EVALUATOR],
        "history_anchor_key_sha256": [hashlib.sha256(HISTORY_KEY).hexdigest()],
        "sigstore_trust_config_sha256": [],
    }
    attestation = {
        "schema_version": 1,
        "producer": producer,
        "reviewer": reviewer,
        "verification_method": "ed25519-detached",
        "issuer": ISSUER,
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
    attestation_bytes = canonical_json(attestation).encode("utf-8")
    return {
        "attestation_bytes": attestation_bytes,
        "signature_bytes": private_key.sign(attestation_bytes),
        "public_key_bytes": public_key,
        "issuer": ISSUER,
        "trust_root_id": trust_root,
        "trust_registry": registry,
        "trust_registry_digest": canonical_digest(registry),
        "trust_anchor": trust_anchor,
        "evaluator_artifact_bytes": EVALUATOR_BYTES,
    }


def _signature_args(material: dict[str, object]) -> dict[str, object]:
    return {
        "attestation_bytes": material["attestation_bytes"],
        "signature_bytes": material["signature_bytes"],
        "public_key_bytes": material["public_key_bytes"],
        "issuer": material["issuer"],
        "trust_root_id": material["trust_root_id"],
        "trust_registry": material["trust_registry"],
        "trust_registry_digest": material["trust_registry_digest"],
        "trust_anchor": material["trust_anchor"],
        "evaluator_artifact_bytes": material["evaluator_artifact_bytes"],
    }


def _bundle(
    source: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    manifest = build_package_manifest(source)
    candidate = manifest["tree_digest"]
    scope = canonical_digest({"scope": "r8-package-install"})
    verification = canonical_digest({"verification": "r8-package-install"})
    ledger = canonical_digest({"ledger": "r8-package-install"})
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
    findings = [
        {
            "finding_id": "F-1",
            "status": "FIXED",
            "impact": "NO_OBSERVED_EFFECT",
            "impact_proof": "negative-control.json",
            "verification_evidence": "test-package-install",
            "evidence_refs": [f"candidate:{candidate}"],
            "evidence_sha256": candidate,
            "closed_by": candidate,
            "closed_at": "2026-11-10T00:00:00+00:00",
        }
    ]
    subject = {
        "scope_digest": scope,
        "candidate_digest": candidate,
        "verification_digest": verification,
        "ledger_digest": ledger,
        "evaluator_digest": evaluator,
        "findings": findings,
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
    packet = build_review_packet(subject)
    material = _signing_material(packet)
    review = review_packet(
        producer="producer-a",
        reviewer="reviewer-b",
        packet=packet,
        **_signature_args(material),
    )
    claim = build_release_claim(review, **_signature_args(material))
    return manifest, review, claim, material


def test_package_manifest_detects_modified_tree(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    manifest = build_package_manifest(source)

    verify_package_manifest(source, manifest)
    (source / "SKILL.md").write_text("# Changed\n", encoding="utf-8")

    with pytest.raises(PackageError, match="file set or content"):
        verify_package_manifest(source, manifest)


def test_install_package_copies_exact_reviewed_tree(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    manifest, review, claim, material = _bundle(source)
    target = tmp_path / "installed"

    receipt = install_package(
        source,
        target,
        manifest,
        review=review,
        claim=claim,
        **_signature_args(material),
    )

    assert (target / "SKILL.md").read_text(encoding="utf-8") == "# Demo\n"
    assert receipt["install_digest"] == manifest["tree_digest"]
    assert receipt["post_install_digest"] == manifest["tree_digest"]
    assert receipt["claim_digest"] == claim["claim_digest"]
    assert receipt["preflight"]["same_volume"] is True


def test_install_replaces_existing_target_with_rollback(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    target = tmp_path / "installed"
    target.mkdir()
    manifest, review, claim, material = _bundle(source)

    (target / "old.txt").write_text("old\n", encoding="utf-8")
    rollback = tmp_path / "rollback"

    receipt = install_package(
        source,
        target,
        manifest,
        review=review,
        claim=claim,
        **_signature_args(material),
        rollback_root=rollback,
    )

    assert (target / "SKILL.md").read_text(encoding="utf-8") == "# Demo\n"
    assert (rollback / "old.txt").read_text(encoding="utf-8") == "old\n"
    assert receipt["install_digest"] == receipt["candidate_digest"]
    assert receipt["rollback_retained"] is True


def test_install_requires_current_claim_review_and_signature(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    manifest, review, claim, material = _bundle(source)
    target = tmp_path / "installed"

    with pytest.raises(PackageError, match="RELEASE_READY claim"):
        install_package(source, target, manifest)
    foreign = copy.deepcopy(claim)
    foreign["candidate_digest"] = "a" * 64
    foreign.pop("claim_digest")
    foreign["claim_digest"] = canonical_digest(foreign)
    with pytest.raises(PackageError, match="foreign candidate"):
        install_package(
            source,
            target,
            manifest,
            review=review,
            claim=foreign,
            **_signature_args(material),
        )
    tampered = dict(material)
    tampered["attestation_bytes"] = material["attestation_bytes"] + b" "
    with pytest.raises(PackageError, match="signature verification failed"):
        install_package(
            source,
            target,
            manifest,
            review=review,
            claim=claim,
            **_signature_args(tampered),
        )


def test_install_rejects_target_and_ancestor_links(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    manifest, review, claim, material = _bundle(source)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        os.symlink(real, link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    with pytest.raises(PackageError, match="symbolic link"):
        install_package(
            source,
            link,
            manifest,
            review=review,
            claim=claim,
            **_signature_args(material),
        )
    with pytest.raises(PackageError, match="symbolic link"):
        install_package(
            source,
            link / "installed",
            manifest,
            review=review,
            claim=claim,
            **_signature_args(material),
        )


def test_install_rejects_overlap_and_rollback_inside_target(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    manifest, review, claim, material = _bundle(source)

    with pytest.raises(PackageError, match="disjoint"):
        install_package(
            source,
            source / "installed",
            manifest,
            review=review,
            claim=claim,
            **_signature_args(material),
        )

    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(PackageError, match="disjoint"):
        install_package(
            source,
            target,
            manifest,
            review=review,
            claim=claim,
            **_signature_args(material),
            rollback_root=target / "rollback",
        )


def test_install_rejects_cross_volume_topology(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    manifest, review, claim, material = _bundle(source)
    target = tmp_path / "installed"
    real_identity = package_module._volume_identity

    def fake_identity(path: Path):
        if path == target.parent.resolve():
            return ("nt", "D:\\", 2)
        return real_identity(path)

    monkeypatch.setattr(package_module, "_volume_identity", fake_identity)
    with pytest.raises(PackageError, match="one volume"):
        install_package(
            source,
            target,
            manifest,
            review=review,
            claim=claim,
            **_signature_args(material),
        )


def test_smoke_failure_restores_old_install(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# New\n", encoding="utf-8")
    target = tmp_path / "installed"
    target.mkdir()
    (target / "SKILL.md").write_text("# Old\n", encoding="utf-8")
    manifest, review, claim, material = _bundle(source)
    rollback = tmp_path / "rollback"

    def fail_smoke(_: Path) -> None:
        raise RuntimeError("smoke failed")

    with pytest.raises(PackageError, match="old install was restored"):
        install_package(
            source,
            target,
            manifest,
            review=review,
            claim=claim,
            **_signature_args(material),
            rollback_root=rollback,
            smoke_check=fail_smoke,
        )

    assert (target / "SKILL.md").read_text(encoding="utf-8") == "# Old\n"
    assert not rollback.exists()
