from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import full_inspection_repair.review as review_module
from full_inspection_repair.contracts import canonical_digest, canonical_json
from full_inspection_repair.coverage import build_complete_coverage
from full_inspection_repair.release import (
    ReleaseBlocked,
    build_release_claim,
    validate_release_claim,
)
from full_inspection_repair.review import (
    ReviewBlocked,
    build_review_packet,
    review_packet,
    trust_root_id_for_public_key,
)
from full_inspection_repair.risk_gate import REQUIRED_DOMAINS
from release_skill import run as release_run

SCOPE = "a" * 64
CANDIDATE = "c" * 64
VERIFICATION = "d" * 64
LEDGER = "e" * 64
EVALUATOR_BYTES = canonical_json({"evaluator": "review-release"}).encode("utf-8")
EVALUATOR = hashlib.sha256(EVALUATOR_BYTES).hexdigest()
ISSUER = "issuer.example/review"
HISTORY_KEY = b"r12-review-test-history-anchor-0001"


def domains() -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for dotted, status in REQUIRED_DOMAINS.items():
        group, key = dotted.split(".")
        receipt = {"status": status, "scope_digest": SCOPE}
        result.setdefault(group, {})[key] = {
            "status": status,
            "scope_digest": SCOPE,
            "runner": "r11-domain-runner",
            "environment": "linux+windows",
            "receipt": receipt,
            "receipt_sha256": canonical_digest(receipt),
        }
    return result


def finding() -> dict[str, object]:
    return {
        "finding_id": "F-1",
        "status": "FIXED",
        "impact": "NO_OBSERVED_EFFECT",
        "impact_proof": "negative-control.json",
        "verification_evidence": "test-review-release",
        "evidence_refs": [f"candidate:{CANDIDATE}"],
        "evidence_sha256": CANDIDATE,
        "closed_by": CANDIDATE,
        "closed_at": "2026-11-10T00:00:00+00:00",
    }


def subject() -> dict[str, object]:
    coverage = build_complete_coverage({"SKILL.md": b"# Demo.\n"})
    matrix: dict[str, object] = {
        "schema_version": 1,
        "status": "PASS",
        "failed_count": 0,
        "scope_digest": SCOPE,
        "candidate_digest": CANDIDATE,
        "verification_digest": VERIFICATION,
        "evaluator_digest": EVALUATOR,
        "coverage_digest": coverage["coverage_digest"],
        "domains_digest": canonical_digest(domains()),
        "requested_cases": ["F-1"],
        "checks": [
            {
                "check_id": "F-1",
                "status": "PASS",
                "candidate_digest": CANDIDATE,
                "runner": "r11-matrix-runner",
                "environment": "linux+windows",
                "receipt": {"case": "F-1", "status": "PASS"},
                "receipt_sha256": canonical_digest(
                    {"case": "F-1", "status": "PASS"}
                ),
            }
        ],
    }
    matrix["matrix_digest"] = canonical_digest(matrix)
    return {
        "scope_digest": "a" * 64,
        "candidate_digest": CANDIDATE,
        "verification_digest": VERIFICATION,
        "ledger_digest": LEDGER,
        "evaluator_digest": EVALUATOR,
        "findings": [finding()],
        "coverage": coverage,
        "matrix": matrix,
        "domains": domains(),
        "limitations": [],
        "unverified_claims": [],
        "not_run": [],
        "non_blocking_observations": [],
        "open_count": 0,
        "residual_risks": [],
        "reviewed_at": "2026-11-10T00:00:00+00:00",
    }


def signing_material(
    packet: dict[str, object],
    *,
    producer: str = "agent-a",
    reviewer: str = "agent-b",
    issuer: str = ISSUER,
    overrides: dict[str, object] | None = None,
) -> dict[str, object]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust_root = trust_root_id_for_public_key(public_key)
    signed_subject = packet["subject"]
    trust_registry = {
        "schema_version": 1,
        "reviewers": [
            {
                "reviewer": reviewer,
                "issuer": issuer,
                "verification_method": "ed25519-detached",
                "trust_root_id": trust_root,
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "status": "ACTIVE",
            }
        ],
    }
    trust_anchor = {
        "schema_version": 1,
        "policy_id": "review-release-test-anchor",
        "reviewers": trust_registry["reviewers"],
        "reviewer_registry_digest": canonical_digest(trust_registry),
        "evaluator_artifacts": [EVALUATOR],
        "history_anchor_key_sha256": [hashlib.sha256(HISTORY_KEY).hexdigest()],
        "sigstore_trust_config_sha256": [],
    }
    attestation: dict[str, object] = {
        "schema_version": 1,
        "producer": producer,
        "reviewer": reviewer,
        "verification_method": "ed25519-detached",
        "issuer": issuer,
        "verdict": "PASS",
        "subject_digest": packet["subject_digest"],
        "scope_digest": signed_subject["scope_digest"],
        "candidate_digest": signed_subject["candidate_digest"],
        "verification_digest": signed_subject["verification_digest"],
        "ledger_digest": signed_subject["ledger_digest"],
        "evaluator_digest": signed_subject["evaluator_digest"],
        "matrix_digest": signed_subject["matrix"]["matrix_digest"],
        "coverage_digest": signed_subject["coverage"]["coverage_digest"],
        "domains_digest": canonical_digest(signed_subject["domains"]),
        "findings_digest": canonical_digest(signed_subject["findings"]),
        "reviewed_at": signed_subject["reviewed_at"],
        "trust_root_id": trust_root,
        "trust_anchor_digest": canonical_digest(trust_anchor),
        "history_anchor_key_sha256": hashlib.sha256(HISTORY_KEY).hexdigest(),
    }
    if overrides:
        attestation.update(overrides)
    attestation_bytes = canonical_json(attestation).encode("utf-8")
    signature_bytes = private_key.sign(attestation_bytes)
    return {
        "attestation_bytes": attestation_bytes,
        "signature_bytes": signature_bytes,
        "public_key_bytes": public_key,
        "trust_root_id": trust_root,
        "issuer": issuer,
        "trust_registry": trust_registry,
        "trust_registry_digest": canonical_digest(trust_registry),
        "trust_anchor": trust_anchor,
        "evaluator_artifact_bytes": EVALUATOR_BYTES,
    }


def signed_review(
    *,
    producer: str = "agent-a",
    reviewer: str = "agent-b",
) -> tuple[dict[str, object], dict[str, object]]:
    packet = build_review_packet(subject())
    material = signing_material(packet, producer=producer, reviewer=reviewer)
    review = review_packet(
        producer=producer,
        reviewer=reviewer,
        packet=packet,
        attestation_bytes=material["attestation_bytes"],
        signature_bytes=material["signature_bytes"],
        public_key_bytes=material["public_key_bytes"],
        issuer=material["issuer"],
        trust_root_id=material["trust_root_id"],
        trust_registry=material["trust_registry"],
        trust_registry_digest=material["trust_registry_digest"],
        trust_anchor=material["trust_anchor"],
        evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
    )
    return review, material


def signature_args(material: dict[str, object]) -> dict[str, object]:
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


def test_no_production_verified_receipt_factory():
    assert not hasattr(review_module, "build_signature_verification_receipt")


def test_same_identity_cannot_produce_and_review():
    packet = build_review_packet(subject())
    material = signing_material(packet, producer="agent-a", reviewer="agent-a")
    with pytest.raises(ReviewBlocked, match="independent"):
        review_packet(
            producer="agent-a",
            reviewer="agent-a",
            packet=packet,
            attestation_bytes=material["attestation_bytes"],
            signature_bytes=material["signature_bytes"],
            public_key_bytes=material["public_key_bytes"],
            issuer=material["issuer"],
            trust_root_id=material["trust_root_id"],
            trust_registry=material["trust_registry"],
            trust_registry_digest=material["trust_registry_digest"],
            trust_anchor=material["trust_anchor"],
            evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        )


def test_tampered_review_packet_is_rejected():
    reviewed, material = signed_review()
    packet = build_review_packet(reviewed["subject"])
    packet["subject"]["ledger_digest"] = "a" * 64

    with pytest.raises(ReviewBlocked, match="packet digest"):
        review_packet(
            producer="agent-a",
            reviewer="agent-b",
            packet=packet,
            attestation_bytes=material["attestation_bytes"],
            signature_bytes=material["signature_bytes"],
            public_key_bytes=material["public_key_bytes"],
            issuer=material["issuer"],
            trust_root_id=material["trust_root_id"],
            trust_registry=material["trust_registry"],
            trust_registry_digest=material["trust_registry_digest"],
            trust_anchor=material["trust_anchor"],
            evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        )


def test_exact_attestation_bytes_and_issuer_are_bound():
    packet = build_review_packet(subject())
    material = signing_material(packet)
    with pytest.raises(ReviewBlocked, match="signature verification failed"):
        review_packet(
            producer="agent-a",
            reviewer="agent-b",
            packet=packet,
            attestation_bytes=material["attestation_bytes"] + b" ",
            signature_bytes=material["signature_bytes"],
            public_key_bytes=material["public_key_bytes"],
            issuer=material["issuer"],
            trust_root_id=material["trust_root_id"],
            trust_registry=material["trust_registry"],
            trust_registry_digest=material["trust_registry_digest"],
            trust_anchor=material["trust_anchor"],
            evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        )
    with pytest.raises(ReviewBlocked, match="issuer mismatch"):
        review_packet(
            producer="agent-a",
            reviewer="agent-b",
            packet=packet,
            attestation_bytes=material["attestation_bytes"],
            signature_bytes=material["signature_bytes"],
            public_key_bytes=material["public_key_bytes"],
            issuer="different-issuer",
            trust_root_id=material["trust_root_id"],
            trust_registry=material["trust_registry"],
            trust_registry_digest=material["trust_registry_digest"],
            trust_anchor=material["trust_anchor"],
            evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("candidate_digest", "1" * 64),
        ("ledger_digest", "2" * 64),
        ("matrix_digest", "3" * 64),
        ("coverage_digest", "4" * 64),
    ],
)
def test_signed_attestation_claims_cannot_disagree_with_subject(
    field: str, value: str
) -> None:
    packet = build_review_packet(subject())
    material = signing_material(packet, overrides={field: value})

    with pytest.raises(ReviewBlocked, match=field):
        review_packet(
            producer="agent-a",
            reviewer="agent-b",
            packet=packet,
            attestation_bytes=material["attestation_bytes"],
            signature_bytes=material["signature_bytes"],
            public_key_bytes=material["public_key_bytes"],
            issuer=material["issuer"],
            trust_root_id=material["trust_root_id"],
            trust_registry=material["trust_registry"],
            trust_registry_digest=material["trust_registry_digest"],
            trust_anchor=material["trust_anchor"],
            evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        )


def test_release_requires_independent_pass():
    reviewed, material = signed_review()
    claim = build_release_claim(reviewed, **signature_args(material))

    assert claim["status"] == "RELEASE_READY"
    assert claim["state"] == "CLOSED_FOR_DECLARED_UNIVERSE"
    assert claim["verification_method"] == "ed25519-detached"
    validate_release_claim(claim, expected_candidate_digest=CANDIDATE)


def test_release_claim_cannot_be_created_from_review_json_alone():
    reviewed, _ = signed_review()

    with pytest.raises(ReleaseBlocked, match="verification material is incomplete"):
        build_release_claim(reviewed)


def test_release_rejects_attestation_that_is_stale_after_open_risk_edit():
    review, material = signed_review()
    review["subject"]["open_count"] = 1
    review["subject_digest"] = canonical_digest(review["subject"])
    review["open_count"] = 1
    review.pop("review_digest")
    review["review_digest"] = canonical_digest(review)
    with pytest.raises(ReleaseBlocked, match="subject_digest"):
        build_release_claim(review, **signature_args(material))


def test_producer_alias_and_bad_signature_are_rejected() -> None:
    packet = build_review_packet(subject())
    material = signing_material(packet, reviewer="Agent-B")
    with pytest.raises(ReviewBlocked, match="independent"):
        review_packet(
            producer="agent-b",
            reviewer="Agent-B",
            packet=packet,
            attestation_bytes=material["attestation_bytes"],
            signature_bytes=material["signature_bytes"],
            public_key_bytes=material["public_key_bytes"],
            issuer=material["issuer"],
            trust_root_id=material["trust_root_id"],
            trust_registry=material["trust_registry"],
            trust_registry_digest=material["trust_registry_digest"],
            trust_anchor=material["trust_anchor"],
            evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        )
    bad_signature = bytearray(material["signature_bytes"])
    bad_signature[0] ^= 1
    with pytest.raises(ReviewBlocked, match="signature verification failed"):
        review_packet(
            producer="agent-a",
            reviewer="Agent-B",
            packet=packet,
            attestation_bytes=material["attestation_bytes"],
            signature_bytes=bytes(bad_signature),
            public_key_bytes=material["public_key_bytes"],
            issuer=material["issuer"],
            trust_root_id=material["trust_root_id"],
            trust_registry=material["trust_registry"],
            trust_registry_digest=material["trust_registry_digest"],
            trust_anchor=material["trust_anchor"],
            evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        )


def test_wrong_public_key_cannot_claim_frozen_trust_root() -> None:
    packet = build_review_packet(subject())
    material = signing_material(packet)
    other = signing_material(packet)
    with pytest.raises(ReviewBlocked, match="does not match the trust root"):
        review_packet(
            producer="agent-a",
            reviewer="agent-b",
            packet=packet,
            attestation_bytes=material["attestation_bytes"],
            signature_bytes=material["signature_bytes"],
            public_key_bytes=other["public_key_bytes"],
            issuer=material["issuer"],
            trust_root_id=material["trust_root_id"],
            trust_registry=material["trust_registry"],
            trust_registry_digest=material["trust_registry_digest"],
            trust_anchor=material["trust_anchor"],
            evaluator_artifact_bytes=material["evaluator_artifact_bytes"],
        )


def test_release_cli_turns_bad_manifest_into_blocked_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{", encoding="utf-8")
    evaluator = tmp_path / "evaluator.json"
    evaluator.write_bytes(EVALUATOR_BYTES)
    output = tmp_path / "output"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "release_skill.py",
            "review",
            "--manifest",
            str(manifest),
            "--source",
            str(source),
            "--verification",
            str(tmp_path / "verification.json"),
            "--ledger",
            str(tmp_path / "ledger.json"),
            "--review-evidence",
            str(tmp_path / "evidence.json"),
            "--attestation",
            str(tmp_path / "attestation.json"),
            "--signature",
            str(tmp_path / "signature.bin"),
            "--public-key",
            str(tmp_path / "reviewer.pub"),
            "--issuer",
            ISSUER,
            "--trust-root",
            "sha256:" + "a" * 64,
            "--trust-registry",
            str(tmp_path / "trust.json"),
            "--trust-registry-digest",
            "0" * 64,
            "--run-state",
            str(output / "run-state.json"),
            "--evaluator-artifact",
            str(evaluator),
            "--producer",
            "producer",
            "--reviewer",
            "reviewer",
            "--output",
            str(output),
        ],
    )

    assert release_run() == 2
    receipt = json.loads((output / "blocked-review.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "BLOCKED_VERIFICATION"
    assert receipt["failure_code"] == "EVIDENCE_PARSE"
    observation = json.loads(
        (output / "observations.jsonl").read_text(encoding="utf-8")
    )
    assert observation["source_phase"] == "REVIEW"
    assert observation["source_run_id"] == "run:unavailable"
    journal_manifest = json.loads(
        (output / "observation-journal-manifest.json").read_text(encoding="utf-8")
    )
    assert journal_manifest["status"] == "PASS"
    assert journal_manifest["record_count"] == 1
