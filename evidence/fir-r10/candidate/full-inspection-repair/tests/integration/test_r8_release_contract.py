from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import release_skill as release_skill_module
from full_inspection_repair.contracts import canonical_digest, canonical_json
from full_inspection_repair.coverage import build_complete_coverage
from full_inspection_repair.package import InstallBlocked, build_package_manifest
from full_inspection_repair.release import (
    ReleaseBlocked,
    append_release_record,
    replay_release_history,
)
from full_inspection_repair.review import (
    build_review_packet,
    trust_root_id_for_public_key,
)
from full_inspection_repair.risk_gate import REQUIRED_DOMAINS
from release_skill import run as release_run

ISSUER = "issuer.example/r8-review"


def _with_digest(value: dict[str, object], field: str) -> dict[str, object]:
    value[field] = canonical_digest(value)
    return value


def _domains() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for dotted, status in REQUIRED_DOMAINS.items():
        group, key = dotted.split(".")
        result.setdefault(group, {})[key] = status
    return result


def _evidence_bundle(
    work: Path,
    *,
    finding_status: str = "FIXED",
) -> dict[str, object]:
    source = work / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    coverage = build_complete_coverage({"SKILL.md": b"# Demo\n"})
    candidate = build_package_manifest(source)["tree_digest"]
    scope = canonical_digest({"scope": "r8-cli"})
    verification = _with_digest(
        {
            "schema_version": 1,
            "status": "PASS",
            "failure_count": 0,
            "checks": ["windows", "linux"],
        },
        "verification_digest",
    )
    evaluator = canonical_digest({"evaluator": "independent"})
    finding = {
        "finding_id": "F-1",
        "status": finding_status,
        "impact": "NO_OBSERVED_EFFECT",
        "impact_proof": "negative-control.json",
        "verification_evidence": "test-r8-cli",
    }
    ledger = _with_digest(
        {
            "schema_version": 1,
            "scope_digest": scope,
            "required_sources": [],
            "required_sources_digest": canonical_digest([]),
            "items": [finding],
            "open_count": 0,
            "closed_count": 1,
            "missing_sources": [],
            "unexpected_sources": [],
            "residual_risks": [],
            "unresolved_ids": [],
        },
        "ledger_digest",
    )
    domains = _domains()
    matrix = _with_digest(
        {
            "schema_version": 1,
            "status": "PASS",
            "failed_count": 0,
            "scope_digest": scope,
            "candidate_digest": candidate,
            "verification_digest": verification["verification_digest"],
            "evaluator_digest": evaluator,
            "coverage_digest": coverage["coverage_digest"],
            "domains_digest": canonical_digest(domains),
        },
        "matrix_digest",
    )
    subject = {
        "scope_digest": scope,
        "candidate_digest": candidate,
        "verification_digest": verification["verification_digest"],
        "ledger_digest": ledger["ledger_digest"],
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
        "risk_gate": {"status": "PASS", "release_ready": True, "gate_digest": "a" * 64},
    }
    packet = build_review_packet(subject)
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust_root = trust_root_id_for_public_key(public_key)
    attestation = {
        "schema_version": 1,
        "producer": "producer-a",
        "reviewer": "reviewer-b",
        "verification_method": "ed25519-detached",
        "issuer": ISSUER,
        "verdict": "PASS",
        "subject_digest": packet["subject_digest"],
        "scope_digest": subject["scope_digest"],
        "candidate_digest": candidate,
        "verification_digest": subject["verification_digest"],
        "ledger_digest": ledger["ledger_digest"],
        "evaluator_digest": evaluator,
        "matrix_digest": matrix["matrix_digest"],
        "coverage_digest": coverage["coverage_digest"],
        "domains_digest": canonical_digest(domains),
        "findings_digest": canonical_digest([finding]),
        "reviewed_at": subject["reviewed_at"],
        "trust_root_id": trust_root,
    }
    attestation_bytes = canonical_json(attestation).encode("utf-8")
    signature_bytes = private_key.sign(attestation_bytes)
    evidence = {
        **subject,
    }
    return {
        "source": source,
        "candidate": candidate,
        "verification": verification,
        "ledger": ledger,
        "evidence": evidence,
        "attestation": attestation_bytes,
        "signature": signature_bytes,
        "public_key": public_key,
        "trust_root": trust_root,
        "issuer": ISSUER,
        "evaluator": evaluator,
    }


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_signature_files(work: Path, bundle: dict[str, object]) -> tuple[Path, Path, Path]:
    attestation = work / "attestation.json"
    signature = work / "reviewer.sig"
    public_key = work / "reviewer.pub"
    attestation.write_bytes(bundle["attestation"])
    signature.write_bytes(bundle["signature"])
    public_key.write_bytes(bundle["public_key"])
    return attestation, signature, public_key


def _run(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["release_skill.py", *argv])
    return release_run()


def test_r8_release_history_is_append_only_and_replayable(tmp_path: Path) -> None:
    history = tmp_path / "release-history.jsonl"
    first = append_release_record(
        history,
        {"event": "CLAIM", "status": "RELEASE_READY", "candidate_digest": "a" * 64},
    )
    second = append_release_record(
        history,
        {"event": "INSTALL", "status": "INSTALLED", "candidate_digest": "a" * 64},
    )

    replayed = replay_release_history(history)

    assert [item["sequence"] for item in replayed] == [1, 2]
    assert first["previous_record_digest"] is None
    assert second["previous_record_digest"] == first["record_digest"]

    lines = history.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["status"] = "BLOCKED"
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    history.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ReleaseBlocked, match="digest mismatch"):
        replay_release_history(history)


def test_r8_cli_review_claim_install_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _evidence_bundle(tmp_path)
    output = tmp_path / "release"
    output.mkdir()
    manifest = output / "package-manifest.json"
    verification = output / "verification.json"
    ledger = output / "risk-ledger.json"
    evidence = output / "risk-gate-evidence.json"
    _write(verification, bundle["verification"])
    _write(ledger, bundle["ledger"])
    _write(evidence, bundle["evidence"])
    attestation, signature, public_key = _write_signature_files(output, bundle)

    assert (
        _run(
            monkeypatch,
            ["package", "--source", str(bundle["source"]), "--output", str(output)],
        )
        == 0
    )
    manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
    assert manifest_value["tree_digest"] == bundle["candidate"]
    assert (
        _run(
            monkeypatch,
            [
                "review",
                "--manifest",
                str(manifest),
                "--source",
                str(bundle["source"]),
                "--verification",
                str(verification),
                "--ledger",
                str(ledger),
                "--review-evidence",
                str(evidence),
                "--verification-method",
                "ed25519-detached",
                "--attestation",
                str(attestation),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--issuer",
                str(bundle["issuer"]),
                "--trust-root",
                str(bundle["trust_root"]),
                "--evaluator",
                str(bundle["evaluator"]),
                "--producer",
                "producer-a",
                "--reviewer",
                "reviewer-b",
                "--output",
                str(output),
            ],
        )
        == 0
    )
    assert (
        _run(
            monkeypatch,
            [
                "claim",
                "--review",
                str(output / "independent-review.json"),
                "--verification-method",
                "ed25519-detached",
                "--attestation",
                str(attestation),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--issuer",
                str(bundle["issuer"]),
                "--trust-root",
                str(bundle["trust_root"]),
                "--output",
                str(output),
            ],
        )
        == 0
    )
    target = tmp_path / "installed"
    rollback = tmp_path / "rollback"
    assert (
        _run(
            monkeypatch,
            [
                "install",
                "--source",
                str(bundle["source"]),
                "--target",
                str(target),
                "--manifest",
                str(manifest),
                "--claim",
                str(output / "release-claim.json"),
                "--review",
                str(output / "independent-review.json"),
                "--verification-method",
                "ed25519-detached",
                "--attestation",
                str(attestation),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--issuer",
                str(bundle["issuer"]),
                "--trust-root",
                str(bundle["trust_root"]),
                "--rollback",
                str(rollback),
                "--output",
                str(output),
            ],
        )
        == 0
    )

    receipt = json.loads((output / "install-receipt.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "INSTALLED"
    assert receipt["post_install_digest"] == bundle["candidate"]
    assert receipt["release_history_sequence"] == 2
    assert len(replay_release_history(output / "release-history.jsonl")) == 2


def test_r8_review_rejects_self_asserted_pass_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _evidence_bundle(tmp_path, finding_status="OPEN")
    output = tmp_path / "release"
    output.mkdir()
    manifest = output / "package-manifest.json"
    verification = output / "verification.json"
    ledger = output / "risk-ledger.json"
    evidence = output / "risk-gate-evidence.json"
    _write(verification, bundle["verification"])
    _write(ledger, bundle["ledger"])
    _write(evidence, bundle["evidence"])
    attestation, signature, public_key = _write_signature_files(output, bundle)
    _run(
        monkeypatch,
        ["package", "--source", str(bundle["source"]), "--output", str(output)],
    )

    code = _run(
        monkeypatch,
        [
            "review",
            "--manifest",
            str(manifest),
            "--source",
            str(bundle["source"]),
            "--verification",
            str(verification),
            "--ledger",
            str(ledger),
            "--review-evidence",
            str(evidence),
            "--verification-method",
            "ed25519-detached",
            "--attestation",
            str(attestation),
            "--signature",
            str(signature),
            "--public-key",
            str(public_key),
            "--issuer",
            str(bundle["issuer"]),
            "--trust-root",
            str(bundle["trust_root"]),
            "--evaluator",
            str(bundle["evaluator"]),
            "--producer",
            "producer-a",
            "--reviewer",
            "reviewer-b",
            "--output",
            str(output),
        ],
    )

    assert code == 2
    blocked = json.loads(
        (output / "blocked-review.json").read_text(encoding="utf-8")
    )
    assert blocked["status"] == "BLOCKED_VERIFICATION"
    assert "strict risk gate blocked" in blocked["failures"][0]["message"]


def test_r8_cli_emits_blocked_install_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _evidence_bundle(tmp_path)
    output = tmp_path / "release"
    output.mkdir()
    manifest = output / "package-manifest.json"
    claim = output / "release-claim.json"
    review = output / "independent-review.json"
    _write(manifest, build_package_manifest(bundle["source"]))
    _write(claim, {"schema_version": 2, "claim_digest": "a" * 64})
    _write(review, {"schema_version": 2, "review_digest": "b" * 64})
    attestation, signature, public_key = _write_signature_files(output, bundle)

    def blocked_install(*args, **kwargs):
        raise InstallBlocked("post-install check failed and old install was restored")

    monkeypatch.setattr(release_skill_module, "install_package", blocked_install)
    code = _run(
        monkeypatch,
        [
            "install",
            "--source",
            str(bundle["source"]),
            "--target",
            str(tmp_path / "installed"),
            "--manifest",
            str(manifest),
            "--claim",
            str(claim),
            "--review",
            str(review),
            "--verification-method",
            "ed25519-detached",
            "--attestation",
            str(attestation),
            "--signature",
            str(signature),
            "--public-key",
            str(public_key),
            "--issuer",
            str(bundle["issuer"]),
            "--trust-root",
            str(bundle["trust_root"]),
            "--output",
            str(output),
        ],
    )

    assert code == 2
    blocked = json.loads(
        (output / "blocked-install.json").read_text(encoding="utf-8")
    )
    assert blocked["status"] == "BLOCKED_VERIFICATION"
    assert blocked["failure_code"] == "INSTALL_BLOCKED"
    assert blocked["release_history_sequence"] == 1
    assert replay_release_history(output / "release-history.jsonl")[0]["event"] == (
        "INSTALL_BLOCKED"
    )
