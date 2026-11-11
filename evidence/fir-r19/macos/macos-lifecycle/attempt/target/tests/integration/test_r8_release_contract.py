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

import release_skill as release_skill_module
from full_inspection_repair.contracts import (
    canonical_digest,
    canonical_json,
    schema_digest,
)
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
HISTORY_KEY = b"r8-release-history-anchor-key-0001"
EVALUATOR_BYTES = canonical_json({"evaluator": "independent"}).encode("utf-8")
TEST_TRUST_ANCHOR: dict[str, object] | None = None


def _with_digest(value: dict[str, object], field: str) -> dict[str, object]:
    value[field] = canonical_digest(value)
    return value


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
            "checks": ["windows", "linux", "macos"],
        },
        "verification_digest",
    )
    evaluator = hashlib.sha256(EVALUATOR_BYTES).hexdigest()
    evaluator_artifact = work / "evaluator.json"
    evaluator_artifact.write_bytes(EVALUATOR_BYTES)
    finding = {
        "schema_version": 1,
        "risk_id": "F-1",
        "invariant_id": "release-contract",
        "defect_class_id": "release.contract",
        "taxonomy_category_id": "INCONSISTENCY",
        "subject_id": "r8-cli",
        "source_id": "source:F-1",
        "severity": "High",
        "message": "contract fixture",
        "mechanism": "negative control",
        "affected_refs": ["SKILL.md"],
        "root_cause_id": "ROOT-CLI",
        "status": finding_status,
        "evidence_refs": [f"candidate:{candidate}"],
        "evidence_sha256": candidate,
        "closed_by": candidate,
        "closed_at": "2026-11-10T00:00:00+00:00",
        "verification_check": "test:r8-cli",
        "residual_risk": None,
    }
    if finding_status == "OPEN":
        finding.update(
            {
                "closed_by": None,
                "closed_at": None,
                "verification_check": None,
            }
        )
    required_sources = ["source:F-1"]
    ledger = _with_digest(
        {
            "schema_version": 1,
            "scope_digest": scope,
            "finding_schema_digest": schema_digest("finding"),
            "risk_ledger_schema_digest": schema_digest("risk-ledger"),
            "required_sources": required_sources,
            "required_sources_digest": canonical_digest(required_sources),
            "observed_sources": required_sources,
            "items": [finding],
            "open_count": 1 if finding_status == "OPEN" else 0,
            "closed_count": 0 if finding_status == "OPEN" else 1,
            "missing_sources": [],
            "unexpected_sources": [],
            "residual_risks": [],
            "unresolved_ids": [],
        },
        "ledger_digest",
    )
    domains = _domains(scope)
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
    trust_registry = {
        "schema_version": 1,
        "reviewers": [
            {
                "reviewer": "reviewer-b",
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
        "policy_id": "r8-cli-test-anchor",
        "reviewers": trust_registry["reviewers"],
        "reviewer_registry_digest": canonical_digest(trust_registry),
        "evaluator_artifacts": [evaluator],
        "history_anchor_key_sha256": [hashlib.sha256(HISTORY_KEY).hexdigest()],
        "sigstore_trust_config_sha256": [],
    }
    attestation["trust_anchor_digest"] = canonical_digest(trust_anchor)
    attestation["history_anchor_key_sha256"] = hashlib.sha256(HISTORY_KEY).hexdigest()
    attestation_bytes = canonical_json(attestation).encode("utf-8")
    signature_bytes = private_key.sign(attestation_bytes)
    global TEST_TRUST_ANCHOR
    TEST_TRUST_ANCHOR = trust_anchor
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
        "trust_registry": trust_registry,
        "trust_registry_digest": canonical_digest(trust_registry),
        "trust_anchor": trust_anchor,
        "evaluator_artifact": evaluator_artifact,
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


def _write_release_support(
    work: Path,
    bundle: dict[str, object],
    *,
    state: str,
) -> tuple[Path, Path, Path]:
    registry = work / "trust-registry.json"
    _write(registry, bundle["trust_registry"])
    run_state = work / "run-state.json"
    anchor_key = work.parent / f"{work.name}-history.key"
    anchor_key.write_bytes(HISTORY_KEY)
    _write(
        run_state,
        {
            "schema_version": 1,
            "run_id": "run:r8-release",
            "current_state": state,
            "candidate_digest": bundle["candidate"],
            "history": [],
        },
    )
    return registry, run_state, anchor_key


def _run(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    assert TEST_TRUST_ANCHOR is not None
    monkeypatch.setattr(
        release_skill_module,
        "_load_release_trust_anchor",
        lambda: TEST_TRUST_ANCHOR,
    )
    monkeypatch.setattr(sys, "argv", ["release_skill.py", *argv])
    return release_run()


def test_r8_release_history_is_append_only_and_replayable(tmp_path: Path) -> None:
    history = tmp_path / "release-history.jsonl"
    first = append_release_record(
        history,
        {"event": "CLAIM", "status": "RELEASE_READY", "candidate_digest": "a" * 64},
        anchor_key=HISTORY_KEY,
    )
    second = append_release_record(
        history,
        {"event": "INSTALL", "status": "INSTALLED", "candidate_digest": "a" * 64},
        anchor_key=HISTORY_KEY,
    )

    replayed = replay_release_history(history, anchor_key=HISTORY_KEY)

    assert [item["sequence"] for item in replayed] == [1, 2]
    assert first["previous_record_digest"] is None
    assert second["previous_record_digest"] == first["record_digest"]

    lines = history.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["status"] = "BLOCKED"
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    history.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ReleaseBlocked, match="digest mismatch"):
        replay_release_history(history, anchor_key=HISTORY_KEY)


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
    registry, run_state, anchor_key = _write_release_support(
        output,
        bundle,
        state="FULL_VERIFICATION",
    )

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
                "--trust-registry",
                str(registry),
                "--trust-registry-digest",
                str(bundle["trust_registry_digest"]),
                "--run-state",
                str(run_state),
                "--evaluator-artifact",
                str(bundle["evaluator_artifact"]),
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
                "--trust-registry",
                str(registry),
                "--trust-registry-digest",
                str(bundle["trust_registry_digest"]),
                "--run-state",
                str(run_state),
                "--history-anchor-key",
                str(anchor_key),
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
                "--trust-registry",
                str(registry),
                "--trust-registry-digest",
                str(bundle["trust_registry_digest"]),
                "--run-state",
                str(run_state),
                "--history-anchor-key",
                str(anchor_key),
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
    assert receipt["release_history_sequence"] == 3
    assert (
        len(
            replay_release_history(
                output / "release-history.jsonl",
                anchor_key=HISTORY_KEY,
            )
        )
        == 3
    )


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
    registry, run_state, _anchor_key = _write_release_support(
        output,
        bundle,
        state="FULL_VERIFICATION",
    )
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
            "--trust-registry",
            str(registry),
            "--trust-registry-digest",
            str(bundle["trust_registry_digest"]),
            "--run-state",
            str(run_state),
            "--evaluator-artifact",
            str(bundle["evaluator_artifact"]),
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
    assert "risk ledger contract violation" in blocked["failures"][0]["message"]


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
    _write(
        claim,
        {
            "schema_version": 2,
            "claim_digest": "a" * 64,
            "history_anchor_key_sha256": hashlib.sha256(HISTORY_KEY).hexdigest(),
        },
    )
    _write(review, {"schema_version": 2, "review_digest": "b" * 64})
    attestation, signature, public_key = _write_signature_files(output, bundle)
    registry, run_state, anchor_key = _write_release_support(
        output,
        bundle,
        state="INDEPENDENT_REVIEW",
    )

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
            "--trust-registry",
            str(registry),
            "--trust-registry-digest",
            str(bundle["trust_registry_digest"]),
            "--run-state",
            str(run_state),
            "--history-anchor-key",
            str(anchor_key),
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
    assert replay_release_history(
        output / "release-history.jsonl",
        anchor_key=HISTORY_KEY,
    )[0]["event"] == "INSTALL_BLOCKED"
