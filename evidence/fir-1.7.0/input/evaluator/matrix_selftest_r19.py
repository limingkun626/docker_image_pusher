#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import run_full_matrix_r19 as matrix

SCRIPT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT = SCRIPT_ROOT / "matrix-tmp" / "selftest"
DEFAULT_CANDIDATE_API = Path(
    r"F:\Codex\skills-candidates\fir-full-r19-review-defect-repair-20261111\full-inspection-repair"
)


def _with_digest(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result.pop(field, None)
    result[field] = matrix.canonical_digest(result)
    return result


def _write_json(path: Path, value: dict[str, Any]) -> None:
    matrix.write_json_atomic(path, value)


def _clean_output(output: Path) -> None:
    allowed = (SCRIPT_ROOT / "matrix-tmp").resolve()
    resolved = output.resolve()
    if resolved != allowed and allowed not in resolved.parents:
        raise ValueError(f"selftest output must be below {allowed}")
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True)


def _copy_candidate_api(candidate: Path, candidate_api: Path) -> None:
    package = candidate / "scripts" / "full_inspection_repair"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    for name in ("contracts.py", "review.py", "risk_gate.py", "strict.py"):
        shutil.copy2(candidate_api / "scripts" / "full_inspection_repair" / name, package / name)
    shutil.copy2(
        candidate_api / "scripts" / "full_inspection_repair" / "verification.py",
        package / "verification.py",
    )


def _candidate_manifest(candidate: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    digests: dict[str, str] = {}
    for path in sorted(candidate.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(candidate).as_posix()
        data = path.read_bytes()
        digest = matrix.sha256_bytes(data)
        digests[relative] = digest
        files.append({"path": relative, "bytes": len(data), "sha256": digest})
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "root_name": candidate.name,
        "files": files,
        "tree_digest": matrix.canonical_digest(digests),
    }
    return _with_digest(manifest, "manifest_digest")


def _tooling_manifest(path: Path) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "scope_id": "fir-r19-matrix-selftest",
        "files": [
            {
                "path": name,
                "sha256": matrix.sha256_file(
                    SCRIPT_ROOT / name, f"selftest tooling {name}"
                ),
            }
            for name in matrix.TOOLING_FILES
        ],
    }
    manifest = _with_digest(manifest, "manifest_digest")
    _write_json(path, manifest)
    return manifest


def _make_freeze(
    *,
    path: Path,
    candidate_digest: str,
    package_manifest_path: Path,
    package_manifest: dict[str, Any],
    candidate_manifest_path: Path,
    evaluator_path: Path,
    verifier_path: Path,
    tooling_manifest_path: Path,
    tooling_manifest: dict[str, Any],
) -> dict[str, Any]:
    now = datetime.now(UTC).replace(microsecond=0)
    profile = matrix.environment_profile()
    freeze: dict[str, Any] = {
        "schema_version": 1,
        "scope_id": "fir-r19-matrix-selftest",
        "run_id": "fir-r19-matrix-selftest-r1",
        "status": "CANDIDATE_FROZEN",
        "created_at": now.isoformat(),
        "source_commit": "a" * 40,
        "candidate_digest": candidate_digest,
        "package_manifest_digest": package_manifest["manifest_digest"],
        "package_manifest_sha256": matrix.sha256_file(
            package_manifest_path, "selftest package manifest"
        ),
        "candidate_manifest_sha256": matrix.sha256_file(
            candidate_manifest_path, "selftest candidate manifest"
        ),
        "evaluator_digest": matrix.sha256_file(
            evaluator_path, "selftest evaluator"
        ),
        "verifier_digest": matrix.sha256_file(
            verifier_path, "selftest verifier"
        ),
        "tooling_manifest_digest": tooling_manifest["manifest_digest"],
        "tooling_manifest_sha256": matrix.sha256_file(
            tooling_manifest_path, "selftest tooling manifest"
        ),
        "environment": profile,
        "environment_digest": matrix.canonical_digest(profile),
    }
    freeze = _with_digest(freeze, "freeze_digest")
    _write_json(path, freeze)
    return freeze


def _junit_xml(
    platform_name: str,
    *,
    common_skipped: bool = False,
) -> str:
    cases = [
        (
            "tests.common",
            "passes",
            "skipped" if common_skipped else "pass",
        ),
        (f"tests.{platform_name}", "native", "pass"),
        (
            "tests.macos",
            "unified_log",
            "pass" if platform_name == "macos" else "skipped",
        ),
    ]
    skipped = sum(state == "skipped" for _classname, _name, state in cases)
    body: list[str] = []
    for classname, name, state in cases:
        if state == "skipped":
            body.append(
                f'<testcase classname="{classname}" name="{name}">'
                '<skipped message="platform not applicable"/></testcase>'
            )
        else:
            body.append(f'<testcase classname="{classname}" name="{name}"/>')
    return (
        '<testsuites><testsuite tests="3" failures="0" errors="0" '
        f'skipped="{skipped}">{"".join(body)}</testsuite></testsuites>\n'
    )


def _make_platform_receipt(
    path: Path,
    platform_name: str,
    candidate_digest: str,
) -> dict[str, Any]:
    stages: dict[str, Any] = {}
    details = {
        "installation": {"source_digest": candidate_digest},
        "readback": {"digest": candidate_digest},
        "atomic_activation": {"activated_atomically": True},
        "rollback": {"retained": True, "digest": candidate_digest},
        "smoke": {"digest": candidate_digest},
    }
    for stage, receipt in details.items():
        stages[stage] = {
            "status": "PASS",
            "receipt": receipt,
            "receipt_sha256": matrix.canonical_digest(receipt),
        }
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "platform": platform_name,
        "candidate_digest": candidate_digest,
        "source_digest": candidate_digest,
        "target_digest": candidate_digest,
        "installation_digest": candidate_digest,
        "readback_digest": candidate_digest,
        "rollback_digest": candidate_digest,
        "smoke_digest": candidate_digest,
        "stages": stages,
    }
    evidence = _with_digest(evidence, "receipt_digest")
    _write_json(path, evidence)
    return evidence


def _make_junit_contract(root: Path) -> Path:
    proof = root / "macos-applicability.txt"
    proof.write_text(
        "tests.macos::unified_log is applicable only on macOS.\n",
        encoding="utf-8",
    )
    contract: dict[str, Any] = {
        "schema_version": 1,
        "common_required": ["tests.common::passes"],
        "platform_required": {
            "windows": ["tests.windows::native"],
            "linux": ["tests.linux::native"],
            "macos": ["tests.macos::native"],
        },
        "platform_specific": [
            {
                "test_id": "tests.macos::unified_log",
                "applicable_platform": "macos",
                "proof": {
                    "path": proof.name,
                    "sha256": matrix.sha256_file(proof, "applicability proof"),
                },
            }
        ],
    }
    contract = _with_digest(contract, "contract_digest")
    path = root / "junit-contract.json"
    _write_json(path, contract)
    return path


def _make_macos_zip(path: Path, junit_path: Path) -> str:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(junit_path, arcname="macos-junit.xml")
    return matrix.sha256_file(path, "macOS artifact")


def _make_trust_anchor_and_power(
    root: Path,
    *,
    candidate: Path,
    freeze: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    review_module = matrix._candidate_module(candidate, "full_inspection_repair.review")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    public_key_path = root / "reviewer-public-key.bin"
    public_key_path.write_bytes(public_key)
    public_key_sha = matrix.sha256_bytes(public_key)
    trust_root_id = review_module.trust_root_id_for_public_key(public_key)
    reviewer = "selftest-reviewer@example.invalid"
    issuer = "selftest-issuer"
    reviewer_entry = {
        "reviewer": reviewer,
        "issuer": issuer,
        "verification_method": "ed25519-detached",
        "trust_root_id": trust_root_id,
        "public_key_sha256": public_key_sha,
        "status": "ACTIVE",
    }
    reviewers = [reviewer_entry]
    registry_digest = matrix.canonical_digest(
        {"schema_version": 1, "reviewers": reviewers}
    )
    history_key_sha = matrix.sha256_bytes(b"k" * 32)
    anchor: dict[str, Any] = {
        "schema_version": 1,
        "policy_id": "fir-r19-selftest",
        "reviewers": reviewers,
        "reviewer_registry_digest": registry_digest,
        "evaluator_artifacts": [
            matrix.sha256_file(Path(__file__), "selftest evaluator")
        ],
        "history_anchor_key_sha256": [history_key_sha],
        "sigstore_trust_config_sha256": [],
    }
    anchor_path = root / "trust-anchor.json"
    _write_json(anchor_path, anchor)

    power_root = root / "power"
    power_root.mkdir()
    proof_specs = {
        "arm": ("arm.json", json.dumps({"armed": True}) + "\n"),
        "cut": ("cut.log", "PDU-7 cut event cut-001\n"),
        "boot": ("boot.log", "boot_id=selftest-boot-001\n"),
        "outage_event": ("outage.csv", "event_id,observed_at\ncut-001,now\n"),
        "rollback": ("rollback.json", json.dumps({"restored": True}) + "\n"),
        "target": ("target.txt", "target readback\n"),
        "os_audit": ("usn.xml", "<audit><record id=\"1\"/></audit>\n"),
    }
    sections: dict[str, Any] = {}
    for section, (name, content) in proof_specs.items():
        proof_path = power_root / name
        proof_path.write_text(content, encoding="utf-8")
        sections[section] = {
            "receipt": name,
            "sha256": matrix.sha256_file(proof_path, f"power proof {section}"),
        }
    now = datetime.now(UTC).replace(microsecond=0)
    sections["arm"].update(
        {
            "candidate_digest": freeze["candidate_digest"],
            "snapshot_digest": matrix.canonical_digest(
                {"candidate": freeze["candidate_digest"], "mode": "ARM"}
            ),
        }
    )
    sections["cut"].update(
        {"external_source": "selftest-pdu", "event_id": "cut-001"}
    )
    sections["boot"]["boot_id"] = "selftest-boot-001"
    sections["outage_event"]["observed_at"] = now.isoformat()
    sections["rollback"]["restored_digest"] = freeze["candidate_digest"]
    sections["target"]["digest"] = freeze["candidate_digest"]
    sections["os_audit"].update(
        {
            "kind": "USN",
            "record_count": 1,
            "query_command": "fsutil usn readjournal F:",
        }
    )
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "candidate_digest": freeze["candidate_digest"],
        "status": "COMPENSATED_MID_SWAP",
        **sections,
        "started_at": (now - timedelta(seconds=10)).isoformat(),
    }
    evidence = _with_digest(evidence, "evidence_digest")
    evidence_path = power_root / "power-evidence.json"
    _write_json(evidence_path, evidence)
    attestation = {
        "schema_version": 1,
        "verification_method": "ed25519-detached",
        "verdict": "PASS",
        "subject_kind": "PHYSICAL_POWER_LOSS",
        "candidate_digest": freeze["candidate_digest"],
        "evidence_sha256": matrix.sha256_file(
            evidence_path, "power evidence"
        ),
        "reviewer": reviewer,
        "issuer": issuer,
        "trust_root_id": trust_root_id,
        "reviewed_at": now.isoformat(),
    }
    attestation_bytes = matrix.canonical_json(attestation).encode("utf-8")
    attestation_path = root / "power-attestation.json"
    attestation_path.write_bytes(attestation_bytes)
    signature_path = root / "power-attestation.sig"
    signature_path.write_bytes(private_key.sign(attestation_bytes))
    return (
        {
            "anchor_path": anchor_path,
            "anchor": anchor,
            "reviewer": reviewer,
            "issuer": issuer,
            "trust_root_id": trust_root_id,
            "public_key_path": public_key_path,
        },
        {
            "evidence_path": evidence_path,
            "attestation_path": attestation_path,
            "signature_path": signature_path,
        },
    )


def _make_bound_bundle(
    root: Path,
    *,
    freeze_path: Path,
    candidate_manifest_path: Path,
    windows_junit_path: Path,
    install_receipt_path: Path,
    verifier_path: Path,
) -> tuple[Path, Path]:
    bundle = root / "bundle"
    bundle.mkdir()
    copies = {
        "freeze.json": freeze_path,
        "candidate-manifest.json": candidate_manifest_path,
        "windows-junit.xml": windows_junit_path,
        "install-receipt.json": install_receipt_path,
        "verifier.py": verifier_path,
        "matrix-runner.py": SCRIPT_ROOT / "run_full_matrix_r19.py",
    }
    for name, source in copies.items():
        shutil.copy2(source, bundle / name)
    review = {
        "schema_version": 1,
        "status": "PASS",
        "reviewer": "selftest-reviewer",
        "candidate_digest": json.loads(
            candidate_manifest_path.read_text(encoding="utf-8")
        )["candidate_digest"],
    }
    review = _with_digest(review, "review_digest")
    _write_json(bundle / "review-receipt.json", review)
    records: list[dict[str, Any]] = []
    previous = None
    for sequence, event in enumerate(("FREEZE", "REVIEW", "CLAIM", "INSTALL"), 1):
        record = {
            "sequence": sequence,
            "previous_record_digest": previous,
            "event": event,
            "status": "PASS",
            "candidate_digest": review["candidate_digest"],
        }
        record["record_digest"] = matrix.canonical_digest(record)
        previous = record["record_digest"]
        records.append(record)
    (bundle / "release-history.jsonl").write_text(
        "".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )
    names = (
        "candidate-manifest.json",
        "freeze.json",
        "install-receipt.json",
        "matrix-runner.py",
        "release-history.jsonl",
        "review-receipt.json",
        "verifier.py",
        "windows-junit.xml",
    )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "scope_id": "fir-r19-matrix-selftest",
        "candidate_digest": review["candidate_digest"],
        "artifacts": {
            {
                "freeze.json": "freeze",
                "verifier.py": "verifier",
                "matrix-runner.py": "matrix-runner",
                "windows-junit.xml": "junit",
                "review-receipt.json": "review-receipt",
                "install-receipt.json": "install-receipt",
                "release-history.jsonl": "release-history",
                "candidate-manifest.json": "candidate-manifest",
            }[name]: {
                "path": name,
                "sha256": matrix.sha256_file(bundle / name, name),
            }
            for name in names
        },
    }
    manifest = _with_digest(manifest, "manifest_digest")
    manifest_path = bundle / "bundle-manifest.json"
    _write_json(manifest_path, manifest)
    return bundle, manifest_path


def _run_case(name: str, function) -> dict[str, Any]:
    try:
        function()
    except Exception as exc:  # noqa: BLE001 - selftest must report every case
        return {
            "case": name,
            "status": "FAIL",
            "failure": f"{type(exc).__name__}: {exc}",
        }
    return {"case": name, "status": "PASS"}


def _expect_failure(name: str, code: str, function) -> dict[str, Any]:
    try:
        function()
    except matrix.MatrixFailure as exc:
        passed = exc.code == code and bool(exc.failures)
        return {
            "case": name,
            "status": "PASS" if passed else "FAIL",
            "expected_code": code,
            "actual_code": exc.code,
            "failure_count": len(exc.failures),
        }
    except Exception as exc:  # noqa: BLE001 - selftest must report every case
        return {
            "case": name,
            "status": "FAIL",
            "expected_code": code,
            "failure": f"{type(exc).__name__}: {exc}",
        }
    return {
        "case": name,
        "status": "FAIL",
        "expected_code": code,
        "actual_code": None,
    }


def _cli_rejection(
    bundle: Path,
    manifest: Path,
    expected_code: str,
) -> tuple[bool, dict[str, Any]]:
    process = subprocess.run(
        [
            sys.executable,
            "-B",
            str(Path(__file__).resolve()),
            "--bundle-root",
            str(bundle),
            "--bundle-manifest",
            str(manifest),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    try:
        output = json.loads(process.stdout)
    except json.JSONDecodeError:
        output = {
            "status": "NON_STRUCTURED",
            "stdout": process.stdout,
            "stderr": process.stderr,
        }
    failures = output.get("failures", [])
    exact = any(
        item.get("code") == expected_code for item in failures if isinstance(item, dict)
    )
    passed = (
        process.returncode == 2
        and output.get("status") == "BLOCKED_VERIFICATION"
        and output.get("failure_code") == expected_code
        and exact
        and bool(failures)
        and "Traceback" not in process.stdout
        and "Traceback" not in process.stderr
    )
    return passed, output


def build_selftest(
    output: Path,
    *,
    candidate_api: Path,
) -> dict[str, Any]:
    _clean_output(output)
    work = output / "fixtures"
    work.mkdir()
    candidate = work / "candidate"
    candidate.mkdir()
    (candidate / "SKILL.md").write_text(
        "# Synthetic R19 matrix fixture\n",
        encoding="utf-8",
    )
    _copy_candidate_api(candidate, candidate_api)
    verifier_path = candidate / "scripts" / "full_inspection_repair" / "verification.py"
    package_manifest = _candidate_manifest(candidate)
    package_manifest_path = work / "package-manifest.json"
    _write_json(package_manifest_path, package_manifest)
    candidate_manifest: dict[str, Any] = {
        "schema_version": 1,
        "scope_id": "fir-r19-matrix-selftest",
        "run_id": "fir-r19-matrix-selftest-r1",
        "status": "CANDIDATE_FROZEN",
        "candidate_digest": package_manifest["tree_digest"],
    }
    candidate_manifest = _with_digest(candidate_manifest, "manifest_digest")
    candidate_manifest_path = work / "candidate-manifest.json"
    _write_json(candidate_manifest_path, candidate_manifest)
    tooling_manifest_path = work / "tooling-manifest.json"
    tooling_manifest = _tooling_manifest(tooling_manifest_path)
    freeze_path = work / "freeze.json"
    freeze = _make_freeze(
        path=freeze_path,
        candidate_digest=package_manifest["tree_digest"],
        package_manifest_path=package_manifest_path,
        package_manifest=package_manifest,
        candidate_manifest_path=candidate_manifest_path,
        evaluator_path=Path(__file__),
        verifier_path=verifier_path,
        tooling_manifest_path=tooling_manifest_path,
        tooling_manifest=tooling_manifest,
    )
    positive_cases: list[dict[str, Any]] = []
    positive_cases.append(
        _run_case(
            "candidate-freeze-tooling-positive",
            lambda: (
                matrix.validate_freeze(
                    freeze_path,
                    package_manifest_path=package_manifest_path,
                    evaluator_path=Path(__file__),
                    verifier_path=verifier_path,
                    tooling_manifest_path=tooling_manifest_path,
                    script_root=SCRIPT_ROOT,
                ),
                matrix.validate_environment(freeze),
                matrix.validate_candidate(
                    candidate,
                    package_manifest,
                    freeze["candidate_digest"],
                ),
                matrix.validate_candidate_manifest(
                    candidate_manifest_path,
                    freeze,
                ),
            ),
        )
    )

    junit_paths: dict[str, Path] = {}
    for platform_name in matrix.PLATFORMS:
        path = work / f"{platform_name}-junit.xml"
        path.write_text(_junit_xml(platform_name), encoding="utf-8")
        junit_paths[platform_name] = path
    contract_path = _make_junit_contract(work)
    junit = {
        platform_name: matrix.parse_junit(path)
        for platform_name, path in junit_paths.items()
    }
    positive_cases.append(
        _run_case(
            "junit-platform-reconciliation-positive",
            lambda: matrix.validate_junit_contract(contract_path, junit),
        )
    )

    install_paths: dict[str, Path] = {}
    for platform_name in matrix.PLATFORMS:
        path = work / f"{platform_name}-install.json"
        _make_platform_receipt(path, platform_name, freeze["candidate_digest"])
        install_paths[platform_name] = path
    positive_cases.append(
        _run_case(
            "three-platform-lifecycle-positive",
            lambda: matrix.validate_platform_receipts(
                install_paths,
                candidate_digest=freeze["candidate_digest"],
            ),
        )
    )

    artifact_path = work / "macos-artifact.zip"
    archive_sha = _make_macos_zip(artifact_path, junit_paths["macos"])
    junit_sha = junit["macos"]["sha256"]
    completed_at = (
        datetime.fromisoformat(freeze["created_at"]) + timedelta(minutes=1)
    ).isoformat()

    def github_transport(url: str, _token: str | None) -> dict[str, Any]:
        if "/artifacts" in url:
            return {
                "total_count": 1,
                "artifacts": [
                    {
                        "id": 99,
                        "name": "macos-matrix",
                        "digest": f"sha256:{archive_sha}",
                        "expired": False,
                    }
                ],
            }
        return {
            "id": 42,
            "run_attempt": 1,
            "repository": {"full_name": "example/r19"},
            "workflow_id": 7,
            "path": ".github/workflows/r19-matrix.yml",
            "name": "R19 matrix",
            "status": "completed",
            "conclusion": "success",
            "head_sha": freeze["source_commit"],
            "updated_at": completed_at,
        }

    positive_cases.append(
        _run_case(
            "macos-live-identity-positive",
            lambda: matrix.validate_macos_provenance(
                freeze=freeze,
                junit_sha256=junit_sha,
                artifact_path=artifact_path,
                repository="example/r19",
                run_id="42",
                artifact_id="99",
                workflow=".github/workflows/r19-matrix.yml",
                token_env="UNUSED_SELFTEST_TOKEN",
                transport=github_transport,
            ),
        )
    )

    trust_and_power, power_paths = _make_trust_anchor_and_power(
        work,
        candidate=candidate,
        freeze=freeze,
    )
    positive_cases.append(
        _run_case(
            "physical-power-signed-proof-positive",
            lambda: matrix.validate_physical_power(
                candidate=candidate,
                evidence_path=power_paths["evidence_path"],
                attestation_path=power_paths["attestation_path"],
                signature_path=power_paths["signature_path"],
                public_key_path=trust_and_power["public_key_path"],
                trust_anchor_path=trust_and_power["anchor_path"],
                reviewer=trust_and_power["reviewer"],
                issuer=trust_and_power["issuer"],
                trust_root_id=trust_and_power["trust_root_id"],
                candidate_digest=freeze["candidate_digest"],
                freeze_created_at=freeze["created_at"],
            ),
        )
    )

    bundle, bundle_manifest = _make_bound_bundle(
        work,
        freeze_path=freeze_path,
        candidate_manifest_path=candidate_manifest_path,
        windows_junit_path=junit_paths["windows"],
        install_receipt_path=install_paths["windows"],
        verifier_path=verifier_path,
    )
    positive_cases.append(
        _run_case(
            "bound-evidence-positive",
            lambda: matrix.evaluate_bound_bundle(bundle, bundle_manifest),
        )
    )

    tamper_spec = json.loads(
        (SCRIPT_ROOT / "matrix_tamper_tests_r19.json").read_text(encoding="utf-8")
    )
    tamper_cases = tamper_spec.get("cases", [])
    tamper_results: list[dict[str, Any]] = []
    tamper_work = output / "tamper"
    tamper_work.mkdir()
    for index, item in enumerate(tamper_cases):
        case_root = tamper_work / f"{index:02d}-{item['name']}"
        shutil.copytree(bundle, case_root)
        target = case_root / item["artifact"]
        target.write_bytes(target.read_bytes() + b"\n")
        passed, output_value = _cli_rejection(
            case_root,
            case_root / "bundle-manifest.json",
            item["failure_code"],
        )
        tamper_results.append(
            {
                "case": item["name"],
                "artifact": item["artifact"],
                "status": "PASS" if passed else "FAIL",
                "expected_code": item["failure_code"],
                "observed_code": output_value.get("failure_code"),
                "failure_count": len(output_value.get("failures", [])),
            }
        )

    negative_cases: list[dict[str, Any]] = []
    cache_copy = work / "candidate-cache"
    shutil.copytree(candidate, cache_copy)
    (cache_copy / "__pycache__").mkdir()
    negative_cases.append(
        _expect_failure(
            "candidate-cache-rejected",
            "CANDIDATE_CACHE",
            lambda: matrix.scan_candidate(cache_copy),
        )
    )
    hardlink_copy = work / "candidate-hardlink"
    shutil.copytree(candidate, hardlink_copy)
    source_file = hardlink_copy / "SKILL.md"
    os.link(source_file, hardlink_copy / "skill-alias.md")
    negative_cases.append(
        _expect_failure(
            "candidate-hardlink-rejected",
            "CANDIDATE_HARDLINK",
            lambda: matrix.scan_candidate(hardlink_copy),
        )
    )
    path_manifest = dict(package_manifest)
    path_manifest["files"] = list(package_manifest["files"]) + [
        {"path": "../escape.txt", "bytes": 1, "sha256": "0" * 64}
    ]
    path_manifest = _with_digest(path_manifest, "manifest_digest")
    negative_cases.append(
        _expect_failure(
            "manifest-path-escape-rejected",
            "CANDIDATE_PATH_ESCAPE",
            lambda: matrix._package_files(path_manifest),
        )
    )
    tree_copy = work / "candidate-tree-drift"
    shutil.copytree(candidate, tree_copy)
    (tree_copy / "SKILL.md").write_text("# drift\n", encoding="utf-8")
    negative_cases.append(
        _expect_failure(
            "candidate-tree-drift-rejected",
            "TREE_DRIFT",
            lambda: matrix.validate_candidate(
                tree_copy,
                package_manifest,
                package_manifest["tree_digest"],
            ),
        )
    )
    bad_freeze = dict(freeze)
    bad_freeze["run_id"] = "drifted-run"
    negative_cases.append(
        _expect_failure(
            "freeze-self-digest-drift-rejected",
            "FREEZE_DRIFT",
            lambda: matrix.validate_freeze(
                work / "missing-freeze.json",
                package_manifest_path=package_manifest_path,
                evaluator_path=Path(__file__),
                verifier_path=verifier_path,
                tooling_manifest_path=tooling_manifest_path,
                script_root=SCRIPT_ROOT,
            )
            if False
            else matrix._declared_digest(
                bad_freeze,
                "freeze_digest",
                "FREEZE_DRIFT",
                "candidate freeze",
            ),
        )
    )
    bad_manifest = dict(package_manifest)
    bad_manifest["files"] = list(package_manifest["files"])[:-1]
    negative_cases.append(
        _expect_failure(
            "manifest-drift-rejected",
            "MANIFEST_DRIFT",
            lambda: matrix._package_files(bad_manifest),
        )
    )
    bad_environment = dict(freeze)
    bad_environment["environment"] = {
        **freeze["environment"],
        "machine": "drifted-machine",
    }
    bad_environment["environment_digest"] = matrix.canonical_digest(
        bad_environment["environment"]
    )
    negative_cases.append(
        _expect_failure(
            "environment-drift-rejected",
            "ENVIRONMENT_DRIFT",
            lambda: matrix.validate_environment(bad_environment),
        )
    )
    skipped_common_path = work / "windows-common-skipped.xml"
    skipped_common_path.write_text(
        _junit_xml("windows", common_skipped=True),
        encoding="utf-8",
    )
    skipped_common = {
        "windows": matrix.parse_junit(skipped_common_path),
        "linux": junit["linux"],
        "macos": junit["macos"],
    }
    negative_cases.append(
        _expect_failure(
            "common-required-skip-rejected",
            "JUNIT_RECONCILIATION",
            lambda: matrix.validate_junit_contract(contract_path, skipped_common),
        )
    )
    missing_proof_contract = dict(json.loads(contract_path.read_text(encoding="utf-8")))
    missing_proof_contract["platform_specific"] = [
        {
            **missing_proof_contract["platform_specific"][0],
            "proof": {
                "path": "missing-proof.txt",
                "sha256": "0" * 64,
            },
        }
    ]
    missing_proof_contract = _with_digest(
        missing_proof_contract, "contract_digest"
    )
    missing_proof_path = work / "missing-proof-contract.json"
    _write_json(missing_proof_path, missing_proof_contract)
    negative_cases.append(
        _expect_failure(
            "platform-skip-proof-missing-rejected",
            "APPLICABILITY_PROOF",
            lambda: matrix.validate_junit_contract(
                missing_proof_path,
                junit,
            ),
        )
    )

    external_blockers = [
        _expect_failure(
            "real-sigstore-remains-blocked",
            "SIGSTORE_EVIDENCE_MISSING",
            lambda: matrix.validate_real_sigstore(
                candidate=candidate,
                freeze=freeze,
                review_path=work / "missing-review.json",
                attestation_path=work / "missing-attestation.json",
                bundle_path=work / "missing-bundle.json",
                verifier_path=work / "missing-verifier.exe",
                trust_config_path=work / "missing-trust-config.json",
                trust_anchor_path=trust_and_power["anchor_path"],
                reviewer=None,
                issuer=None,
                cert_identity=None,
                oidc_issuer=None,
                snapshot_root=work / "missing-snapshot",
            ),
        ),
        _expect_failure(
            "real-macos-provenance-remains-blocked",
            "MACOS_PROVENANCE_UNAVAILABLE",
            lambda: matrix.validate_macos_provenance(
                freeze=freeze,
                junit_sha256=junit_sha,
                artifact_path=artifact_path,
                repository=None,
                run_id=None,
                artifact_id=None,
                workflow=None,
                token_env="UNUSED_SELFTEST_TOKEN",
            ),
        ),
        _expect_failure(
            "real-physical-power-remains-blocked",
            "POWER_EVIDENCE_MISSING",
            lambda: matrix.validate_physical_power(
                candidate=candidate,
                evidence_path=power_paths["evidence_path"],
                attestation_path=power_paths["attestation_path"],
                signature_path=power_paths["signature_path"],
                public_key_path=trust_and_power["public_key_path"],
                trust_anchor_path=trust_and_power["anchor_path"],
                reviewer=None,
                issuer=None,
                trust_root_id=None,
                candidate_digest=freeze["candidate_digest"],
                freeze_created_at=freeze["created_at"],
            ),
        ),
    ]
    failures = [
        item
        for item in (
            positive_cases
            + tamper_results
            + negative_cases
            + external_blockers
        )
        if item.get("status") != "PASS"
    ]
    if len(tamper_results) != 8:
        failures.append(
            {
                "case": "tamper-count",
                "status": "FAIL",
                "failure": f"expected 8 tamper cases, got {len(tamper_results)}",
            }
        )
    result: dict[str, Any] = {
        "schema_version": 1,
        "scope_id": "fir-r19-matrix-selftest",
        "run_id": "fir-r19-matrix-selftest-r1",
        "status": "SELFTEST_PASS" if not failures else "BLOCKED_SELFTEST",
        "release_ready": False,
        "formal_matrix_emitted": False,
        "positive_cases": positive_cases,
        "tamper_cases": tamper_results,
        "negative_cases": negative_cases,
        "external_formal_gates": external_blockers,
        "external_gate_note": (
            "Synthetic positives qualify internal checks only. The formal runner "
            "still requires live GitHub provenance, a real Sigstore verifier result, "
            "and a real physical-outage attestation."
        ),
        "failure_count": len(failures),
        "failures": failures,
    }
    result["selftest_digest"] = matrix.canonical_digest(result)
    _write_json(output / "MATRIX-SELFTEST.json", result)
    return result


def bundle_mode(bundle_root: Path, manifest: Path) -> int:
    try:
        result = matrix.evaluate_bound_bundle(bundle_root, manifest)
    except matrix.MatrixFailure as exc:
        blocked: dict[str, Any] = {
            "schema_version": 1,
            "status": "BLOCKED_VERIFICATION",
            "release_ready": False,
            "canonical_matrix_emitted": False,
            "failure_code": exc.code,
            "failure_count": len(exc.failures),
            "failures": exc.failures,
        }
        blocked["blocked_digest"] = matrix.canonical_digest(blocked)
        print(json.dumps(blocked, ensure_ascii=False, sort_keys=True), flush=True)
        return 2
    except Exception as exc:  # noqa: BLE001 - evaluator CLI boundary
        blocked = {
            "schema_version": 1,
            "status": "BLOCKED_VERIFICATION",
            "failure_code": "INTERNAL_ERROR",
            "failures": [
                {
                    "code": "INTERNAL_ERROR",
                    "message": f"{type(exc).__name__}: {exc}",
                }
            ],
        }
        print(json.dumps(blocked, ensure_ascii=False, sort_keys=True), flush=True)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the FIR R19 matrix pre-freeze self-test")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--candidate-api", default=str(DEFAULT_CANDIDATE_API))
    parser.add_argument("--bundle-root")
    parser.add_argument("--bundle-manifest")
    args = parser.parse_args(argv)
    if args.bundle_root or args.bundle_manifest:
        if not args.bundle_root or not args.bundle_manifest:
            print(
                json.dumps(
                    {
                        "status": "BLOCKED_VERIFICATION",
                        "failure_code": "ARGUMENT_ERROR",
                        "failures": [
                            {
                                "code": "ARGUMENT_ERROR",
                                "message": "bundle mode needs both root and manifest",
                            }
                        ],
                    },
                    sort_keys=True,
                )
            )
            return 2
        return bundle_mode(
            Path(args.bundle_root).resolve(),
            Path(args.bundle_manifest).resolve(),
        )
    try:
        result = build_selftest(
            Path(args.output).resolve(),
            candidate_api=Path(args.candidate_api).resolve(),
        )
    except Exception as exc:  # noqa: BLE001 - CLI must emit a structured failure
        result = {
            "schema_version": 1,
            "status": "BLOCKED_SELFTEST",
            "failure_code": "INTERNAL_ERROR",
            "failures": [
                {
                    "code": "INTERNAL_ERROR",
                    "message": f"{type(exc).__name__}: {exc}",
                }
            ],
        }
    print(
        json.dumps(
            {
                "status": result["status"],
                "failure_count": result.get("failure_count", len(result.get("failures", []))),
                "output": str(Path(args.output).resolve() / "MATRIX-SELFTEST.json"),
            },
            sort_keys=True,
        )
    )
    return 0 if result["status"] == "SELFTEST_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

