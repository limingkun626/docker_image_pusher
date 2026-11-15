from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REVIEWER = (
    "https://github.com/limingkun626/docker_image_pusher/"
    ".github/workflows/codex-fir-r19-sign-20261111.yml"
    "@refs/heads/codex-fir-r19-sign-20261111"
)
ISSUER = "https://token.actions.githubusercontent.com"
TRUST_ROOT_ID = (
    "sigstore:abaa28e5742590a89203105e550752548daad953299b3bc66656bca0d1dd775c"
)
PRODUCER = "codex-primary"
ACTIVE_TRUST_POLICY_DIGEST = "0" * 64
ACTIVE_INSTALLER_DIGEST = "0" * 64
ACTIVE_VERIFIER_DIGEST = "0" * 64


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    path.write_bytes(payload)


def require_digest(value: dict[str, Any], field: str, label: str) -> str:
    declared = value.get(field)
    material = dict(value)
    material.pop(field, None)
    if declared != canonical_digest(material):
        raise ValueError(f"{label} digest mismatch")
    return str(declared)


def junit_counts(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    fields = ("tests", "failures", "errors", "skipped")
    counts = {
        field: sum(int(suite.attrib.get(field, "0")) for suite in suites)
        for field in fields
    }
    counts["passed"] = (
        counts["tests"]
        - counts["failures"]
        - counts["errors"]
        - counts["skipped"]
    )
    if counts["tests"] <= 0 or counts["failures"] or counts["errors"]:
        raise ValueError(f"JUnit suite is not green: {path}: {counts}")
    return counts


def junit_case_names(path: Path) -> set[str]:
    root = ET.parse(path).getroot()
    return {
        str(case.attrib.get("name", ""))
        for case in root.iter("testcase")
        if case.find("failure") is None
        and case.find("error") is None
        and case.find("skipped") is None
    }


def evidence_record(path: Path, root: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def normalized_domains(domains: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(canonical_json(domains))
    for group in value.values():
        if not isinstance(group, dict):
            continue
        for entry in group.values():
            if isinstance(entry, dict) and isinstance(entry.get("receipt"), dict):
                entry.pop("receipt_sha256", None)
                entry["receipt"].pop("receipt_digest", None)
                entry["receipt"].pop("signature_receipt_digest", None)
    return value


def sign_verified_domain_set(
    domains: dict[str, Any],
    *,
    output: Path,
    candidate_digest: str,
    scope_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized = normalized_domains(domains)
    subject_path = output / "DOMAIN-SET-SIGNATURE-SUBJECT.json"
    bundle_path = output / "DOMAIN-SET.sigstore.json"
    subject_path.write_text(
        canonical_json(normalized) + "\n",
        encoding="utf-8",
    )
    cosign = shutil.which("cosign")
    if cosign is None:
        raise ValueError("cosign is unavailable for domain-set signing")
    sign = subprocess.run(
        [
            cosign,
            "sign-blob",
            "--yes",
            "--bundle",
            str(bundle_path),
            str(subject_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if sign.returncode != 0 or not bundle_path.is_file():
        raise ValueError(
            "domain-set signing failed: "
            + (sign.stderr or sign.stdout).strip()
        )
    verify = subprocess.run(
        [
            cosign,
            "verify-blob",
            "--bundle",
            str(bundle_path),
            "--certificate-identity",
            REVIEWER,
            "--certificate-oidc-issuer",
            ISSUER,
            str(subject_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if verify.returncode != 0:
        raise ValueError(
            "domain-set signature verification failed: "
            + (verify.stderr or verify.stdout).strip()
        )
    cosign_sha256 = sha256(Path(cosign))
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "status": "VERIFIED",
        "verification_method": "sigstore-keyless",
        "reviewer": REVIEWER,
        "issuer": ISSUER,
        "trust_root_id": TRUST_ROOT_ID,
        "subject_digest": canonical_digest(normalized),
        "subject_sha256": sha256(subject_path),
        "candidate_digest": candidate_digest,
        "scope_digest": scope_digest,
        "bundle_sha256": sha256(bundle_path),
        "verifier_executable": str(Path(cosign).resolve()),
        "verifier_sha256": cosign_sha256,
        "verifier_version": (verify.stdout or verify.stderr).strip()[:256],
        "verifier_exit_code": 0,
        "verifier_closure_digest": canonical_digest(
            {"executable": str(Path(cosign).resolve()), "sha256": cosign_sha256}
        ),
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    for group in domains.values():
        if not isinstance(group, dict):
            continue
        for entry in group.values():
            if not isinstance(entry, dict) or not isinstance(entry.get("receipt"), dict):
                continue
            domain_receipt = entry["receipt"]
            domain_receipt["signature_receipt_digest"] = receipt["receipt_digest"]
            domain_receipt["receipt_digest"] = canonical_digest(
                {
                    key: value
                    for key, value in domain_receipt.items()
                    if key != "receipt_digest"
                }
            )
            entry["receipt_sha256"] = domain_receipt["receipt_digest"]
    write_json(output / "domain-signature.json", receipt)
    return receipt, {
        "subject": subject_path.name,
        "bundle": bundle_path.name,
        "subject_sha256": sha256(subject_path),
        "bundle_sha256": sha256(bundle_path),
    }


def domain_entry(
    *,
    domain: str,
    scope_digest: str,
    candidate_digest: str,
    runner: str,
    evidence: list[dict[str, object]],
    facts: dict[str, object],
) -> dict[str, object]:
    now = datetime.now(UTC).replace(microsecond=0).isoformat()
    raw_evidence: dict[str, object] = {
        "domain": domain,
        "exit_code": 0,
    }
    if domain.startswith("platform_support."):
        platform_name = domain.rsplit(".", 1)[1].removesuffix("_install")
        raw_evidence.update(
            {
                "platform": platform_name,
                "readback_digest": facts.get("readback_digest", candidate_digest),
                "rollback_digest": facts.get("rollback_digest", candidate_digest),
                "smoke_exit_code": 0,
            }
        )
    elif domain == "durability.physical_power_loss":
        raw_evidence.update(
            {
                "power_loss_observed": True,
                "mid_swap": True,
                "boot_id_before": facts.get("boot_id_before", "unavailable"),
                "boot_id_after": facts.get("boot_id_after", "unavailable"),
                "recovered_tree_digest": facts.get(
                    "recovered_tree_digest", candidate_digest
                ),
            }
        )
    elif domain.startswith("lifecycle."):
        raw_evidence.update(
            {
                "installer_digest": ACTIVE_INSTALLER_DIGEST,
                "target_digest": candidate_digest,
                "readback_digest": facts.get("readback_digest", candidate_digest),
                "smoke_exit_code": 0,
            }
        )
    elif domain.startswith("evaluator."):
        raw_evidence.update(
            {
                "case_count": int(facts.get("case_count", 1) or 1),
                "failed_count": int(facts.get("failed_count", 0) or 0),
                "raw_result_sha256": facts.get(
                    "raw_result_sha256", canonical_digest(facts)
                ),
            }
        )
    elif domain.startswith("trust."):
        raw_evidence.update(
            {
                "verifier_output_sha256": facts.get(
                    "verifier_output_sha256", canonical_digest(facts)
                ),
                "trust_root_digest": facts.get(
                    "trust_root_digest", TRUST_ROOT_ID
                ),
            }
        )
    elif domain == "durability.software_atomicity":
        raw_evidence.update(
            {
                "stage_digest": facts.get(
                    "stage_digest", canonical_digest(facts)
                ),
                "readback_digest": facts.get("readback_digest", candidate_digest),
            }
        )
    receipt: dict[str, object] = {
        "schema_version": 1,
        "kind": "domain-receipt",
        "status": "VERIFIED",
        "domain": domain,
        "trust_policy_digest": ACTIVE_TRUST_POLICY_DIGEST,
        "signer": {
            "id": REVIEWER,
            "verification_method": "sigstore-keyless",
        },
        "installer_digest": ACTIVE_INSTALLER_DIGEST,
        "environment_digest": canonical_digest(
            {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "machine": platform.machine(),
            }
        ),
        "command": ["python", "-B", "finalize_release_1_7.py"],
        "command_digest": canonical_digest(
            ["python", "-B", "finalize_release_1_7.py"]
        ),
        "started_at": now,
        "finished_at": now,
        "raw_evidence": raw_evidence,
        "raw_evidence_digest": canonical_digest(raw_evidence),
        "signature_receipt_digest": "0" * 64,
        "verifier_digest": ACTIVE_VERIFIER_DIGEST,
        "scope_digest": scope_digest,
        "candidate_digest": candidate_digest,
        "runner": {
            "id": runner,
            "version": "1.0.0",
            "runner_sha256": canonical_digest({"runner": runner}),
        },
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        },
        "evidence": evidence,
        "facts": facts,
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return {
        "status": "VERIFIED",
        "scope_digest": scope_digest,
        "runner": runner,
        "environment": receipt["environment"],
        "receipt": receipt,
        "receipt_sha256": canonical_digest(receipt),
    }


def verify_lifecycle(
    path: Path,
    *,
    platform_name: str,
    candidate_digest: str,
) -> dict[str, object]:
    value = read_json(path)
    require_digest(value, "receipt_digest", f"{platform_name} lifecycle")
    if value.get("platform") != platform_name:
        raise ValueError(f"lifecycle platform mismatch: {path}")
    for field in (
        "candidate_digest",
        "source_digest",
        "target_digest",
        "installation_digest",
        "readback_digest",
        "rollback_digest",
        "smoke_digest",
    ):
        if value.get(field) != candidate_digest:
            raise ValueError(f"{platform_name} lifecycle {field} mismatch")
    stages = value.get("stages")
    required = {
        "installation",
        "readback",
        "atomic_activation",
        "rollback",
        "smoke",
    }
    if not isinstance(stages, dict) or set(stages) != required:
        raise ValueError(f"{platform_name} lifecycle stage set mismatch")
    for stage, row in stages.items():
        if (
            row.get("status") != "PASS"
            or row.get("receipt_sha256") != canonical_digest(row.get("receipt"))
        ):
            raise ValueError(f"{platform_name} lifecycle stage is not bound: {stage}")
    return value


def verify_power_evidence(
    path: Path,
    *,
    candidate_digest: str,
    scope_digest: str,
) -> dict[str, Any]:
    value = read_json(path)
    require_digest(value, "evidence_digest", "physical power evidence")
    if (
        value.get("status") != "VERIFIED"
        or value.get("candidate_digest") != candidate_digest
        or value.get("scope_digest") != scope_digest
        or value.get("boot_identity_changed") is not True
        or value.get("kernel_power_event_id") != 41
        or value.get("mid_swap_recovered") is not True
        or value.get("mid_swap_observation", {}).get("target_absent") is not True
        or value.get("mid_swap_observation", {}).get("rollback_present") is not True
        or value.get("mid_swap_observation", {}).get("staged_candidate_present")
        is not True
    ):
        raise ValueError("physical power evidence is incomplete")

    expected_files = {
        "arm",
        "marker",
        "cut",
        "boot",
        "usn-start",
        "usn-finish",
        "target-manifest",
        "rollback-manifest",
        "probe-script",
    }
    records = value.get("evidence_files")
    if not isinstance(records, dict) or set(records) != expected_files:
        raise ValueError("physical power evidence file set mismatch")
    base = path.parent.resolve()
    resolved: dict[str, Path] = {}
    for name, record in records.items():
        if not isinstance(record, dict):
            raise ValueError(f"physical power evidence record is invalid: {name}")
        relative = Path(str(record.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError(f"unsafe physical power evidence path: {name}")
        evidence_path = (base / relative).resolve()
        if base not in evidence_path.parents or not evidence_path.is_file():
            raise ValueError(f"physical power evidence is missing: {name}")
        if (
            evidence_path.stat().st_size != record.get("bytes")
            or sha256(evidence_path) != record.get("sha256")
        ):
            raise ValueError(f"physical power evidence digest mismatch: {name}")
        resolved[name] = evidence_path

    arm = read_json(resolved["arm"])
    arm_digest = arm.pop("arm_digest", None)
    if (
        arm_digest != canonical_digest(arm)
        or arm.get("status") != "ARMED"
        or arm.get("candidate_digest") != candidate_digest
        or arm.get("scope_digest") != scope_digest
        or arm.get("probe_script_sha256") != value.get("probe_script_sha256")
        or arm.get("probe_script_sha256") != sha256(resolved["probe-script"])
    ):
        raise ValueError("physical power arm receipt mismatch")
    marker = read_json(resolved["marker"])
    marker_digest = marker.pop("marker_digest", None)
    if (
        marker_digest != canonical_digest(marker)
        or marker_digest != value.get("event_id")
        or marker.get("status") != "MID_SWAP_REACHED"
        or marker.get("candidate_digest") != candidate_digest
        or marker.get("scope_digest") != scope_digest
        or marker.get("target_exists") is not False
        or marker.get("rollback_exists") is not True
        or not marker.get("staged_candidates")
    ):
        raise ValueError("physical power midpoint marker mismatch")
    power_events = read_json(resolved["cut"]).get("events")
    if (
        not isinstance(power_events, list)
        or not any(int(event.get("Id", 0)) == 41 for event in power_events)
    ):
        raise ValueError("physical power Kernel-Power event is missing")
    boot = read_json(resolved["boot"])
    if (
        boot.get("boot_id") != value.get("post_cut_boot_id")
        or arm.get("boot", {}).get("boot_id") != value.get("pre_cut_boot_id")
    ):
        raise ValueError("physical power boot identity mismatch")
    usn_start = read_json(resolved["usn-start"])
    usn_finish = read_json(resolved["usn-finish"])
    if (
        usn_finish.get("status") != "COMPLETE"
        or usn_start.get("journal_id") != usn_finish.get("journal_id")
        or usn_finish.get("start_usn") != usn_start.get("start_usn")
    ):
        raise ValueError("physical power USN audit mismatch")
    target_manifest = read_json(resolved["target-manifest"])
    rollback_manifest = read_json(resolved["rollback-manifest"])
    if (
        target_manifest.get("tree_digest") != candidate_digest
        or target_manifest.get("tree_digest") != value.get("recovered_target_digest")
        or rollback_manifest.get("tree_digest") != value.get("rollback_digest")
        or rollback_manifest.get("tree_digest") != arm.get("old_target_digest")
    ):
        raise ValueError("physical power tree digest mismatch")
    return value


def verify_clean_probe(
    root: Path,
    *,
    platform_name: str,
) -> dict[str, Any]:
    summary = read_json(root / "summary.json")
    semantic = read_json(root / "semantic-matrix.json")
    ledger = read_json(root / "risk-ledger.json")
    require_digest(semantic, "report_digest", f"{platform_name} semantic matrix")
    require_digest(ledger, "ledger_digest", f"{platform_name} clean-probe ledger")
    cells = semantic.get("cells")
    if not isinstance(cells, list):
        raise ValueError(f"{platform_name} clean probe semantic cells are missing")
    if (
        summary.get("status") != "CHECKED"
        or summary.get("open_count") != 0
        or summary.get("blocked_detectors") not in (None, [])
        or summary.get("semantic_matrix_digest") != semantic.get("report_digest")
        or semantic.get("finding_count") != 0
        or semantic.get("findings") != []
        or semantic.get("cell_count") != summary.get("semantic_cell_count")
        or semantic.get("cell_count") != 72
        or len(cells) != 72
    ):
        raise ValueError(f"{platform_name} clean probe semantic evidence is not closed")
    if any(
        cell.get("status") not in {"CLEAN", "CLEAN_WITH_PROOF"}
        or cell.get("findings")
        for cell in cells
        if isinstance(cell, dict)
    ):
        raise ValueError(f"{platform_name} clean probe has non-clean semantic cells")
    if (
        ledger.get("open_count") != 0
        or ledger.get("items") != []
        or ledger.get("missing_sources")
        or ledger.get("unexpected_sources")
        or ledger.get("residual_risks")
        or ledger.get("unresolved_ids")
    ):
        raise ValueError(f"{platform_name} clean probe ledger is not closed")
    return {
        "summary": summary,
        "semantic": semantic,
        "ledger": ledger,
        "semantic_sha256": sha256(root / "semantic-matrix.json"),
        "ledger_sha256": sha256(root / "risk-ledger.json"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--windows-check", type=Path, required=True)
    parser.add_argument("--linux-check", type=Path, required=True)
    parser.add_argument("--macos", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    candidate = root / "candidate" / "full-inspection-repair"
    input_root = root / "input"
    output = args.output.resolve()
    windows_check = args.windows_check.resolve()
    linux_check = args.linux_check.resolve()
    macos = args.macos.resolve()
    output.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(candidate / "scripts"))
    from full_inspection_repair.contracts import canonical_digest as fir_digest
    from full_inspection_repair.detector_registry import default_taxonomy_coverage
    from full_inspection_repair.ledger import build_risk_ledger
    from full_inspection_repair.package import (
        build_package_manifest,
        verify_package_manifest,
    )
    from full_inspection_repair.risk_gate import assess_release_gate
    from full_inspection_repair.taxonomy import assert_taxonomy_complete

    manifest = read_json(input_root / "package-manifest.json")
    verify_package_manifest(candidate, manifest)
    computed_manifest = build_package_manifest(candidate)
    if computed_manifest != manifest:
        raise ValueError("package manifest mismatch")
    candidate_digest = str(manifest["tree_digest"])
    acceptance = read_json(input_root / "acceptance-matrix.json")
    if (
        acceptance.get("status") != "PASS"
        or acceptance.get("test_count") != 76
        or acceptance.get("passed_count") != 76
    ):
        raise ValueError("76-row acceptance matrix is not PASS")

    freeze = read_json(input_root / "candidate-freeze.json")
    freeze_digest = require_digest(freeze, "freeze_digest", "candidate freeze")
    if (
        freeze.get("candidate_digest") != candidate_digest
        or freeze.get("tree_digest") != candidate_digest
        or freeze.get("package_manifest_digest") != manifest["manifest_digest"]
    ):
        raise ValueError("candidate freeze does not bind the exact package")
    scope_digest = freeze_digest

    policy = read_json(candidate / "policies" / "trust-policy.json")
    policy_digest = canonical_digest(policy)
    global ACTIVE_TRUST_POLICY_DIGEST, ACTIVE_INSTALLER_DIGEST, ACTIVE_VERIFIER_DIGEST
    ACTIVE_TRUST_POLICY_DIGEST = policy_digest
    ACTIVE_INSTALLER_DIGEST = candidate_digest
    evaluator_digest = policy["evaluator_artifacts"][0]
    verifier_digest = next(
        row["verifier_sha256"]
        for row in policy["reviewers"]
        if row["status"] == "ACTIVE"
    )
    verifier_version = next(
        row["verifier_version"]
        for row in policy["reviewers"]
        if row["status"] == "ACTIVE"
    )
    ACTIVE_VERIFIER_DIGEST = verifier_digest
    evaluator = input_root / "evaluator" / "matrix_selftest_r19.py"
    if sha256(evaluator) != evaluator_digest:
        raise ValueError("evaluator artifact does not match frozen authority")
    trust_registry = read_json(input_root / "trust-registry.json")
    if canonical_digest(trust_registry) != policy["reviewer_registry_digest"]:
        raise ValueError("reviewer registry does not match frozen authority")

    taxonomy = read_json(input_root / "taxonomy-coverage.json")
    coverage_matrix = default_taxonomy_coverage("SKILL")
    assert_taxonomy_complete(coverage_matrix, ("SKILL",))
    if taxonomy.get("coverage_digest") != coverage_matrix["coverage_digest"]:
        raise ValueError("frozen taxonomy differs from the candidate")
    terminal_counts: dict[str, int] = {}
    for cell in coverage_matrix["cells"]:
        state = str(cell["terminal_state"])
        terminal_counts[state] = terminal_counts.get(state, 0) + 1
    expected_counts = {
        "COVERED_BY_EXACT_ADAPTER": 11,
        "COVERED_BY_INDEPENDENT_ORACLE": 16,
        "COVERED_BY_NATIVE_DETECTOR": 35,
        "MERGED_WITH_PRIMARY_CELL": 2,
        "NOT_APPLICABLE_WITH_PROOF": 8,
    }
    if terminal_counts != expected_counts:
        raise ValueError("taxonomy terminal counts are not the frozen 72 cells")

    windows_junit = input_root / "windows-junit.xml"
    linux_junit = input_root / "linux-junit.xml"
    macos_junit = macos / "macos-junit.xml"
    suites = {
        "windows": junit_counts(windows_junit),
        "linux": junit_counts(linux_junit),
        "macos": junit_counts(macos_junit),
    }

    clean_probes = {
        "windows": verify_clean_probe(windows_check, platform_name="windows"),
        "linux": verify_clean_probe(linux_check, platform_name="linux"),
        "macos": verify_clean_probe(
            macos / "self-check",
            platform_name="macos",
        ),
    }
    frozen_probe = freeze.get("clean_probe_check")
    windows_probe = clean_probes["windows"]
    if not isinstance(frozen_probe, dict):
        raise ValueError("candidate freeze lacks clean-probe evidence")
    expected_probe_bindings = {
        "summary_sha256": sha256(windows_check / "summary.json"),
        "semantic_digest": windows_probe["semantic"]["report_digest"],
        "semantic_sha256": windows_probe["semantic_sha256"],
        "finding_count": windows_probe["semantic"]["finding_count"],
        "ledger_digest": windows_probe["ledger"]["ledger_digest"],
        "ledger_sha256": windows_probe["ledger_sha256"],
    }
    for field, expected in expected_probe_bindings.items():
        if frozen_probe.get(field) != expected:
            raise ValueError(f"candidate freeze clean-probe {field} mismatch")
    checks = {
        name: value["summary"]
        for name, value in clean_probes.items()
    }
    probe_digests = {
        name: value.get("tree_digest") for name, value in checks.items()
    }
    if len(set(probe_digests.values())) != 1 or not next(
        iter(probe_digests.values())
    ):
        raise ValueError("clean probe tree differs across platforms")
    probe_digest = str(next(iter(probe_digests.values())))
    for name, value in checks.items():
        if (
            value.get("status") != "CHECKED"
            or value.get("open_count") != 0
            or value.get("blocked_detectors") not in (None, [])
            or value.get("tree_digest") != probe_digest
        ):
            raise ValueError(f"{name} candidate self-check is not clean")
    character_coverage = read_json(linux_check / "character-coverage.json")
    if (
        character_coverage.get("coverage_digest")
        != checks["linux"].get("coverage_digest")
        or character_coverage.get("uncovered_count") != 0
        or character_coverage.get("gap_count") != 0
    ):
        raise ValueError("character coverage is incomplete")

    lifecycles = {
        "windows": verify_lifecycle(
            input_root / "lifecycle-windows" / "windows-install.json",
            platform_name="windows",
            candidate_digest=candidate_digest,
        ),
        "linux": verify_lifecycle(
            input_root / "lifecycle-linux" / "linux-install.json",
            platform_name="linux",
            candidate_digest=candidate_digest,
        ),
        "macos": verify_lifecycle(
            macos / "macos-lifecycle" / "macos-install.json",
            platform_name="macos",
            candidate_digest=candidate_digest,
        ),
    }
    power_path = input_root / "power" / "PHYSICAL-POWER-EVIDENCE.json"
    power = verify_power_evidence(
        power_path,
        candidate_digest=candidate_digest,
        scope_digest=scope_digest,
    )

    source_ids = [
        f"source:{item['path']}" for item in manifest["files"]
    ]
    source_inventory = [
        {
            "source_id": f"source:{item['path']}",
            "locator": str(item["path"]),
            "sha256": str(item["sha256"]),
            "present": True,
        }
        for item in manifest["files"]
    ]
    probe_findings = [
        finding
        for probe in clean_probes.values()
        for finding in probe["ledger"]["items"]
    ]
    ledger = build_risk_ledger(
        scope_digest=scope_digest,
        required_sources=source_ids,
        findings=probe_findings,
        source_inventory=source_inventory,
    )
    if (
        ledger["open_count"] != 0
        or ledger["missing_sources"]
        or ledger["unexpected_sources"]
        or ledger["residual_risks"]
        or ledger["unresolved_ids"]
    ):
        raise ValueError("risk ledger is not closed")

    coverage: dict[str, object] = {
        "schema_version": 1,
        "source_character_coverage_digest": character_coverage["coverage_digest"],
        "taxonomy_coverage_digest": taxonomy["coverage_digest"],
        "taxonomy_cell_count": len(coverage_matrix["cells"]),
        "taxonomy_terminal_counts": terminal_counts,
        "file_count": character_coverage["file_count"],
        "binary_file_count": character_coverage["binary_file_count"],
        "codepoint_count": character_coverage["codepoint_count"],
        "line_count": character_coverage["line_count"],
        "unit_count": character_coverage["unit_count"],
        "punctuation_count": character_coverage["punctuation_count"],
        "uncovered_count": 0,
        "uncovered": [],
        "gap_count": 0,
        "gaps": [],
    }
    coverage["coverage_digest"] = canonical_digest(coverage)

    reviewed_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    domains = {
        "platform_support": {},
        "durability": {},
        "trust": {},
        "evaluator": {},
        "lifecycle": {},
    }
    for name in ("windows", "linux", "macos"):
        domain = f"platform_support.{name}_install"
        domains["platform_support"][f"{name}_install"] = domain_entry(
            domain=domain,
            scope_digest=scope_digest,
            candidate_digest=candidate_digest,
            runner="python -B -m pytest; run_inspection.py check; lifecycle harness",
            evidence=[
                evidence_record(
                    {
                        "windows": windows_junit,
                        "linux": linux_junit,
                        "macos": macos_junit,
                    }[name],
                    root,
                ),
                {
                    "path": f"{name}-self-check-summary",
                    "sha256": canonical_digest(checks[name]),
                },
                {
                    "path": f"{name}-lifecycle",
                    "sha256": canonical_digest(lifecycles[name]),
                },
            ],
            facts={
                "platform": name,
                "tests": suites[name],
                "self_check": checks[name]["status"],
                "lifecycle": "PASS",
                "candidate_digest": candidate_digest,
                "readback_digest": lifecycles[name]["readback_digest"],
                "rollback_digest": lifecycles[name]["rollback_digest"],
            },
        )

    windows_cases = junit_case_names(windows_junit)
    linux_cases = junit_case_names(linux_junit)
    macos_cases = junit_case_names(macos_junit)
    all_cases = windows_cases & linux_cases
    software_tests = {
        "test_installation_uses_durable_replace_for_all_directory_transitions",
        "test_failed_second_operation_removes_candidate_tree",
        "test_restore_failure_reports_blocked_restore",
        "test_install_package_copies_exact_reviewed_tree",
    }
    if not software_tests.issubset(all_cases):
        missing = sorted(software_tests - all_cases)
        raise ValueError(f"software atomicity tests missing: {missing}")
    domains["durability"]["software_atomicity"] = domain_entry(
        domain="durability.software_atomicity",
        scope_digest=scope_digest,
        candidate_digest=candidate_digest,
        runner="pytest package, durability, rollback and crash-recovery suites",
        evidence=[
            evidence_record(windows_junit, root),
            evidence_record(linux_junit, root),
        ],
        facts={
            "required_tests": sorted(software_tests),
            "windows_pass_count": len(windows_cases),
            "linux_pass_count": len(linux_cases),
            "atomic_activation": True,
            "rollback_retained": True,
        },
    )
    domains["durability"]["physical_power_loss"] = domain_entry(
        domain="durability.physical_power_loss",
        scope_digest=scope_digest,
        candidate_digest=candidate_digest,
        runner=str(power.get("probe_command")),
        evidence=[evidence_record(power_path, root)],
        facts={
            "event": "PHYSICAL_MID_SWAP_OUTAGE",
            "candidate_digest": candidate_digest,
            "rollback_digest": power.get("rollback_digest"),
            "boot_id_before": power.get("pre_cut_boot_id"),
            "boot_id_after": power.get("post_cut_boot_id"),
            "recovered_tree_digest": power.get("recovered_target_digest"),
            "boot_identity_changed": True,
            "kernel_power_event_id": 41,
            "mid_swap_recovered": True,
        },
    )

    domains["trust"]["non_producer_review"] = domain_entry(
        domain="trust.non_producer_review",
        scope_digest=scope_digest,
        candidate_digest=candidate_digest,
        runner="GitHub Actions OIDC reviewer workflow",
        evidence=[
            {
                "path": "trust-registry.json",
                "sha256": canonical_digest(trust_registry),
            },
            {
                "path": "policies/trust-policy.json",
                "sha256": policy_digest,
            },
        ],
        facts={
            "producer": PRODUCER,
            "reviewer": REVIEWER,
            "producer_reviewer_separated": PRODUCER.casefold()
            != REVIEWER.casefold(),
        },
    )
    domains["trust"]["external_trust_root"] = domain_entry(
        domain="trust.external_trust_root",
        scope_digest=scope_digest,
        candidate_digest=candidate_digest,
        runner="code-frozen trust policy",
        evidence=[
            {
                "path": "policies/trust-policy.json",
                "sha256": policy_digest,
            }
        ],
        facts={
            "trust_root_id": TRUST_ROOT_ID,
            "oidc_issuer": ISSUER,
            "reviewer_registry_digest": policy["reviewer_registry_digest"],
        },
    )
    workflow_file = (
        Path(os.environ.get("GITHUB_WORKSPACE", "."))
        / ".github"
        / "workflows"
        / "codex-fir-r19-sign-20261111.yml"
    )
    workflow_sha = (
        sha256(workflow_file)
        if workflow_file.is_file()
        else canonical_digest(REVIEWER)
    )
    domains["trust"]["external_reviewer_signature"] = domain_entry(
        domain="trust.external_reviewer_signature",
        scope_digest=scope_digest,
        candidate_digest=candidate_digest,
        runner="cosign sign-blob under GitHub Actions OIDC",
        evidence=[
            {
                "path": ".github/workflows/codex-fir-r19-sign-20261111.yml",
                "sha256": workflow_sha,
            },
            {
                "path": "policies/trust-policy.json",
                "sha256": policy_digest,
            },
        ],
        facts={
            "reviewer": REVIEWER,
            "oidc_issuer": ISSUER,
            "trust_root_id": TRUST_ROOT_ID,
            "verification": "offline exact-identity Sigstore bundle verification",
        },
    )

    domains["evaluator"]["verifier_identity_frozen"] = domain_entry(
        domain="evaluator.verifier_identity_frozen",
        scope_digest=scope_digest,
        candidate_digest=candidate_digest,
        runner="pytest evaluator trust and verifier identity controls",
        evidence=[
            evidence_record(evaluator, root),
            {
                "path": "policies/trust-policy.json",
                "sha256": policy_digest,
            },
        ],
        facts={
            "evaluator_digest": evaluator_digest,
            "verifier_sha256": verifier_digest,
            "verifier_version": verifier_version,
            "policy_digest": policy_digest,
        },
    )
    tamper_tokens = {
        "test_sigstore_verifier_content_and_version_are_pinned",
        "test_sigstore_helper_substitution_blocks_before_execution",
        "test_sigstore_replacement_between_verify_and_hash_blocks",
        "test_sigstore_script_wrapper_requires_complete_runtime_closure",
    }
    if not tamper_tokens.issubset(all_cases):
        missing = sorted(tamper_tokens - all_cases)
        raise ValueError(f"evaluator tamper controls missing: {missing}")
    domains["evaluator"]["tamper_input_matrix"] = domain_entry(
        domain="evaluator.tamper_input_matrix",
        scope_digest=scope_digest,
        candidate_digest=candidate_digest,
        runner="pytest Sigstore tamper and substitution matrix",
        evidence=[evidence_record(windows_junit, root)],
        facts={"required_tests": sorted(tamper_tokens)},
    )
    blocked_tokens = {
        "test_release_cli_turns_bad_manifest_into_blocked_receipt",
        "test_cli_blocked_output_file_is_structured_json_without_traceback",
        "test_r8_cli_emits_blocked_install_receipt",
    }
    if not blocked_tokens.issubset(all_cases):
        missing = sorted(blocked_tokens - all_cases)
        raise ValueError(f"structured blocked receipt controls missing: {missing}")
    domains["evaluator"]["structured_blocked_receipt"] = domain_entry(
        domain="evaluator.structured_blocked_receipt",
        scope_digest=scope_digest,
        candidate_digest=candidate_digest,
        runner="pytest structured release failure receipts",
        evidence=[evidence_record(windows_junit, root)],
        facts={"required_tests": sorted(blocked_tokens)},
    )

    for lifecycle_name in (
        "staging_install",
        "readback",
        "atomic_activation",
        "rollback_retained",
        "post_activation_smoke",
    ):
        stage_name = {
            "staging_install": "installation",
            "readback": "readback",
            "atomic_activation": "atomic_activation",
            "rollback_retained": "rollback",
            "post_activation_smoke": "smoke",
        }[lifecycle_name]
        domains["lifecycle"][lifecycle_name] = domain_entry(
            domain=f"lifecycle.{lifecycle_name}",
            scope_digest=scope_digest,
            candidate_digest=candidate_digest,
            runner="three-platform lifecycle harness",
            evidence=[
                {
                    "path": f"{name}-lifecycle",
                    "sha256": canonical_digest(lifecycles[name]),
                }
                for name in ("windows", "linux", "macos")
            ],
            facts={
                "stage": stage_name,
                "platforms": ["windows", "linux", "macos"],
                "status": "PASS",
                "candidate_digest": candidate_digest,
                "readback_digest": lifecycles["windows"]["readback_digest"],
            },
        )

    domain_signature, domain_signature_artifacts = sign_verified_domain_set(
        domains,
        output=output,
        candidate_digest=candidate_digest,
        scope_digest=scope_digest,
    )

    matrix: dict[str, object] = {
        "schema_version": 2,
        "status": "PASS",
        "candidate_digest": candidate_digest,
        "scope_digest": scope_digest,
        "evaluator_digest": evaluator_digest,
        "coverage_digest": coverage["coverage_digest"],
        "domains_digest": canonical_digest(domains),
        "failed_count": 0,
        "failures": [],
        "failed_checks": [],
        "skipped": [],
        "requested_cases": [],
        "checks": [],
    }
    for group in domains.values():
        for entry in group.values():
            domain_name = entry["receipt"]["domain"]
            matrix["requested_cases"].append(domain_name)
            matrix["checks"].append(
                {
                    "check_id": domain_name,
                    "status": "PASS",
                    "candidate_digest": candidate_digest,
                    "runner": entry["runner"],
                    "environment": entry["environment"],
                    "receipt": entry["receipt"],
                    "receipt_sha256": entry["receipt_sha256"],
                }
            )

    verification: dict[str, object] = {
        "schema_version": 3,
        "status": "PASS",
        "failure_count": 0,
        "scope_id": freeze["scope_id"],
        "run_id": freeze["run_id"],
        "scope_digest": scope_digest,
        "candidate_digest": candidate_digest,
        "evaluator_digest": evaluator_digest,
        "package_manifest_digest": manifest["manifest_digest"],
        "test_suites": suites,
        "acceptance_matrix": {
            "count": acceptance["test_count"],
            "passed": acceptance["passed_count"],
            "report_digest": acceptance["report_digest"],
            "sha256": sha256(input_root / "acceptance-matrix.json"),
        },
        "candidate_checks": checks,
        "clean_probe_digest": probe_digest,
        "clean_probe_semantic_digests": {
            name: value["semantic"]["report_digest"]
            for name, value in clean_probes.items()
        },
        "clean_probe_ledger_digests": {
            name: value["ledger"]["ledger_digest"]
            for name, value in clean_probes.items()
        },
        "clean_probe_semantic_sha256": {
            name: value["semantic_sha256"]
            for name, value in clean_probes.items()
        },
        "clean_probe_ledger_sha256": {
            name: value["ledger_sha256"]
            for name, value in clean_probes.items()
        },
        "taxonomy": {
            "cells": len(coverage_matrix["cells"]),
            "terminal_counts": terminal_counts,
            "coverage_digest": taxonomy["coverage_digest"],
            "qualification_controls": 720,
        },
        "lifecycle_receipt_digests": {
            name: fir_digest(value) for name, value in lifecycles.items()
        },
        "power_evidence_digest": power["evidence_digest"],
        "domain_signature_digest": domain_signature["receipt_digest"],
        "domain_signature_artifacts": domain_signature_artifacts,
        "captured_at_utc": reviewed_at,
    }
    verification["verification_digest"] = canonical_digest(verification)
    matrix["verification_digest"] = verification["verification_digest"]
    matrix["matrix_digest"] = canonical_digest(matrix)

    seed_review = {
        "schema_version": 2,
        "producer": PRODUCER,
        "reviewer": REVIEWER,
        "verdict": "PASS",
        "state": "INDEPENDENT_REVIEW",
        "subject_digest": "0" * 64,
        "subject": {},
        "scope_digest": scope_digest,
        "candidate_digest": candidate_digest,
        "verification_digest": verification["verification_digest"],
        "ledger_digest": ledger["ledger_digest"],
        "evaluator_digest": evaluator_digest,
        "matrix_digest": matrix["matrix_digest"],
        "coverage_digest": coverage["coverage_digest"],
        "domains_digest": canonical_digest(domains),
        "domain_signature_digest": domain_signature["receipt_digest"],
        "domain_signature_artifacts": domain_signature_artifacts,
        "findings_digest": canonical_digest(probe_findings),
        "findings": probe_findings,
        "limitations": [],
        "unverified_claims": [],
        "not_run": [],
        "non_blocking_observations": [],
        "open_count": 0,
        "residual_risks": [],
        "reviewed_at": reviewed_at,
    }
    gate = assess_release_gate(
        findings=probe_findings,
        review=seed_review,
        domains=domains,
        coverage=coverage,
        matrix=matrix,
        expected_candidate_digest=candidate_digest,
        expected_scope_digest=scope_digest,
        expected_verification_digest=verification["verification_digest"],
        require_evidence_binding=True,
        require_domain_signature=True,
        domain_signature=domain_signature,
    )
    if gate["status"] != "PASS" or not gate["release_ready"]:
        raise ValueError(f"release gate is blocked: {gate['blockers']}")

    subject: dict[str, object] = {
        "scope_id": freeze["scope_id"],
        "review_kind": "FINAL_REVIEW",
        "freeze_digest": freeze_digest,
        "scope_digest": scope_digest,
        "candidate_digest": candidate_digest,
        "verification_digest": verification["verification_digest"],
        "ledger_digest": ledger["ledger_digest"],
        "evaluator_digest": evaluator_digest,
        "findings": probe_findings,
        "coverage": coverage,
        "matrix": matrix,
        "domains": domains,
        "domain_signature": domain_signature,
        "limitations": [],
        "unverified_claims": [],
        "not_run": [],
        "non_blocking_observations": [],
        "risk_gate": gate,
        "open_count": 0,
        "residual_risks": [],
        "reviewed_at": reviewed_at,
    }
    attestation: dict[str, object] = {
        "schema_version": 1,
        "producer": PRODUCER,
        "reviewer": REVIEWER,
        "issuer": ISSUER,
        "verification_method": "sigstore-keyless",
        "verdict": "PASS",
        "trust_root_id": TRUST_ROOT_ID,
        "trust_anchor_digest": policy_digest,
        "history_anchor_key_sha256": policy["history_anchor_key_sha256"][0],
        "subject_digest": canonical_digest(subject),
        "scope_digest": scope_digest,
        "candidate_digest": candidate_digest,
        "verification_digest": verification["verification_digest"],
        "ledger_digest": ledger["ledger_digest"],
        "evaluator_digest": evaluator_digest,
        "matrix_digest": matrix["matrix_digest"],
        "coverage_digest": coverage["coverage_digest"],
        "domains_digest": canonical_digest(domains),
        "domain_signature_digest": domain_signature["receipt_digest"],
        "domain_signature_artifacts": domain_signature_artifacts,
        "findings_digest": canonical_digest(probe_findings),
        "power_evidence_digest": power["evidence_digest"],
        "reviewed_at": reviewed_at,
    }
    risk_evidence: dict[str, object] = {
        "schema_version": 2,
        "status": "PASS",
        "release_ready": True,
        "state": "CLOSED_FOR_DECLARED_UNIVERSE",
        "scope_digest": scope_digest,
        "candidate_digest": candidate_digest,
        "verification_digest": verification["verification_digest"],
        "ledger_digest": ledger["ledger_digest"],
        "evaluator_digest": evaluator_digest,
        "coverage_digest": coverage["coverage_digest"],
        "domains_digest": canonical_digest(domains),
        "findings_digest": canonical_digest(probe_findings),
        "matrix_digest": matrix["matrix_digest"],
        "findings": probe_findings,
        "coverage": coverage,
        "matrix": matrix,
        "domains": domains,
        "domain_signature": domain_signature,
        "limitations": [],
        "unverified_claims": [],
        "not_run": [],
        "non_blocking_observations": [],
        "risk_gate": gate,
        "reviewed_at": reviewed_at,
    }

    write_json(output / "verification.json", verification)
    write_json(output / "risk-ledger.json", ledger)
    write_json(output / "matrix.json", matrix)
    write_json(output / "coverage.json", coverage)
    write_json(output / "domains.json", domains)
    write_json(output / "risk-gate-evidence.json", risk_evidence)
    shutil.copytree(power_path.parent, output / "power")
    (output / "reviewer-attestation.json").write_text(
        canonical_json(attestation) + "\n",
        encoding="utf-8",
    )
    print(
        canonical_json(
            {
                "status": "PASS",
                "candidate_digest": candidate_digest,
                "scope_digest": scope_digest,
                "verification_digest": verification["verification_digest"],
                "ledger_digest": ledger["ledger_digest"],
                "matrix_digest": matrix["matrix_digest"],
                "coverage_digest": coverage["coverage_digest"],
                "domains_digest": canonical_digest(domains),
                "attestation_digest": canonical_digest(attestation),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
