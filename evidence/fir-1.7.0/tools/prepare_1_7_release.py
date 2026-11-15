from __future__ import annotations

import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path


RUN = Path(r"F:\Codex\runs\fir-1.7.0-release-20261115")
GEN = RUN / "generation-6"
CANDIDATE = GEN / "full-inspection-repair"
PACKAGE = GEN / "package" / "package-manifest.json"
BUILD = GEN / "release-build"
JUNIT = BUILD / "windows-junit.xml"
ACCEPTANCE = BUILD / "acceptance-matrix.json"
SELF_CHECK = BUILD / "windows-check" / "summary.json"
CAPABILITY_VALIDATION = BUILD / "capability-pack-validation.json"
SCOPE_ID = "fir-1.7.0-release-20261115-generation-6"
RUN_ID = "fir-1.7.0-release-20261115-generation-6-r1"

FIXED_INPUTS = {
    "evaluator_artifact": Path(
        r"F:\Codex\runs\fir-full-r19-review-defect-repair-20261111"
        r"\matrix_selftest_r19.py"
    ),
    "history_anchor_key": Path(
        r"F:\Codex\runs\fir-full-r14-darwin-openat-20261111"
        r"\authority\history-anchor.key"
    ),
    "sigstore_trust_config": Path(
        r"F:\Codex\runs\fir-full-r23-power-tooling-20261112"
        r"\authority-r23-r1\client-trust-config.json"
    ),
    "sigstore_verifier": Path(
        r"F:\Codex\runs\fir-full-closure-r5-20261110"
        r"\.sigstore-venv\Scripts\sigstore.exe"
    ),
    "trust_policy": CANDIDATE / "policies" / "trust-policy.json",
}
CACHE_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".hypothesis",
}


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def require_digest(value: dict[str, object], field: str, label: str) -> str:
    declared = value.get(field)
    material = dict(value)
    material.pop(field, None)
    if declared != digest(material):
        raise ValueError(f"{label} digest mismatch")
    return str(declared)


def verify_clean_probe(root: Path) -> dict[str, object]:
    summary = read_json(root / "summary.json")
    semantic = read_json(root / "semantic-matrix.json")
    ledger = read_json(root / "risk-ledger.json")
    require_digest(semantic, "report_digest", "clean-probe semantic matrix")
    require_digest(ledger, "ledger_digest", "clean-probe risk ledger")
    if (
        summary.get("status") != "CHECKED"
        or summary.get("open_count") != 0
        or summary.get("blocked_detectors") not in (None, [])
        or summary.get("semantic_matrix_digest") != semantic.get("report_digest")
        or semantic.get("finding_count") != 0
        or semantic.get("findings") != []
        or semantic.get("cell_count") != summary.get("semantic_cell_count")
    ):
        raise ValueError("clean probe semantic evidence is not closed")
    if any(
        cell.get("status") not in {"CLEAN", "CLEAN_WITH_PROOF"}
        or cell.get("findings")
        for cell in semantic.get("cells", ())
        if isinstance(cell, dict)
    ):
        raise ValueError("clean probe has non-clean semantic cells")
    if (
        ledger.get("open_count") != 0
        or ledger.get("items") != []
        or ledger.get("missing_sources")
        or ledger.get("unexpected_sources")
        or ledger.get("residual_risks")
        or ledger.get("unresolved_ids")
    ):
        raise ValueError("clean probe risk ledger is not closed")
    return {
        "summary": summary,
        "semantic": semantic,
        "ledger": ledger,
    }


def inventory(root: Path) -> list[dict[str, object]]:
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


def junit_counts(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    fields = ("tests", "failures", "errors", "skipped")
    counts = {
        field: sum(int(suite.attrib.get(field, "0")) for suite in suites)
        for field in fields
    }
    counts["passed"] = (
        counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
    )
    if counts["failures"] or counts["errors"]:
        raise ValueError(f"JUnit is not green: {counts}")
    return counts


def main() -> int:
    sys.path.insert(0, str(CANDIDATE / "scripts"))
    from full_inspection_repair.contracts import canonical_digest
    from full_inspection_repair.detector_registry import default_taxonomy_coverage
    from full_inspection_repair.package import build_package_manifest, verify_package_manifest
    from full_inspection_repair.runtime_registry import load_registry
    from full_inspection_repair.taxonomy import assert_taxonomy_complete

    files = inventory(CANDIDATE)
    caches = [
        item["path"]
        for item in files
        if CACHE_NAMES.intersection(Path(str(item["path"])).parts)
    ]
    if caches:
        raise ValueError(f"candidate contains runtime caches: {caches}")
    manifest = read_json(PACKAGE)
    if build_package_manifest(CANDIDATE) != manifest:
        raise ValueError("package manifest changed after test execution")
    verify_package_manifest(CANDIDATE, manifest)
    counts = junit_counts(JUNIT)
    acceptance = read_json(ACCEPTANCE)
    if (
        acceptance.get("status") != "PASS"
        or acceptance.get("test_count") != 76
        or acceptance.get("passed_count") != 76
    ):
        raise ValueError("76-row acceptance matrix is not PASS")
    clean_probe = verify_clean_probe(SELF_CHECK.parent)
    self_check = clean_probe["summary"]
    semantic = clean_probe["semantic"]
    probe_ledger = clean_probe["ledger"]
    capability = read_json(CAPABILITY_VALIDATION)
    if (
        capability.get("status") != "PASS"
        or capability.get("slices") != 22
        or capability.get("release_authority") is not False
    ):
        raise ValueError("capability pack validation is not qualified")

    coverage = default_taxonomy_coverage("SKILL")
    assert_taxonomy_complete(coverage, ("SKILL",))
    registry = load_registry()
    terminal_counts: dict[str, int] = {}
    for cell in coverage["cells"]:
        state = str(cell["terminal_state"])
        terminal_counts[state] = terminal_counts.get(state, 0) + 1
    expected_terminal_counts = {
        "COVERED_BY_EXACT_ADAPTER": 11,
        "COVERED_BY_INDEPENDENT_ORACLE": 16,
        "COVERED_BY_NATIVE_DETECTOR": 35,
        "MERGED_WITH_PRIMARY_CELL": 2,
        "NOT_APPLICABLE_WITH_PROOF": 8,
    }
    if terminal_counts != expected_terminal_counts:
        raise ValueError(f"unexpected 72-cell terminal counts: {terminal_counts}")

    policy = read_json(FIXED_INPUTS["trust_policy"])
    active = next(row for row in policy["reviewers"] if row["status"] == "ACTIVE")
    fixed_inputs = {
        name: {
            "path": str(path),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for name, path in FIXED_INPUTS.items()
    }
    expected = {
        "evaluator_artifact": policy["evaluator_artifacts"][0],
        "history_anchor_key": policy["history_anchor_key_sha256"][0],
        "sigstore_trust_config": policy["sigstore_trust_config_sha256"][0],
        "sigstore_verifier": active["verifier_sha256"],
    }
    for name, value in expected.items():
        if fixed_inputs[name]["sha256"] != value:
            raise ValueError(f"fixed input digest mismatch: {name}")

    captured_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    freeze: dict[str, object] = {
        "schema_version": 2,
        "status": "FROZEN_CANDIDATE",
        "scope_id": SCOPE_ID,
        "run_id": RUN_ID,
        "version": "1.7.0",
        "generation": 1,
        "candidate_path": str(CANDIDATE),
        "candidate_name": CANDIDATE.name,
        "candidate_digest": manifest["tree_digest"],
        "tree_digest": manifest["tree_digest"],
        "file_count": len(files),
        "files": files,
        "package_manifest_digest": manifest["manifest_digest"],
        "package_manifest_sha256": sha256(PACKAGE),
        "taxonomy_coverage_digest": coverage["coverage_digest"],
        "taxonomy_terminal_counts": terminal_counts,
        "policy_digest": coverage["coverage_digest"],
        "registry_digest": registry.registry_digest,
        "fixed_inputs": fixed_inputs,
        "trust_policy_digest": canonical_digest(policy),
        "reviewer_registry_digest": policy["reviewer_registry_digest"],
        "windows_tests": {
            **counts,
            "junit_sha256": sha256(JUNIT),
        },
        "acceptance_matrix": {
            "test_count": 76,
            "report_digest": acceptance["report_digest"],
            "report_sha256": sha256(ACCEPTANCE),
        },
        "clean_probe_check": {
            "status": self_check["status"],
            "semantic_cells": self_check["semantic_cell_count"],
            "summary_sha256": sha256(SELF_CHECK),
            "semantic_digest": semantic["report_digest"],
            "semantic_sha256": sha256(SELF_CHECK.parent / "semantic-matrix.json"),
            "finding_count": semantic["finding_count"],
            "ledger_digest": probe_ledger["ledger_digest"],
            "ledger_sha256": sha256(SELF_CHECK.parent / "risk-ledger.json"),
        },
        "capability_pack": {
            "status": capability["status"],
            "slices": capability["slices"],
            "pack_digest": capability["pack_digest"],
            "validation_sha256": sha256(CAPABILITY_VALIDATION),
        },
        "captured_at_utc": captured_at,
    }
    freeze["freeze_digest"] = digest(freeze)
    write_json(BUILD / "candidate-freeze.json", freeze)

    trust_registry = {
        "schema_version": 1,
        "reviewers": policy["reviewers"],
    }
    if digest(trust_registry) != policy["reviewer_registry_digest"]:
        raise ValueError("trust registry digest mismatch")
    write_json(BUILD / "trust-registry.json", trust_registry)
    write_json(BUILD / "taxonomy-coverage.json", coverage)
    print(
        json.dumps(
            {
                "status": freeze["status"],
                "candidate_digest": freeze["candidate_digest"],
                "freeze_digest": freeze["freeze_digest"],
                "file_count": freeze["file_count"],
                "tests": counts,
                "acceptance_count": 76,
                "semantic_cells": self_check["semantic_cell_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
