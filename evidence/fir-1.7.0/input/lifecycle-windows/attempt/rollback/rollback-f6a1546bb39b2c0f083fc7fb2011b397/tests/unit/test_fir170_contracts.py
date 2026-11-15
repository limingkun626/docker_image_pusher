from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import (
    ContractError,
    build_evidence_fact,
    build_run_manifest,
    canonical_digest,
    dir_hash1,
    in_toto_statement,
    material_digest,
    validate_candidate_manifest,
    validate_evidence_fact,
    validate_execution_receipt,
    validate_run_manifest,
    validate_tool_closure,
)


def _digest(label: str) -> str:
    return canonical_digest({"label": label})


def _bindings() -> dict[str, str]:
    return {
        name: _digest(name)
        for name in (
            "registry_digest",
            "taxonomy_policy_digest",
            "trust_policy_digest",
            "knowledge_pack_digest",
            "tool_closure_digest",
            "environment_digest",
            "config_digest",
            "evaluation_case_registry_digest",
        )
    }


def _manifest(tmp_path: Path, **changes):
    root = tmp_path / "skill"
    root.mkdir(exist_ok=True)
    (root / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    values = {
        "run_id": "scope-1:1",
        "scope_id": "scope-1",
        "scope_digest": _digest("scope"),
        "platform": "WINDOWS",
        "subject_manifest_digest": _digest("subject-manifest"),
        "subject_tree_digest": _digest("subject-tree"),
        "subject_dir_hash1": dir_hash1(root),
        "logical_identity": "skill:demo",
        "bindings": _bindings(),
        "repair_plan_digest": None,
        "candidate_digest": None,
    }
    values.update(changes)
    return build_run_manifest(**values)


def _tool_closure():
    closure = {
        "schema_version": 1,
        "tool_id": "probe",
        "logical_name": "Probe",
        "version": "1.0.0",
        "platform": "WINDOWS",
        "artifact_sha256": _digest("artifact"),
        "version_output_sha256": _digest("version"),
        "argv_template": ["{tool}", "--version"],
        "rule_set_digest": _digest("rules"),
        "fixture_archive_digest": _digest("fixtures"),
        "license_digest": _digest("license"),
    }
    closure["closure_digest"] = material_digest(closure, "closure_digest")
    return closure


def _execution_receipt(manifest):
    receipt = {
        "schema_version": 3,
        "receipt_id": _digest("receipt-id"),
        "run_id": manifest["run_id"],
        "receipt_kind": "DETECTOR",
        "cell_id": "SKILL:FUNCTIONAL_FAULT:STATIC",
        "binding_id": "detector.probe",
        "tool": {"closure_digest": manifest["bindings"]["tool_closure_digest"]},
        "subject": {
            "tree_digest": manifest["subject"]["tree_digest"],
            "candidate_digest": manifest["candidate_digest"],
            "snapshot_digest": _digest("snapshot"),
        },
        "execution": {
            "argv_digest": _digest("argv"),
            "environment_digest": manifest["bindings"]["environment_digest"],
            "rule_set_digest": _digest("rules"),
            "exit_code": 0,
            "stdout_digest": _digest("stdout"),
            "stderr_digest": _digest("stderr"),
            "parse_status": "PASS",
        },
        "resources": {
            "elapsed_seconds": 0.1,
            "peak_rss_mib": 1.0,
            "input_files": 1,
            "output_bytes": 0,
            "limit_hit": None,
        },
        "process_tree": {
            "root_pid": 1,
            "descendants_seen": [],
            "descendants_remaining": [],
            "termination_method": "wait",
            "empty_verified": True,
        },
        "network": {
            "policy": "DENY",
            "backend": "job-object",
            "enforced": True,
            "namespace_or_job_identity": "job-1",
            "canary_receipt_digest": _digest("canary"),
            "cleanup_verified": True,
        },
        "facts": [],
        "terminal_status": "CLEAN",
        "failure_code": None,
    }
    receipt["receipt_digest"] = material_digest(receipt, "receipt_digest")
    return receipt


def test_t_id_01_forged_subject_digest_blocks_stale_input(tmp_path: Path):
    manifest = _manifest(tmp_path)
    manifest["subject"]["tree_digest"] = _digest("other-subject")
    manifest["manifest_digest"] = material_digest(manifest, "manifest_digest")
    with pytest.raises(ContractError, match="subject tree") as caught:
        validate_run_manifest(
            manifest,
            expected={"subject_tree_digest": _digest("subject-tree")},
        )
    assert caught.value.code == "BLOCKED_STALE_INPUT"


def test_t_id_02_forged_candidate_digest_blocks_evidence():
    candidate = {
        "schema_version": 2,
        "candidate_id": _digest("candidate-id"),
        "base_subject_digest": _digest("subject"),
        "candidate_digest": _digest("candidate"),
        "candidate_dir_hash1": _digest("candidate-dir"),
        "repair_plan_digest": _digest("plan"),
        "operation_receipt_digests": [],
        "logical_identity": "skill:demo",
        "generation": 1,
        "files": [],
    }
    candidate["candidate_manifest_digest"] = material_digest(
        candidate, "candidate_manifest_digest"
    )
    with pytest.raises(ContractError, match="candidate binding"):
        validate_candidate_manifest(
            candidate,
            expected={"candidate_digest": _digest("forged-candidate")},
        )


def test_t_id_03_tool_version_substitution_blocks_adapter():
    closure = _tool_closure()
    with pytest.raises(ContractError, match="tool artifact") as caught:
        validate_tool_closure(
            closure, expected_artifact_sha256=_digest("different-binary")
        )
    assert caught.value.code == "BLOCKED_ADAPTER"


def test_t_id_04_rule_drift_after_freeze_blocks_stale_input(tmp_path: Path):
    manifest = _manifest(tmp_path, candidate_digest=_digest("candidate"))
    receipt = _execution_receipt(manifest)
    with pytest.raises(ContractError, match="rule set") as caught:
        validate_execution_receipt(
            receipt,
            expected={
                "run_id": manifest["run_id"],
                "subject_tree_digest": manifest["subject"]["tree_digest"],
                "candidate_digest": manifest["candidate_digest"],
                "environment_digest": manifest["bindings"]["environment_digest"],
                "rule_set_digest": _digest("drifted-rules"),
            },
        )
    assert caught.value.code == "BLOCKED_STALE_INPUT"


def test_dir_hash_and_in_toto_statement_are_deterministic(tmp_path: Path):
    root = tmp_path / "tree"
    (root / "nested").mkdir(parents=True)
    (root / "a.txt").write_text("a\n", encoding="utf-8")
    (root / "nested" / "b.txt").write_text("b\n", encoding="utf-8")
    digest = dir_hash1(root)
    assert digest == dir_hash1(root)
    statement = in_toto_statement(
        name="candidate",
        digest=digest,
        predicate_type="https://fir.local/attestation/test/v1",
        predicate={"ok": True},
    )
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["subject"][0]["digest"]["sha256"] == digest


def test_evidence_fact_and_execution_receipt_validate(tmp_path: Path):
    manifest = _manifest(tmp_path, candidate_digest=_digest("candidate"))
    receipt = _execution_receipt(manifest)
    validate_execution_receipt(
        receipt,
        expected={
            "run_id": manifest["run_id"],
            "subject_tree_digest": manifest["subject"]["tree_digest"],
            "candidate_digest": manifest["candidate_digest"],
            "environment_digest": manifest["bindings"]["environment_digest"],
            "rule_set_digest": _digest("rules"),
        },
    )
    fact = build_evidence_fact(
        run_id=manifest["run_id"],
        cell_id="SKILL:FUNCTIONAL_FAULT:STATIC",
        invariant_id="invariant.test",
        defect_class_id="test.finding",
        subject_digest=manifest["subject"]["tree_digest"],
        candidate_digest=manifest["candidate_digest"],
        policy_digest=manifest["bindings"]["taxonomy_policy_digest"],
        registry_digest=manifest["bindings"]["registry_digest"],
        locator={"path": "SKILL.md", "start_byte": 0, "end_byte": 1},
        predicate="test",
        value={},
        witness_refs=["receipt:" + receipt["receipt_digest"]],
        method_id="probe",
        method_version="1.0.0",
        producer_receipt_digest=receipt["receipt_digest"],
        terminal_observation="CLEAN",
    )
    validate_evidence_fact(
        fact,
        expected={
            "run_id": manifest["run_id"],
            "subject_tree_digest": manifest["subject"]["tree_digest"],
            "candidate_digest": manifest["candidate_digest"],
            "registry_digest": manifest["bindings"]["registry_digest"],
            "policy_digest": manifest["bindings"]["taxonomy_policy_digest"],
        },
    )
