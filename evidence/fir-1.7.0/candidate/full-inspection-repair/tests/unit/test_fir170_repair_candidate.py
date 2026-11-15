from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import repair as repair_module
from full_inspection_repair.adapters import Subject, build_subject
from full_inspection_repair.candidate_closure import (
    ClosureError,
    require_candidate_closure,
)
from full_inspection_repair.contracts import (
    ContractError,
    canonical_digest,
    material_digest,
)
from full_inspection_repair.detectors import run_default_detectors
from full_inspection_repair.ledger import build_risk_ledger_v2
from full_inspection_repair.repair import (
    RepairBlocked,
    apply_batch,
    assert_batch_digest,
    plan_batch,
    preflight_batch,
)
from full_inspection_repair.verification_matrix import reconcile_evaluation


def _digest(label: str) -> str:
    return canonical_digest({"label": label})


def _source(tmp_path: Path):
    root = tmp_path / "source-skill"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo",
        encoding="utf-8",
    )
    return root, build_subject(root, "SKILL")


def _findings(subject: Subject):
    return [
        finding
        for result in run_default_detectors(subject)
        for finding in result.findings
    ]


def _batch_with_operation(
    operation_type: str,
    target: str,
    parameters: dict[str, object] | None = None,
) -> dict[str, object]:
    operation = {
        "risk_ids": ["finding-1"],
        "operation_type": operation_type,
        "binding_id": "repair." + operation_type.lower().replace("_", "-"),
        "binding_version": "1.0.0",
        "target": target,
        "preimage_sha256": None,
        "expected_postimage_sha256": None,
        "parameters": parameters or {},
        "preconditions": [],
        "postconditions": [],
        "rollback_slice": "RB-1",
    }
    operation["operation_id"] = canonical_digest(operation)
    batch = {
        "schema_version": 2,
        "scope_id": "scope-1",
        "issue_set_digest": _digest("issues"),
        "base_subject_digest": _digest("subject"),
        "registry_digest": _digest("registry"),
        "policy_digest": _digest("policy"),
        "decision_set_digest": None,
        "candidate_generation": 1,
        "root_ids": ["root-1"],
        "root_dag": [{"root_id": "root-1", "depends_on": []}],
        "finding_root_map": {"finding-1": "root-1"},
        "operations": [operation],
        "dependencies": [],
        "conflicts": [],
    }
    batch["batch_digest"] = material_digest(batch, "batch_digest")
    return batch


def _run(manifest_source: Subject, candidate: Subject, candidate_manifest, batch):
    bindings = {
        name: _digest(name)
        for name in (
            "registry_digest",
            "taxonomy_policy_digest",
            "trust_policy_digest",
            "knowledge_pack_digest",
            "tool_closure_digest",
            "environment_digest",
            "config_digest",
        )
    }
    run = {
        "schema_version": 2,
        "run_id": "scope-1:1",
        "scope_id": "scope-1",
        "scope_digest": _digest("scope"),
        "platform": "WINDOWS",
        "subject": {
            "manifest_digest": manifest_source.snapshot_digest,
            "tree_digest": manifest_source.tree_digest,
            "dir_hash1": _digest("source-dir"),
            "logical_identity": manifest_source.subject_id,
        },
        "bindings": bindings,
        "repair_plan_digest": batch["batch_digest"],
        "candidate_digest": candidate.tree_digest,
    }
    run["manifest_digest"] = material_digest(run, "manifest_digest")
    return run


def _report(label: str, run: dict[str, object], candidate_digest: str):
    report = {
        "schema_version": 2,
        "run_id": run["run_id"],
        "scope_digest": run["scope_digest"],
        "subject_digest": run["subject"]["tree_digest"],
        "candidate_digest": candidate_digest,
        "registry_digest": run["bindings"]["registry_digest"],
        "policy_digest": run["bindings"]["taxonomy_policy_digest"],
        "tool_closure_digest": run["bindings"]["tool_closure_digest"],
        "cells": [
            {
                "cell_id": "SKILL:FUNCTIONAL_FAULT:STATIC",
                "status": "CLEAN",
            }
        ],
        "receipt_digests": [_digest(label + "-receipt")],
    }
    report["report_digest"] = material_digest(report, "report_digest")
    return report


def _closure_artifacts(run, candidate_digest):
    source_inventory = {
        "schema_version": 2,
        "run_id": run["run_id"],
        "scope_digest": run["scope_digest"],
        "subject_digest": run["subject"]["tree_digest"],
        "candidate_digest": candidate_digest,
        "policy_digest": run["bindings"]["taxonomy_policy_digest"],
        "sources": [
            {
                "source_id": "source:SKILL.md",
                "locator": "SKILL.md",
                "applicability": "APPLICABLE",
            }
        ],
    }
    source_inventory["inventory_digest"] = material_digest(
        source_inventory, "inventory_digest"
    )
    source_closure = {
        "schema_version": 1,
        "scope_id": run["run_id"],
        "subject_digest": run["subject"]["tree_digest"],
        "candidate_digest": candidate_digest,
        "runtime_registry_digest": run["bindings"]["registry_digest"],
        "source_denominator_digest": canonical_digest(
            source_inventory["sources"]
        ),
        "source_count": 1,
        "terminal_count": 1,
        "records": [
            {
                "source_id": "source:SKILL.md",
                "terminal_status": "SATISFIED",
                "evidence_refs": ["semantic-matrix:" + "1" * 64],
            }
        ],
        "coverage_boundary_digest": canonical_digest(
            [{"source_id": "source:SKILL.md"}]
        ),
    }
    source_closure["closure_digest"] = material_digest(
        source_closure,
        "closure_digest",
    )
    detection = _report("detection", run, candidate_digest)
    oracle = _report("oracle", run, candidate_digest)
    taxonomy = {
        "schema_version": 2,
        "scope_digest": run["scope_digest"],
        "subject_digest": run["subject"]["tree_digest"],
        "candidate_digest": candidate_digest,
        "required_cell_count": 1,
        "covered_cell_count": 1,
    }
    taxonomy["coverage_digest"] = material_digest(taxonomy, "coverage_digest")
    impact = {
        "schema_version": 2,
        "scope_digest": run["scope_digest"],
        "subject_digest": run["subject"]["tree_digest"],
        "candidate_digest": candidate_digest,
        "unresolved_count": 0,
    }
    impact["graph_digest"] = material_digest(impact, "graph_digest")
    identities = {
        "case-1": {
            "fixture_digest": _digest("fixture"),
            "runner_digest": _digest("runner"),
            "tool_digest": _digest("tool"),
        }
    }
    matrix = reconcile_evaluation(
        requested=["case-1"],
        attempts={"case-1": "PASS"},
        f2p={"case-1"},
        p2p=set(),
        case_identities=identities,
        expected_identities=identities,
        run_id=run["run_id"],
        scope_digest=run["scope_digest"],
        subject_digest=run["subject"]["tree_digest"],
        candidate_digest=candidate_digest,
    )
    evidence = {
        "source_inventory_digest": source_inventory["inventory_digest"],
        "detection_digest": detection["report_digest"],
        "oracle_digest": oracle["report_digest"],
        "taxonomy_digest": taxonomy["coverage_digest"],
        "impact_digest": impact["graph_digest"],
        "matrix_digest": matrix["matrix_digest"],
        "registry_digest": run["bindings"]["registry_digest"],
    }
    ledger = build_risk_ledger_v2(
        run_id=run["run_id"],
        scope_digest=run["scope_digest"],
        subject_digest=run["subject"]["tree_digest"],
        candidate_digest=candidate_digest,
        required_sources=["source:SKILL.md"],
        findings=[],
        observed_sources=["source:SKILL.md"],
        source_inventory_digest=source_inventory["inventory_digest"],
        evidence_digests=evidence,
    )
    return (
        source_inventory,
        source_closure,
        ledger,
        detection,
        oracle,
        taxonomy,
        impact,
        matrix,
    )


def _closure_fixture(tmp_path: Path):
    source_root, source = _source(tmp_path)
    batch = plan_batch(_findings(source), source)
    candidate_root = tmp_path / "candidate" / "renamed"
    receipt = apply_batch(source, batch, candidate_root)
    candidate = build_subject(candidate_root, "SKILL")
    run = _run(source, candidate, receipt["candidate_manifest"], batch)
    artifacts = _closure_artifacts(run, candidate.tree_digest)
    return {
        "source_root": source_root,
        "source": source,
        "candidate_root": candidate_root,
        "candidate": candidate,
        "manifest": receipt["candidate_manifest"],
        "batch": batch,
        "run": run,
        "source_inventory": artifacts[0],
        "source_closure": artifacts[1],
        "ledger": artifacts[2],
        "detection": artifacts[3],
        "oracle": artifacts[4],
        "taxonomy": artifacts[5],
        "impact": artifacts[6],
        "matrix": artifacts[7],
    }


def test_t_rep_01_post_freeze_injection_blocks_batch(tmp_path: Path):
    _root, subject = _source(tmp_path)
    batch = plan_batch(_findings(subject), subject)
    batch["operations"][0]["target"] = "other.md"
    with pytest.raises(RepairBlocked, match="digest mismatch"):
        assert_batch_digest(batch)


def test_t_rep_02_operation_digest_is_stable_before_and_after_apply(tmp_path: Path):
    _root, subject = _source(tmp_path)
    batch = plan_batch(_findings(subject), subject)
    before = batch["batch_digest"]
    receipt = apply_batch(subject, batch, tmp_path / "candidate" / "renamed")
    assert_batch_digest(batch)
    assert before == batch["batch_digest"]
    assert receipt["operation_receipt_digests"]


def test_t_rep_03_target_escape_is_rejected(tmp_path: Path):
    _root, subject = _source(tmp_path)
    finding = _findings(subject)[0]
    finding = copy.deepcopy(finding)
    finding["affected_refs"] = ["../outside.md"]
    with pytest.raises(RepairBlocked, match="unsafe repair target"):
        plan_batch([finding], subject)


def test_t_rep_04_overlapping_ranges_conflict():
    left = _batch_with_operation(
        "REPLACE_BYTE_RANGE",
        "SKILL.md",
        {"start_byte": 0, "end_byte": 4, "replacement": "x"},
    )
    right = copy.deepcopy(left["operations"][0])
    right["risk_ids"] = ["finding-2"]
    right["parameters"] = {"start_byte": 2, "end_byte": 6, "replacement": "y"}
    right["operation_id"] = canonical_digest(
        {key: value for key, value in right.items() if key != "operation_id"}
    )
    left["operations"].append(right)
    left["finding_root_map"]["finding-2"] = "root-1"
    left["batch_digest"] = material_digest(left, "batch_digest")
    with pytest.raises(RepairBlocked, match="conflict") as caught:
        preflight_batch(left)
    assert caught.value.code == "BLOCKED_REPAIR_CONFLICT"


def test_t_rep_05_cache_inclusive_copy(tmp_path: Path):
    root, subject = _source(tmp_path)
    cache = root / "__pycache__"
    cache.mkdir()
    (cache / "state.pyc").write_bytes(b"cache")
    subject = build_subject(root, "SKILL")
    candidate = tmp_path / "candidate" / "renamed"
    apply_batch(subject, plan_batch(_findings(subject), subject), candidate)
    assert (candidate / "__pycache__" / "state.pyc").read_bytes() == b"cache"


def test_t_rep_06_candidate_basename_does_not_change_logical_identity(tmp_path: Path):
    _root, subject = _source(tmp_path)
    batch = plan_batch(_findings(subject), subject)
    receipt = apply_batch(subject, batch, tmp_path / "candidate" / "different-name")
    assert receipt["logical_identity"] == subject.subject_id


def test_t_rep_07_ast_rewrite_changes_only_planned_range(tmp_path: Path):
    _root, subject = _source(tmp_path)
    start = (subject.root / "SKILL.md").read_bytes().index(b"Demo")
    batch = _batch_with_operation(
        "AST_RULE_REWRITE",
        "SKILL.md",
        {
            "replacements": [
                {
                    "start_byte": start,
                    "end_byte": start + 4,
                    "expected": "Demo",
                    "replacement": "Demo2",
                }
            ]
        },
    )
    receipt = apply_batch(subject, batch, tmp_path / "candidate")
    assert receipt["operations"][0]["postimage_sha256"] != receipt["operations"][0]["preimage_sha256"]


def test_t_rep_08_ast_unplanned_match_blocks(tmp_path: Path):
    _root, subject = _source(tmp_path)
    batch = _batch_with_operation(
        "AST_RULE_REWRITE",
        "SKILL.md",
        {
            "replacements": [
                {"start_byte": 0, "end_byte": 3, "expected": "no", "replacement": "yes"}
            ]
        },
    )
    with pytest.raises(RepairBlocked, match="preimage mismatch"):
        apply_batch(subject, batch, tmp_path / "candidate")


def test_t_rep_09_failure_during_staging_leaves_no_candidate(tmp_path: Path, monkeypatch):
    _root, subject = _source(tmp_path)
    batch = plan_batch(_findings(subject), subject)
    candidate = tmp_path / "candidate"
    receipt_path = tmp_path / "repair-receipt.json"

    def fail_write(*_args, **_kwargs):
        raise OSError("injected crash")

    monkeypatch.setattr(repair_module, "_atomic_write", fail_write)
    with pytest.raises(OSError, match="injected crash"):
        apply_batch(subject, batch, candidate, receipt_path=receipt_path)
    assert not candidate.exists()
    assert receipt_path.exists()
    blocked = __import__("json").loads(receipt_path.read_text(encoding="utf-8"))
    assert blocked["status"] == "BLOCKED_EVIDENCE"


def test_t_rep_10_atomic_commit_failure_retains_rollback_receipt(
    tmp_path: Path, monkeypatch
):
    _root, subject = _source(tmp_path)
    batch = plan_batch(_findings(subject), subject)
    candidate = tmp_path / "candidate"
    receipt_path = tmp_path / "repair-receipt.json"
    real_replace = repair_module.os.replace

    def fail_directory_commit(source, destination):
        if Path(destination) == candidate:
            raise OSError("candidate parent vanished")
        return real_replace(source, destination)

    monkeypatch.setattr(repair_module.os, "replace", fail_directory_commit)
    with pytest.raises(RepairBlocked, match="atomic commit failed"):
        apply_batch(subject, batch, candidate, receipt_path=receipt_path)
    assert not candidate.exists()
    blocked = __import__("json").loads(receipt_path.read_text(encoding="utf-8"))
    assert blocked["status"] == "BLOCKED_REPAIR_PLAN"
    assert blocked["candidate_created"] is False


def test_t_mat_01_mixed_scored_and_unscored_passes():
    result = reconcile_evaluation(
        requested=["required", "optional"],
        attempts={"required": "PASS", "optional": "UNSCORED"},
        f2p={"required"},
        p2p=set(),
    )
    assert result["status"] == "PASS"
    assert result["unscored_count"] == 1


def test_t_mat_02_all_unscored_blocks():
    with pytest.raises(ValueError, match="unscored|inconclusive"):
        reconcile_evaluation(
            requested=["a", "b"],
            attempts={"a": "UNSCORED", "b": "UNSCORED"},
            f2p={"a"},
            p2p={"b"},
        )


def test_t_mat_03_required_unscored_blocks():
    with pytest.raises(ValueError, match="required cases are unscored"):
        reconcile_evaluation(
            requested=["a", "b"],
            attempts={"a": "UNSCORED", "b": "PASS"},
            f2p={"a"},
            p2p={"b"},
        )


def test_t_cc_01_residual_risk_blocks(tmp_path: Path):
    fixture = _closure_fixture(tmp_path)
    ledger = copy.deepcopy(fixture["ledger"])
    ledger["residual_risks"] = ["residual"]
    ledger["ledger_digest"] = material_digest(ledger, "ledger_digest")
    with pytest.raises((ClosureError, ContractError), match="residual"):
        require_candidate_closure(
            candidate=fixture["manifest"],
            ledger=ledger,
            source_inventory=fixture["source_inventory"],
            detection=fixture["detection"],
            oracle=fixture["oracle"],
            taxonomy=fixture["taxonomy"],
            impact=fixture["impact"],
            matrix=fixture["matrix"],
            registry=fixture["run"]["bindings"]["registry_digest"],
            run=fixture["run"],
            source_closure=fixture["source_closure"],
            source_denominator_digest=fixture["source_closure"][
                "source_denominator_digest"
            ],
        )


def test_t_cc_02_unresolved_id_blocks(tmp_path: Path):
    fixture = _closure_fixture(tmp_path)
    ledger = copy.deepcopy(fixture["ledger"])
    ledger["unresolved_ids"] = ["finding-open"]
    ledger["ledger_digest"] = material_digest(ledger, "ledger_digest")
    with pytest.raises((ClosureError, ContractError), match="unresolved"):
        require_candidate_closure(
            candidate=fixture["manifest"],
            ledger=ledger,
            source_inventory=fixture["source_inventory"],
            detection=fixture["detection"],
            oracle=fixture["oracle"],
            taxonomy=fixture["taxonomy"],
            impact=fixture["impact"],
            matrix=fixture["matrix"],
            registry=fixture["run"]["bindings"]["registry_digest"],
            run=fixture["run"],
            source_closure=fixture["source_closure"],
            source_denominator_digest=fixture["source_closure"][
                "source_denominator_digest"
            ],
        )


def test_t_cc_03_source_matrix_digest_blocks(tmp_path: Path):
    fixture = _closure_fixture(tmp_path)
    matrix = copy.deepcopy(fixture["matrix"])
    matrix["candidate_digest"] = fixture["source"].tree_digest
    matrix["matrix_digest"] = material_digest(matrix, "matrix_digest")
    with pytest.raises(ClosureError, match="matrix candidate"):
        require_candidate_closure(
            candidate=fixture["manifest"],
            ledger=fixture["ledger"],
            source_inventory=fixture["source_inventory"],
            detection=fixture["detection"],
            oracle=fixture["oracle"],
            taxonomy=fixture["taxonomy"],
            impact=fixture["impact"],
            matrix=matrix,
            registry=fixture["run"]["bindings"]["registry_digest"],
            run=fixture["run"],
            source_closure=fixture["source_closure"],
            source_denominator_digest=fixture["source_closure"][
                "source_denominator_digest"
            ],
        )


def test_t_cc_04_complete_candidate_closure(tmp_path: Path):
    fixture = _closure_fixture(tmp_path)
    proof = require_candidate_closure(
        candidate=fixture["manifest"],
        ledger=fixture["ledger"],
        source_inventory=fixture["source_inventory"],
        detection=fixture["detection"],
        oracle=fixture["oracle"],
        taxonomy=fixture["taxonomy"],
        impact=fixture["impact"],
        matrix=fixture["matrix"],
        registry=fixture["run"]["bindings"]["registry_digest"],
        run=fixture["run"],
        candidate_root=fixture["candidate_root"],
        source_closure=fixture["source_closure"],
        source_denominator_digest=fixture["source_closure"][
            "source_denominator_digest"
        ],
    )
    assert proof["open_count"] == 0
    assert proof["attestation"]["subject"][0]["digest"]["sha256"] == fixture["candidate"].tree_digest


def _closure_call(fixture, **overrides):
    artifacts = {
        "candidate": fixture["manifest"],
        "ledger": fixture["ledger"],
        "source_inventory": fixture["source_inventory"],
        "detection": fixture["detection"],
        "oracle": fixture["oracle"],
        "taxonomy": fixture["taxonomy"],
        "impact": fixture["impact"],
        "matrix": fixture["matrix"],
        "source_closure": fixture["source_closure"],
        "source_denominator_digest": fixture["source_closure"][
            "source_denominator_digest"
        ],
    }
    artifacts.update(overrides)
    return require_candidate_closure(
        **artifacts,
        registry=fixture["run"]["bindings"]["registry_digest"],
        run=fixture["run"],
    )


def test_t_cc_05_ledger_scope_substitution_blocks(tmp_path: Path):
    fixture = _closure_fixture(tmp_path)
    ledger = copy.deepcopy(fixture["ledger"])
    ledger["scope_digest"] = _digest("other-scope")
    ledger["ledger_digest"] = material_digest(ledger, "ledger_digest")
    with pytest.raises(ClosureError, match="scope") as caught:
        _closure_call(fixture, ledger=ledger)
    assert caught.value.code == "BLOCKED_VERIFICATION"


def test_t_cc_06_subject_candidate_identity_swap_blocks(tmp_path: Path):
    fixture = _closure_fixture(tmp_path)
    candidate = copy.deepcopy(fixture["manifest"])
    candidate["candidate_digest"] = fixture["source"].tree_digest
    candidate["candidate_manifest_digest"] = material_digest(
        candidate, "candidate_manifest_digest"
    )
    with pytest.raises(ClosureError, match="candidate"):
        _closure_call(fixture, candidate=candidate)


@pytest.mark.parametrize("artifact_name", ["detection", "oracle"])
def test_t_cc_07_08_report_candidate_substitution_blocks(
    tmp_path: Path, artifact_name: str
):
    fixture = _closure_fixture(tmp_path)
    substituted = copy.deepcopy(fixture[artifact_name])
    substituted["candidate_digest"] = fixture["source"].tree_digest
    substituted["report_digest"] = material_digest(substituted, "report_digest")
    with pytest.raises(ClosureError, match="candidate"):
        _closure_call(fixture, **{artifact_name: substituted})


@pytest.mark.parametrize(
    "artifact_name",
    ["source_inventory", "taxonomy", "impact", "matrix", "ledger"],
)
def test_t_cc_09_remaining_artifact_substitution_blocks(
    tmp_path: Path, artifact_name: str
):
    fixture = _closure_fixture(tmp_path)
    substituted = copy.deepcopy(fixture[artifact_name])
    substituted["candidate_digest"] = fixture["source"].tree_digest
    digest_field = next(
        (
            field
            for field in (
                "inventory_digest",
                "coverage_digest",
                "graph_digest",
                "matrix_digest",
                "ledger_digest",
            )
            if field in substituted
        ),
        None,
    )
    if digest_field:
        substituted[digest_field] = material_digest(substituted, digest_field)
    with pytest.raises(ClosureError, match="candidate|scope|subject"):
        _closure_call(fixture, **{artifact_name: substituted})
