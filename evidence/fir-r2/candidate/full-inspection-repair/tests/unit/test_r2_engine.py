from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import ContractError, canonical_digest
from full_inspection_repair.detector_registry import default_taxonomy_coverage
from full_inspection_repair.r2_engine import (
    EvidenceFact,
    EvidenceState,
    ORACLE_ONLY_CELLS,
    build_r2_taxonomy_coverage,
    compare_cell_runs,
    compare_facts,
    execution_receipt,
    lifecycle_receipt,
    oracle_receipt,
    repeatability_status,
    rollback_file,
    run_bounded_process,
    run_cell,
    run_native,
    run_oracle,
    run_lifecycle_transaction,
    runtime_repeatability,
)
from full_inspection_repair.taxonomy import (
    assert_taxonomy_complete,
    validate_not_applicable_proof,
)


def _registry() -> dict[str, object]:
    from full_inspection_repair.r2_engine import load_registry

    return load_registry()


def test_taxonomy_exposes_exact_r2_terminal_counts() -> None:
    coverage = default_taxonomy_coverage("SKILL")
    counts: dict[str, int] = {}
    for cell in coverage["cells"]:
        state = cell["terminal_state"]
        counts[state] = counts.get(state, 0) + 1

    assert counts == {
        "COVERED_BY_EXACT_ADAPTER": 11,
        "COVERED_BY_INDEPENDENT_ORACLE": 16,
        "COVERED_BY_NATIVE_DETECTOR": 35,
        "MERGED_WITH_PRIMARY_CELL": 2,
        "NOT_APPLICABLE_WITH_PROOF": 8,
    }
    assert_taxonomy_complete(coverage, ("SKILL",))


def test_no_synthetic_ids_duplicate_measurements_or_ambiguous_na() -> None:
    coverage = default_taxonomy_coverage("SKILL")
    measurements = set()
    for cell in coverage["cells"]:
        identifiers = [*cell["detector_ids"], *cell["oracle_ids"]]
        assert not any(
            item.startswith(("detector.cell.", "oracle.cell."))
            for item in identifiers
        )
        if cell["terminal_state"] == "MERGED_WITH_PRIMARY_CELL":
            assert not cell["detector_ids"]
            assert not cell["oracle_ids"]
            assert cell["primary_cell_id"]
        elif cell["terminal_state"] == "NOT_APPLICABLE_WITH_PROOF":
            assert not cell["detector_ids"]
            assert not cell["oracle_ids"]
            proof = validate_not_applicable_proof(
                cell["not_applicable_proof"],
                target_kind=cell["target_kind"],
                category_id=cell["category_id"],
                evidence_plane=cell["evidence_plane"],
            )
            assert proof["evidence_refs"] == [
                "policy:taxonomy-policy-v2.json:na_scope"
            ]
        elif cell["detector_ids"]:
            measurement = (
                tuple(cell["detector_ids"]),
                tuple(cell["oracle_ids"]),
            )
            assert measurement not in measurements
            measurements.add(measurement)


def test_native_oracle_disagreement_and_empty_sets_block() -> None:
    assert compare_cell_runs(
        {"status": "CLEAN", "findings": []},
        {"status": "FINDING", "findings": [{"witness": "x"}]},
    ) == {"status": "BLOCKED", "failure_code": "ORACLE_DISAGREEMENT"}
    assert compare_cell_runs(
        {"status": "EMPTY_RESULT"},
        {"status": "CLEAN"},
    ) == {"status": "UNCOVERED", "failure_code": "EMPTY_RESULT"}


def test_evidence_facts_are_digest_bound_and_independent() -> None:
    first = EvidenceFact(
        cell_id="SKILL:FUNCTIONAL_FAULT:SEMANTIC",
        invariant_id="declared-effect-vs-sink",
        defect_class_id="functional.effect",
        snapshot_digest="1" * 64,
        policy_digest="2" * 64,
        locator="fixture.py",
        predicate="read-only-function-has-effect",
        value={"effect": "write_text"},
        witness_refs=("fixture:positive",),
        method_id="native.functional.semantic",
        method_version="1.0.0",
        terminal_observation=EvidenceState.FINDING,
    )
    second = EvidenceFact(
        cell_id=first.cell_id,
        invariant_id=first.invariant_id,
        defect_class_id=first.defect_class_id,
        snapshot_digest=first.snapshot_digest,
        policy_digest=first.policy_digest,
        locator=first.locator,
        predicate=first.predicate,
        value=first.value,
        witness_refs=first.witness_refs,
        method_id="oracle.functional.semantic",
        method_version="1.0.0",
        terminal_observation=EvidenceState.FINDING,
    )

    assert first.receipt()["fact_digest"]
    assert second.receipt()["fact_digest"]
    assert compare_facts([first], [second])["comparison"] == "AGREE"
    assert compare_facts([first], [first])["failure_code"] == "SAME_METHOD"


def test_execution_oracle_and_lifecycle_receipts_validate() -> None:
    digest = "1" * 64
    execution = execution_receipt(
        receipt_kind="DETECTOR",
        cell_id="SKILL:FUNCTIONAL_FAULT:SEMANTIC",
        mechanism_id="P2-NATIVE-C03",
        tool_version="1.0.0",
        tool_digest=digest,
        argv_digest=digest,
        snapshot_digest=digest,
        policy_digest=digest,
        adapter_digest=digest,
        fact_set_digest=digest,
        terminal_status="PASS",
        failure_code=None,
    )
    oracle = oracle_receipt(
        oracle_id="oracle.functional.semantic",
        oracle_version="1.0.0",
        cell_id="SKILL:FUNCTIONAL_FAULT:SEMANTIC",
        snapshot_digest=digest,
        policy_digest=digest,
        detector_fact_ids=[],
        recomputed_fact_digest=digest,
        comparison="AGREE",
        terminal_status="PASS",
        failure_code=None,
    )
    lifecycle = lifecycle_receipt(
        cell_id="SKILL:EXCEPTION_PATH:LIFECYCLE",
        fixture_digest=digest,
        operation="ROLLBACK",
        before_tree_digest=digest,
        after_tree_digest=digest,
        discovery_receipt={"status": "AVAILABLE"},
        process_receipt={"descendants_empty": True},
        expected_residue=[],
        observed_residue=[],
        network_receipt={"policy": "DENY"},
        terminal_status="PASS",
        failure_code=None,
    )
    assert execution["receipt_digest"]
    assert oracle["receipt_digest"]
    assert lifecycle["receipt_digest"]


def test_empty_and_malformed_inputs_fail_closed() -> None:
    empty = run_cell("SKILL:FUNCTIONAL_FAULT:SEMANTIC", {"files": {}})
    assert empty["status"] == "UNCOVERED"

    malformed = run_cell(
        "SKILL:FUNCTIONAL_FAULT:SEMANTIC",
        {"files": {"broken.py": "def broken(:\n"}},
    )
    assert malformed["status"] == "BLOCKED"


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("import time; time.sleep(2)", "TIMEOUT"),
        ("import time\ndata=bytearray(32*1024*1024)\ntime.sleep(2)", "OOM"),
        ("import sys; sys.stdout.write('x'*4096)", "OUTPUT_OVERFLOW"),
    ],
)
def test_runtime_limits_block(code: str, expected: str) -> None:
    observed = run_bounded_process(
        [sys.executable, "-c", code],
        timeout=0.2,
        max_output_bytes=1024,
        max_rss_mib=32,
    )
    assert observed["status"] == expected
    assert observed["failure_code"] == expected


def test_runtime_repeatability_is_derived_from_digest_equality() -> None:
    snapshot = {
        "files": {
            "fixture.py": (
                "import os\n"
                "def run():\n"
                "    os.system('echo forbidden')\n"
                "    return True\n"
            )
        },
        "runtime_case": {
            "call": "run",
            "args": [],
            "declared_return": True,
            "forbidden_calls": ["system"],
        },
    }
    first = run_native("SKILL:RISK_EXPOSURE:RUNTIME", snapshot)
    second = run_native("SKILL:RISK_EXPOSURE:RUNTIME", snapshot)
    assert repeatability_status(first["events_digest"], second["events_digest"]) == "PASS"
    assert repeatability_status("a" * 64, "b" * 64) == "FAIL"
    repeated = runtime_repeatability("SKILL:RISK_EXPOSURE:RUNTIME", snapshot)
    assert repeated["native"]["status"] == "PASS"
    assert repeated["oracle"]["status"] == "PASS"
    assert repeated["oracle"]["first_digest"] == repeated["oracle"]["second_digest"]


def test_oracle_only_cells_do_not_require_native_detectors() -> None:
    rows = {row["cell_id"]: row for row in _registry()["dispositions"]}
    cell_id = "SKILL:FUNCTIONAL_FAULT:STATIC"
    assert rows[cell_id]["terminal_state"] == "COVERED_BY_INDEPENDENT_ORACLE"
    result = run_cell(cell_id, {"files": {}})
    assert result["oracle_only"] is True
    assert result["duplicate_measurement"] is False


def test_every_oracle_only_cell_has_an_executable_recompute() -> None:
    snapshot = {
        "files": {
            "SKILL.md": "---\nname: oracle-fixture\n---\n",
            "fixture.py": "def run():\n    return True\n",
        }
    }
    for cell_id in sorted(ORACLE_ONLY_CELLS):
        observed = run_oracle(cell_id, snapshot)
        assert observed["status"] in {"CLEAN", "FINDING", "EMPTY_RESULT"}
        assert observed["method_id"] == "oracle.standalone"


def test_merge_alias_reuses_primary_without_new_measurement() -> None:
    row = next(
        row
        for row in _registry()["dispositions"]
        if row["cell_id"] == "SKILL:LATENT_DEFECT:STATIC"
    )
    result = run_cell(row["cell_id"], {"files": {}})
    assert result["measurement_ref"] == row["primary_cell_id"]
    assert result["duplicate_measurement"] is False


def test_disabled_cell_is_blocked_taxonomy() -> None:
    coverage = build_r2_taxonomy_coverage(
        disabled_cells=("SKILL:FUNCTIONAL_FAULT:SEMANTIC",)
    )
    with pytest.raises(ContractError, match="taxonomy coverage incomplete"):
        assert_taxonomy_complete(coverage, ("SKILL",))


def test_rollback_restores_exact_bytes_and_removes_probe(tmp_path: Path) -> None:
    target = tmp_path / "probe.json"
    result = rollback_file(target, {"cell_id": "SKILL:BOUNDARY:CONTRACT"})
    assert result["status"] == "PASS"
    assert result["before_digest"] == result["restored_digest"]
    assert not target.exists()


def test_lifecycle_adapter_blocks_unavailable_capability(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "file.txt").write_text("stable\n", encoding="utf-8")
    result = run_lifecycle_transaction(
        capability_id="L05",
        fixture=fixture,
        operation="SCAN",
        action=lambda root: None,
        rollback=lambda root: None,
    )
    assert result["status"] == "BLOCKED_ADAPTER"
    assert result["failure_code"] == "CAPABILITY_UNAVAILABLE"
