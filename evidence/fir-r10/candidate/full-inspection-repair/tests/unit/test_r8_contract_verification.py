from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import cli
from full_inspection_repair.adapters import build_subject
from full_inspection_repair.contracts import (
    ContractError,
    assert_zero_open_risk,
    gate_finding_projection,
    gate_receipt_digest,
    validate_contract,
    validate_gate_receipt,
    validate_risk_ledger_consistency,
)
from full_inspection_repair.detectors import DetectorResult, run_default_detectors
from full_inspection_repair.knowledge import (
    KnowledgeError,
    load_frozen_pack,
    pack_content_digest,
)
from full_inspection_repair.ledger import build_risk_ledger
from full_inspection_repair.observation import ObservationJournal
from full_inspection_repair.taxonomy import (
    CATEGORIES,
    EVIDENCE_PLANES,
    DetectorSpec,
    build_taxonomy_coverage,
)
from full_inspection_repair.verification import (
    VerificationBlocked,
    reconcile_detector_results,
    verify_repair,
)
from full_inspection_repair.verification_matrix import (
    MatrixBlocked,
    reconcile_evaluation,
)

DIGEST = "a" * 64


def finding(*, source_id: str = "source:SKILL.md") -> dict[str, object]:
    return {
        "schema_version": 1,
        "risk_id": "finding-1",
        "invariant_id": "INV-001",
        "defect_class_id": "omission.resource",
        "taxonomy_category_id": "OMISSION",
        "subject_id": "skill:demo",
        "source_id": source_id,
        "severity": "Low",
        "message": "A required script is absent.",
        "mechanism": "The manifest omits a referenced executable.",
        "affected_refs": ["SKILL.md"],
        "root_cause_id": "root-1",
        "status": "OPEN",
        "evidence_refs": [source_id],
        "evidence_sha256": DIGEST,
        "closed_by": None,
        "closed_at": None,
        "verification_check": None,
        "residual_risk": None,
    }


def ledger(*, observed: list[str] | None = None):
    return build_risk_ledger(
        scope_digest=DIGEST,
        required_sources=["source:SKILL.md"],
        observed_sources=["source:SKILL.md"] if observed is None else observed,
        findings=[finding()],
    )


def write_taxonomy(path: Path) -> Path:
    specs = [
        DetectorSpec(
            detector_id=f"fixture.{category}.{plane}".lower(),
            detector_version="1.0.0",
            target_kinds=("SKILL",),
            category_id=category,
            evidence_plane=plane,
            oracle_id=f"fixture-oracle.{category}.{plane}".lower(),
        )
        for category in CATEGORIES
        for plane in EVIDENCE_PLANES
    ]
    coverage = build_taxonomy_coverage(("SKILL",), specs)
    path.write_text(json.dumps(coverage), encoding="utf-8")
    return path


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_generated_ledger_round_trips_to_gate_without_unknown_ids():
    value = ledger()

    validate_contract("risk-ledger", value)
    validate_risk_ledger_consistency(value)
    projected = gate_finding_projection(value)

    assert [item["finding_id"] for item in projected] == ["finding-1"]
    assert all(item["finding_id"] != "UNKNOWN" for item in projected)


def test_gate_receipt_digest_is_verified_at_the_contract_boundary():
    gate = {"schema_version": 1, "status": "PASS", "release_ready": True}
    gate["gate_digest"] = gate_receipt_digest(gate)
    validate_gate_receipt(gate)

    gate["release_ready"] = False
    with pytest.raises(ContractError, match="not a PASS"):
        validate_gate_receipt(gate)


def test_forged_ledger_denominator_and_digests_block():
    with pytest.raises(ContractError, match="observed_sources"):
        build_risk_ledger(
            scope_digest=DIGEST,
            required_sources=["source:SKILL.md"],
            findings=[],
        )

    mismatched = build_risk_ledger(
        scope_digest=DIGEST,
        required_sources=["source:SKILL.md"],
        observed_sources=["source:notes.txt"],
        findings=[],
    )
    assert mismatched["missing_sources"] == ["source:SKILL.md"]
    assert mismatched["unexpected_sources"] == ["source:notes.txt"]
    with pytest.raises(ContractError, match="missing_sources"):
        assert_zero_open_risk(mismatched)

    tampered = ledger()
    tampered["ledger_digest"] = "0" * 64
    with pytest.raises(ContractError, match="ledger_digest"):
        validate_risk_ledger_consistency(tampered)


def test_status_conditional_closure_fields_and_datetime_are_asserted():
    malformed = finding()
    malformed.update(
        {
            "status": "FIXED",
            "closed_by": DIGEST,
            "closed_at": "not-a-date",
            "verification_check": "rerun:INV-001:SKILL.md",
            "evidence_refs": [f"candidate:{DIGEST}"],
        }
    )
    with pytest.raises(ContractError, match="date-time"):
        validate_contract("finding", malformed)

    unsupported = finding()
    unsupported["status"] = "FALSE_POSITIVE"
    with pytest.raises(ContractError, match="FALSE_POSITIVE"):
        validate_contract("finding", unsupported)


def test_forged_zero_open_closure_is_rejected():
    closed = finding()
    closed.update(
        {
            "status": "FIXED",
            "closed_by": DIGEST,
            "closed_at": "2026-11-10T09:00:00Z",
            "verification_check": "receipt:not-run",
            "evidence_refs": ["source:SKILL.md"],
            "evidence_sha256": "b" * 64,
        }
    )
    with pytest.raises(ContractError, match="ledger_digest|verification|evidence"):
        value = build_risk_ledger(
            scope_digest=DIGEST,
            required_sources=["source:SKILL.md"],
            observed_sources=["source:SKILL.md"],
            findings=[closed],
        )
        assert_zero_open_risk(value)


def test_empty_truncated_and_mismatched_detector_sets_block():
    with pytest.raises(VerificationBlocked, match="empty"):
        reconcile_detector_results((), ["detector-a"])
    with pytest.raises(VerificationBlocked, match="missing"):
        reconcile_detector_results(
            (DetectorResult("detector-a", "PASS", ()),),
            ["detector-a", "detector-b"],
        )
    with pytest.raises(VerificationBlocked, match="empty"):
        verify_repair(
            original_findings=[finding()],
            candidate_results=(),
            candidate_digest=DIGEST,
            scope_digest=DIGEST,
            required_sources=["source:SKILL.md"],
            observed_sources=["source:SKILL.md"],
            expected_detector_ids=["detector-a"],
        )


def test_any_unscored_requested_case_blocks_matrix():
    with pytest.raises(MatrixBlocked, match="unscored"):
        reconcile_evaluation(
            requested=["required", "optional"],
            attempts={"required": "PASS", "optional": "UNSCORED"},
            f2p={"required"},
            p2p=set(),
        )


def test_knowledge_pack_digest_binds_content_and_evidence():
    pack = {
        "schema_version": 1,
        "pack_id": "pack-1",
        "pack_version": "1.0.0",
        "entries": [{"knowledge_id": "knowledge-1"}],
        "scope": {"target_kinds": ["SKILL"]},
        "source_evidence_digest": DIGEST,
        "shadow_replay_passed": True,
        "expires_at": None,
    }
    pack["pack_digest"] = pack_content_digest(pack)
    assert load_frozen_pack(run_pack_digest=pack["pack_digest"], requested_pack=pack)

    forged = {**pack, "entries": [{"knowledge_id": "forged"}]}
    with pytest.raises(KnowledgeError, match="content"):
        load_frozen_pack(run_pack_digest=pack["pack_digest"], requested_pack=forged)


def test_cli_blocks_write_ahead_failure_without_success_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    output = tmp_path / "run"
    taxonomy = write_taxonomy(tmp_path / "taxonomy.json")
    monkeypatch.setattr(
        cli,
        "verify_journal",
        lambda _path: {
            "status": "BLOCKED_JOURNAL",
            "failures": ["tampered"],
        },
    )

    code = cli.main(
        [
            "check",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(output),
            "--taxonomy",
            str(taxonomy),
        ]
    )

    summary = read_json(output / "summary.json")
    assert code == 2
    assert summary["status"] == "BLOCKED_EVIDENCE"
    assert summary["status"] != "CHECKED"
    assert read_json(output / "run-state.json")["current_state"] == "BLOCKED_EVIDENCE"


def test_cli_blocks_empty_observation_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    output = tmp_path / "run"
    taxonomy = write_taxonomy(tmp_path / "taxonomy.json")
    def leave_empty(journal, payload):
        journal.path.parent.mkdir(parents=True, exist_ok=True)
        journal.path.touch()
        return payload

    monkeypatch.setattr(ObservationJournal, "append", leave_empty)

    code = cli.main(
        [
            "check",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(output),
            "--taxonomy",
            str(taxonomy),
        ]
    )

    summary = read_json(output / "summary.json")
    assert code == 2
    assert summary["status"] == "BLOCKED_EVIDENCE"
    assert "empty" in summary["error"]


def test_cli_zero_findings_writes_explicit_empty_checkpoint(tmp_path: Path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo\n",
        encoding="utf-8",
    )
    output = tmp_path / "run"

    code = cli.main(
        ["check", "--target", str(source), "--kind", "SKILL", "--output", str(output)]
    )

    summary = read_json(output / "summary.json")
    manifest = read_json(output / "observation-journal-manifest.json")
    assert code == 0
    assert summary["status"] == "CHECKED"
    assert manifest["status"] == "PASS"
    assert manifest["record_count"] == 0
    assert manifest["journal_sha256"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_cli_blocks_empty_detector_set_with_structured_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    output = tmp_path / "run"
    taxonomy = write_taxonomy(tmp_path / "taxonomy.json")
    monkeypatch.setattr(cli, "run_default_detectors", lambda _subject: ())

    code = cli.main(
        [
            "check",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(output),
            "--taxonomy",
            str(taxonomy),
        ]
    )

    summary = read_json(output / "summary.json")
    assert code == 2
    assert summary["status"] == "BLOCKED_DETECTOR"
    assert summary["failure_code"] == "VerificationBlocked"


def test_cli_blocks_stale_expected_input(tmp_path: Path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    output = tmp_path / "run"
    taxonomy = write_taxonomy(tmp_path / "taxonomy.json")

    code = cli.main(
        [
            "check",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(output),
            "--taxonomy",
            str(taxonomy),
            "--expected-tree-digest",
            "0" * 64,
        ]
    )

    summary = read_json(output / "summary.json")
    assert code == 2
    assert summary["status"] == "BLOCKED_STALE_INPUT"
    state = read_json(output / "run-state.json")
    assert state["current_state"] == "BLOCKED_STALE_INPUT"
    assert state["history"][-1]["event"] == "input_drift"


def test_cli_blocks_unscored_requested_case(tmp_path: Path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    output = tmp_path / "run"
    taxonomy = write_taxonomy(tmp_path / "taxonomy.json")
    evaluation = tmp_path / "evaluation.json"
    evaluation.write_text(
        json.dumps(
            {
                "requested": ["case-a"],
                "attempts": {"case-a": "UNSCORED"},
                "f2p": ["case-a"],
                "p2p": [],
            }
        ),
        encoding="utf-8",
    )

    code = cli.main(
        [
            "check",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(output),
            "--taxonomy",
            str(taxonomy),
            "--evaluation-evidence",
            str(evaluation),
        ]
    )

    summary = read_json(output / "summary.json")
    assert code == 2
    assert summary["status"] == "BLOCKED_VERIFICATION"
    assert "unscored" in summary["error"]


def test_repair_records_candidate_stage_observations_before_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo",
        encoding="utf-8",
    )
    output = tmp_path / "run"
    candidate = tmp_path / "candidate" / "source-skill"
    taxonomy = write_taxonomy(tmp_path / "taxonomy.json")
    initial_results = run_default_detectors(build_subject(source, "SKILL"))
    finding_index = next(
        index for index, result in enumerate(initial_results) if result.findings
    )
    injected = dict(initial_results[finding_index].findings[0])
    injected.update(
        {
            "risk_id": "injected-candidate-finding",
            "invariant_id": "INJECTED-CANDIDATE-001",
            "message": "candidate introduced a finding",
            "mechanism": "verification observed a new failure",
        }
    )
    calls = 0

    def fake_detectors(subject):
        nonlocal calls
        calls += 1
        if calls == 1:
            return initial_results
        results = list(initial_results)
        results[finding_index] = DetectorResult(
            results[finding_index].detector_id,
            "FINDINGS",
            (injected,),
        )
        return tuple(results)

    monkeypatch.setattr(cli, "run_default_detectors", fake_detectors)
    code = cli.main(
        [
            "repair",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(output),
            "--candidate",
            str(candidate),
            "--taxonomy",
            str(taxonomy),
        ]
    )

    summary = read_json(output / "summary.json")
    assert code == 2
    assert summary["status"] == "BLOCKED_VERIFICATION"
    records = [
        json.loads(line)
        for line in (output / "observations.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [record["source_phase"] for record in records] == [
        "CHECK",
        "VERIFICATION",
    ]
    assert ObservationJournal(output / "observations.jsonl").verify() == 2
    assert read_json(output / "run-state.json")["current_state"] == "BLOCKED_VERIFICATION"
