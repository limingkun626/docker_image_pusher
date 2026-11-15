from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

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
from full_inspection_repair.detector_registry import default_taxonomy_coverage
from full_inspection_repair.detectors import DetectorResult, run_default_detectors
from full_inspection_repair.knowledge import (
    KnowledgeError,
    load_frozen_pack,
)
from full_inspection_repair.ledger import build_risk_ledger
from full_inspection_repair.observation import ObservationJournal
from full_inspection_repair.verification import (
    VerificationBlocked,
    reconcile_detector_results,
    verify_repair,
)
from full_inspection_repair.verification_matrix import (
    MatrixBlocked,
    reconcile_evaluation,
)
from knowledge_replay_fixture import valid_knowledge_pack

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
    coverage = default_taxonomy_coverage("SKILL")
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
            source_inventory=[
                {
                    "source_id": "source:SKILL.md",
                    "locator": "SKILL.md",
                    "sha256": DIGEST,
                    "present": True,
                }
            ],
        )
        assert_zero_open_risk(value)


def test_empty_truncated_and_mismatched_detector_sets_block():
    with pytest.raises(VerificationBlocked, match="empty"):
        reconcile_detector_results((), ["text.empty"])
    with pytest.raises(VerificationBlocked, match="missing"):
        reconcile_detector_results(
            (
                DetectorResult(
                    "text.empty",
                    "PASS",
                    (),
                    detector_version="1.0.0",
                    taxonomy_category_id="FUNCTIONAL_FAULT",
                    evidence_plane="STATIC",
                ),
            ),
            ["text.empty", "text.placeholder"],
        )
    with pytest.raises(VerificationBlocked, match="empty"):
        verify_repair(
            original_findings=[finding()],
            candidate_results=(),
            candidate_digest=DIGEST,
            scope_digest=DIGEST,
            required_sources=["source:SKILL.md"],
            observed_sources=["source:SKILL.md"],
            expected_detector_ids=["text.empty"],
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
    _candidate, pack = valid_knowledge_pack()
    assert load_frozen_pack(
        run_pack_digest=pack["pack_digest"],
        requested_pack=pack,
        target_kinds=["SKILL"],
    )

    forged = {**pack, "entries": [{"knowledge_id": "forged"}]}
    with pytest.raises(KnowledgeError, match="content"):
        load_frozen_pack(
            run_pack_digest=pack["pack_digest"],
            requested_pack=forged,
            target_kinds=["SKILL"],
        )


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


def test_identical_input_runs_have_distinct_observation_provenance(tmp_path: Path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo\n\nTODO\n",
        encoding="utf-8",
    )
    run_ids = []
    for index in (1, 2):
        output = tmp_path / f"run-{index}"
        code = cli.main(
            ["check", "--target", str(source), "--kind", "SKILL", "--output", str(output)]
        )
        assert code == 0
        first = json.loads(
            (output / "observations.jsonl").read_text(encoding="utf-8").splitlines()[0]
        )
        run_ids.append(first["source_run_id"])

    assert len(set(run_ids)) == 2
    assert all(item.startswith("run:") for item in run_ids)


def test_run_state_provenance_is_independent_of_subject_content(tmp_path: Path):
    first = cli._RunState(tmp_path / "one" / "run-state.json")
    second = cli._RunState(tmp_path / "two" / "run-state.json")

    assert first.run_id != second.run_id
    assert read_json(first.path)["run_id"] == first.run_id
    assert read_json(second.path)["run_id"] == second.run_id


def test_cli_persists_write_ahead_high_water_and_rejects_pair_truncation(
    tmp_path: Path,
):
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
    assert code == 0

    journal_path = output / "write-ahead-journal.jsonl"
    checkpoint = cli.load_journal_checkpoint(
        output / "write-ahead-journal-checkpoint.json"
    )
    lines = journal_path.read_bytes().splitlines(keepends=True)
    journal_path.write_bytes(b"".join(lines[:2]))

    with pytest.raises(cli.EvidenceBlocked, match="high_water"):
        cli._require_journal_pass(journal_path, checkpoint)


def test_observations_redact_secrets_pii_and_bind_redacted_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    subject = SimpleNamespace(
        subject_id="skill:redaction",
        subject_kind="SKILL",
        tree_digest=DIGEST,
    )
    finding_value = finding()
    finding_value.update(
        {
            "message": (
                "token=super-secret-value owner alice@example.com "
                "ssn 123-45-6789 key sk-abcdefghijklmnop"
            ),
            "mechanism": "password=hunter2 at C:\\Users\\alice\\secret.txt",
            "root_cause_id": "root-redaction",
            "evidence_refs": ["C:\\Users\\alice\\evidence.json"],
        }
    )
    payload = cli._observation_payload(
        subject,
        finding_value,
        source_phase="CHECK",
        source_run_id="run:redaction",
    )
    rendered = json.dumps(payload)

    for secret in (
        "super-secret-value",
        "alice@example.com",
        "123-45-6789",
        "sk-abcdefghijklmnop",
        "hunter2",
        "alice",
    ):
        assert secret not in rendered
    assert payload["evidence_sha256"] != finding_value["evidence_sha256"]

    original = cli._redaction_policy_digest()
    monkeypatch.setattr(cli, "REDACTION_POLICY_VERSION", "2.0.1")
    assert cli._redaction_policy_digest() != original


def test_manifest_uses_exact_pack_identity_and_rejects_pair_drift(tmp_path: Path):
    (tmp_path / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    subject = build_subject(tmp_path, "SKILL")
    taxonomy = default_taxonomy_coverage("SKILL")
    manifest = cli._subject_manifest(subject, taxonomy)

    cli._assert_manifest_pack_identity(manifest, "SKILL", taxonomy)
    assert manifest["knowledge_pack_id"] == "default-v0"
    manifest["knowledge_pack_id"] = "default"
    with pytest.raises(ContractError, match="ID/digest mismatch"):
        cli._assert_manifest_pack_identity(manifest, "SKILL", taxonomy)


def test_cli_uses_documented_adapter_and_taxonomy_statuses(tmp_path: Path):
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    taxonomy = default_taxonomy_coverage("SKILL")
    taxonomy["cells"] = taxonomy["cells"][:-1]
    taxonomy["coverage_digest"] = cli.canonical_digest(
        {key: value for key, value in taxonomy.items() if key != "coverage_digest"}
    )
    taxonomy_path = tmp_path / "taxonomy.json"
    taxonomy_path.write_text(json.dumps(taxonomy), encoding="utf-8")

    taxonomy_output = tmp_path / "taxonomy-run"
    taxonomy_code = cli.main(
        [
            "check",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(taxonomy_output),
            "--taxonomy",
            str(taxonomy_path),
        ]
    )
    adapter_output = tmp_path / "adapter-run"
    adapter_code = cli.main(
        [
            "check",
            "--target",
            str(tmp_path / "missing"),
            "--kind",
            "SKILL",
            "--output",
            str(adapter_output),
        ]
    )

    assert taxonomy_code == 2
    assert read_json(taxonomy_output / "summary.json")["status"] == "BLOCKED_TAXONOMY"
    assert adapter_code == 2
    assert read_json(adapter_output / "summary.json")["status"] == "BLOCKED_ADAPTER"
    assert read_json(adapter_output / "summary.json")["failure_code"] == "AdapterError"


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
            detector_version=results[finding_index].detector_version,
            taxonomy_category_id=results[finding_index].taxonomy_category_id,
            evidence_plane=results[finding_index].evidence_plane,
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
