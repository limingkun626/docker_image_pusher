from __future__ import annotations

import copy
import json
import multiprocessing
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from full_inspection_repair import detector_registry
from full_inspection_repair.adapters import build_subject
from full_inspection_repair.contracts import (
    ContractError,
    assert_zero_open_risk,
    canonical_digest,
)
from full_inspection_repair.coverage import (
    CoverageError,
    build_complete_coverage,
    verify_complete_coverage,
)
from full_inspection_repair.detector_registry import default_taxonomy_coverage
from full_inspection_repair.detectors import (
    DetectorResult,
    detect_latent_markers,
    detect_placeholders,
    run_default_detectors,
)
from full_inspection_repair.impact import assert_impact_closed, build_impact_graph
from full_inspection_repair.knowledge import (
    KnowledgeError,
    load_frozen_pack,
)
from full_inspection_repair.ledger import build_risk_ledger
from full_inspection_repair.observation import (
    ObservationJournal,
    _exclusive_append_lock,
)
from full_inspection_repair.taxonomy import (
    assert_taxonomy_complete,
)
from full_inspection_repair.taxonomy_qualification import qualify_taxonomy
from full_inspection_repair.verification import VerificationBlocked, verify_repair
from knowledge_replay_fixture import resign_pack, valid_knowledge_pack

DIGEST = "a" * 64


def _skill(root: Path, body: str = "# Demo\n") -> Path:
    root.mkdir()
    (root / "SKILL.md").write_text(
        f"---\nname: {root.name}\n---\n\n{body}", encoding="utf-8"
    )
    return root


def _finding(target: str = "SKILL.md") -> dict[str, object]:
    return {
        "schema_version": 1,
        "risk_id": "finding-1",
        "invariant_id": "TEST-001",
        "defect_class_id": "test.finding",
        "taxonomy_category_id": "FUNCTIONAL_FAULT",
        "subject_id": "skill:test",
        "source_id": f"source:{target}",
        "severity": "Low",
        "message": "test",
        "mechanism": "test",
        "affected_refs": [target],
        "root_cause_id": "root-1",
        "status": "OPEN",
        "evidence_refs": [f"source:{target}"],
        "evidence_sha256": DIGEST,
        "closed_by": None,
        "closed_at": None,
        "verification_check": None,
        "residual_risk": None,
    }


def _receipt(consumer: str, subject_digest: str) -> dict[str, object]:
    receipt: dict[str, object] = {
        "consumer": consumer,
        "command": "python -m pytest -q tests/consumer",
        "exit_code": 0,
        "subject_digest": subject_digest,
        "verifier_id": "pytest",
        "verifier_version": "8.3.4",
        "verifier_sha256": "d" * 64,
    }
    receipt["receipt_sha256"] = canonical_digest(receipt)
    return receipt


def test_pipe_002_missing_canonical_detector_cannot_become_na(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = "text.placeholder"
    monkeypatch.setattr(
        detector_registry,
        "DEFAULT_DETECTORS",
        tuple(item for item in detectors_without(missing)),
    )

    with pytest.raises((ContractError, ValueError), match="canonical detector"):
        default_taxonomy_coverage("SKILL")


def detectors_without(detector_id: str):
    return tuple(
        item for item in detector_registry.DEFAULT_DETECTORS if item[0] != detector_id
    )


def test_pipe_003_qualification_is_target_kind_and_declared_id_bound() -> None:
    coverage = default_taxonomy_coverage("SKILL")
    exact = {}
    for cell in (item for item in coverage["cells"] if item["detector_ids"]):
        key = (
            f"{cell['target_kind']}:{cell['category_id']}:"
            f"{cell['evidence_plane']}"
        )
        exact[key] = {
            "subject_digest": DIGEST,
            "detector": {
                "id": cell["detector_ids"][0],
                "passed": True,
                "observations": {
                    "category": cell["category_id"],
                    "plane": cell["evidence_plane"],
                },
            },
            "oracle": {
                "id": cell["oracle_ids"][0],
                "passed": True,
                "observations": {
                    "category": cell["category_id"],
                    "plane": cell["evidence_plane"],
                },
            },
        }
    positive = qualify_taxonomy(
        coverage,
        {
            "tree_digest": DIGEST,
            "target_kinds": ["SKILL"],
            "cell_evidence": exact,
        },
    )
    assert positive["all_passed"] is True

    shared = copy.deepcopy(exact)
    bound_cell = next(cell for cell in coverage["cells"] if cell["detector_ids"])
    cell_key = (
        f"{bound_cell['target_kind']}:{bound_cell['category_id']}:"
        f"{bound_cell['evidence_plane']}"
    )
    shared[cell_key]["detector"]["id"] = "legacy.alias.detector"

    report = qualify_taxonomy(
        coverage,
        {
            "tree_digest": DIGEST,
            "target_kinds": ["SKILL"],
            "cell_evidence": shared,
        },
    )

    assert report["all_passed"] is False


def test_pipe_005_python_markers_without_literal_false_positive(
    tmp_path: Path,
) -> None:
    root = _skill(tmp_path / "demo-skill")
    (root / "code.py").write_text(
        'EXAMPLES = ["TODO", "FIXME"]\n'
        "# TODO implement\n"
        "def work():\n"
        '    """FIXME preserve this debt marker."""\n'
        "    return 1\n",
        encoding="utf-8",
    )
    (root / "guide.md").write_text(
        "Use `TODO` literally.\n```text\nFIXME example\n```\n",
        encoding="utf-8",
    )
    subject = build_subject(root, "SKILL")

    placeholders = detect_placeholders(subject)
    latent = detect_latent_markers(subject)

    assert any("code.py" in item["affected_refs"] for item in placeholders)
    assert any("code.py" in item["affected_refs"] for item in latent)
    assert not any("guide.md" in item["affected_refs"] for item in placeholders)
    assert not any("guide.md" in item["affected_refs"] for item in latent)


def test_pipe_007_dynamic_import_is_resolved_or_explicitly_unresolved(
    tmp_path: Path,
) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "a.py").write_text(
        "import importlib as il\n"
        "mode = '.b'\n"
        "il.import_module(mode, __package__)\n"
        "il.import_module('.b', __package__)\n"
        "il.import_module(mode, __package__)\n",
        encoding="utf-8",
    )
    (tmp_path / "pkg" / "b.py").write_text("VALUE = 1\n", encoding="utf-8")
    subject = build_subject(tmp_path, "PROJECT")

    graph = build_impact_graph(subject, [_finding("pkg/b.py")])

    assert {
        "from": "file:pkg/a.py",
        "to": "file:pkg/b.py",
        "kind": "IMPORTS_DYNAMIC",
    } in graph["edges"]
    assert any(
        item["kind"] == "UNRESOLVED"
        and item["module"] == "<dynamic>"
        for item in graph["imports"]
    )


def test_pipe_008_consumers_require_trusted_execution_receipts(
    tmp_path: Path,
) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "a.py").write_text("from . import b\n", encoding="utf-8")
    (tmp_path / "pkg" / "b.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("from pkg.a import VALUE\n", encoding="utf-8")
    subject = build_subject(tmp_path, "PROJECT")
    graph = build_impact_graph(subject, [_finding("pkg/b.py")])

    with pytest.raises(ContractError, match="terminal evidence"):
        assert_impact_closed(graph)

    receipts = {
        consumer: [_receipt(consumer, subject.tree_digest)]
        for consumer in ("file:app.py", "file:pkg/a.py")
    }
    verified = build_impact_graph(
        subject, [_finding("pkg/b.py")], consumer_receipts=receipts
    )
    assert_impact_closed(verified)


def test_pipe_010_verification_requires_frozen_detector_set() -> None:
    original = _finding()
    with pytest.raises(VerificationBlocked, match="expected detector"):
        verify_repair(
            original_findings=[original],
            candidate_results=(DetectorResult("rogue", "PASS", ()),),
            candidate_digest="b" * 64,
            scope_digest=DIGEST,
            required_sources=["source:SKILL.md"],
            observed_sources=["source:SKILL.md"],
        )

    with pytest.raises(VerificationBlocked, match="unknown detector"):
        verify_repair(
            original_findings=[original],
            candidate_results=(DetectorResult("rogue", "PASS", ()),),
            candidate_digest="b" * 64,
            scope_digest=DIGEST,
            required_sources=["source:SKILL.md"],
            observed_sources=["source:SKILL.md"],
            expected_detector_ids=["rogue"],
        )


def test_pipe_012_frozen_pack_requires_scope_review_and_replay() -> None:
    _candidate, base = valid_knowledge_pack()
    missing_replay = {**base}
    evidence = dict(missing_replay["replay_evidence"])
    evidence["receipts"] = {
        key: value
        for key, value in evidence["receipts"].items()
        if key != "SHADOW_REPLAY"
    }
    missing_replay["replay_evidence"] = evidence
    cases = (
        (
            resign_pack({**base, "scope": {"target_kinds": ["PLAN"]}}),
            "pack identity|scope",
        ),
        (resign_pack({**base, "reviewed_by": None}), "reviewer"),
        (resign_pack(missing_replay), "executed replay|shadow replay"),
    )

    for pack, error in cases:
        if "pack_digest" not in pack:
            pack = resign_pack(pack)
        with pytest.raises(KnowledgeError, match=error):
            load_frozen_pack(
                run_pack_digest=str(pack["pack_digest"]),
                requested_pack=pack,
                target_kinds=["SKILL"],
            )


def test_pipe_015_na_proof_rejects_dangling_evidence() -> None:
    coverage = default_taxonomy_coverage("SKILL")
    cell = next(item for item in coverage["cells"] if item["not_applicable_proof"])
    proof = json.loads(cell["not_applicable_proof"])
    proof["evidence_refs"].append("missing:dangling-evidence")
    proof["evidence_digest"] = canonical_digest(
        {key: value for key, value in proof.items() if key != "evidence_digest"}
    )
    cell["not_applicable_proof"] = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    coverage["coverage_digest"] = canonical_digest(
        {key: value for key, value in coverage.items() if key != "coverage_digest"}
    )

    with pytest.raises(ContractError, match="taxonomy coverage incomplete"):
        assert_taxonomy_complete(coverage, ("SKILL",))


def _append_concurrently(path: str, barrier, message: str) -> None:
    payload = {
        "source_run_id": "run-1",
        "source_phase": "CHECK",
        "producer_id": "probe",
        "subject_id": "skill:demo",
        "subject_kind": "SKILL",
        "subject_digest": DIGEST,
        "invariant_id": "INV-001",
        "defect_class_id": "test.finding",
        "taxonomy_category_id": "FUNCTIONAL_FAULT",
        "fingerprint": "probe",
        "fingerprint_version": "1.0.0",
        "message": message,
        "mechanism": "concurrency",
        "root_cause_hypothesis": None,
        "evidence_refs": ["evidence/probe.json"],
        "evidence_sha256": DIGEST,
        "redaction_policy_digest": DIGEST,
        "severity": "Low",
        "analogous_surfaces": [],
        "status": "CONFIRMED",
        "safe_feedback": "serialize append",
        "recorded_at": "2026-11-10T12:00:00Z",
    }
    barrier.wait()
    ObservationJournal(path).append(payload)


def test_r11_pipeline_001_cross_process_append_is_serialized(tmp_path: Path) -> None:
    path = str(tmp_path / "observations.jsonl")
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    processes = [
        context.Process(target=_append_concurrently, args=(path, barrier, message))
        for message in ("first", "second")
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
    assert [process.exitcode for process in processes] == [0, 0]
    journal = ObservationJournal(path)
    assert journal.verify() == 2
    assert [item["journal_sequence"] for item in journal._records(require_nonempty=True)] == [
        1,
        2,
    ]


def test_r11_pipeline_001_lock_timeout_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "observations.jsonl.lock"
    with (
        _exclusive_append_lock(path, timeout=1.0),
        pytest.raises(ContractError, match="lock timeout"),
        _exclusive_append_lock(path, timeout=0.05),
    ):
        pass


def test_r11_pipeline_002_python_parse_failure_cannot_pass_semantics(
    tmp_path: Path,
) -> None:
    root = _skill(tmp_path / "demo-skill")
    (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    subject = build_subject(root, "SKILL")

    results = run_default_detectors(subject)
    by_id = {result.detector_id: result for result in results}

    assert any(
        item["taxonomy_category_id"] == "BOUNDARY"
        for item in by_id["text.boundary"].findings
    )
    assert by_id["python.exception-swallow"].status == "BLOCKED"
    assert by_id["security.dangerous-pattern"].status == "BLOCKED"


def test_r11_pipeline_003_ledger_requires_source_inventory(tmp_path: Path) -> None:
    root = _skill(tmp_path / "demo-skill")
    subject = build_subject(root, "SKILL")
    ok_inventory = [
        {
            "source_id": f"source:{item.locator}",
            "locator": item.locator,
            "sha256": item.sha256,
            "present": True,
        }
        for item in subject.files
    ]
    build_risk_ledger(
        scope_digest=subject.tree_digest,
        required_sources=["source:SKILL.md"],
        observed_sources=["source:SKILL.md"],
        findings=[],
        source_inventory=ok_inventory,
    )

    with pytest.raises(ContractError, match="source inventory"):
        build_risk_ledger(
            scope_digest=subject.tree_digest,
            required_sources=["source:ghost"],
            observed_sources=["source:ghost"],
            findings=[],
            source_inventory=[
                {"source_id": "source:ghost", "locator": "ghost", "present": True}
            ],
        )

    unbound = build_risk_ledger(
        scope_digest=subject.tree_digest,
        required_sources=["source:ghost"],
        observed_sources=["source:ghost"],
        findings=[],
    )
    with pytest.raises(ContractError, match="residual_risks"):
        assert_zero_open_risk(unbound)


def test_r11_pipeline_004_whitespace_coverage_is_bounded() -> None:
    content = {"SKILL.md": b" " * 20_000}
    report = build_complete_coverage(content, max_derived_bytes=64_000)

    assert len(json.dumps(report, separators=(",", ":")).encode()) < 64_000
    assert report["whitespace_control_runs"]
    with pytest.raises(CoverageError, match="budget"):
        build_complete_coverage(content, max_derived_bytes=1_000)


def test_r8_rt_005_sentence_view_has_no_whitespace_only_unit() -> None:
    report = build_complete_coverage({"SKILL.md": "第一句。第二句。\n".encode()})
    record = report["files"][0]

    assert all(
        any(not character.isspace() for character in item["text"])
        for item in record["sentence_units"]
    )
    assert record["sentence_covered_codepoints"] == record["codepoint_count"]


def test_r8_rt_006_coverage_report_rejects_unknown_fields() -> None:
    content = {"SKILL.md": b"# Demo.\n"}
    report = build_complete_coverage(content)
    report["unexpected_extension"] = True
    report["coverage_digest"] = canonical_digest(
        {key: value for key, value in report.items() if key != "coverage_digest"}
    )

    assert "schema" in verify_complete_coverage(content, report)
