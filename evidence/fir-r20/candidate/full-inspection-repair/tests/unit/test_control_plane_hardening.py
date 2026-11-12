from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import protected_reader
from full_inspection_repair.adapters import build_required_sources, build_subject
from full_inspection_repair.cli import _taxonomy_context
from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.coverage import build_complete_coverage
from full_inspection_repair.detector_registry import default_taxonomy_coverage
from full_inspection_repair.detectors import DetectorResult, run_default_detectors
from full_inspection_repair.impact import build_impact_graph
from full_inspection_repair.ledger import build_risk_ledger
from full_inspection_repair.package import PackageError, build_package_manifest
from full_inspection_repair.release import ReleaseBlocked, build_release_claim
from full_inspection_repair.repair import apply_batch, plan_batch
from full_inspection_repair.strict import StrictJSONError, strict_loads
from full_inspection_repair.taxonomy_qualification import qualify_taxonomy
from full_inspection_repair.verification import verify_repair


def test_strict_json_rejects_duplicate_keys_and_non_finite() -> None:
    with pytest.raises(StrictJSONError, match="duplicate key"):
        strict_loads('{"a":1,"a":2}')
    with pytest.raises(StrictJSONError, match="non-finite"):
        strict_loads('{"a":NaN}')


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory fd contract")
def test_posix_snapshot_reads_file_with_repeated_short_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    expected = b"0123456789"
    (source / "value.txt").write_bytes(expected)
    reads = iter([expected[:3], expected[3:], expected[:2], expected[2:]])
    monkeypatch.setattr(protected_reader.os, "read", lambda _fd, _size: next(reads))

    snapshot = protected_reader._walk_posix(source)

    item = snapshot["sources"][0]
    assert item["content"] == expected
    assert item["two_reads_equal"] is True


def test_missing_skill_entrypoint_is_an_addressable_finding(tmp_path: Path) -> None:
    root = tmp_path / "missing-skill"
    root.mkdir()
    subject = build_subject(root, "SKILL")
    findings = [
        finding
        for result in run_default_detectors(subject)
        for finding in result.findings
    ]
    sources = build_required_sources(subject)

    ledger = build_risk_ledger(
        scope_digest=subject.tree_digest,
        required_sources=[item["source_id"] for item in sources],
        findings=findings,
        present_sources=[],
    )

    assert ledger["open_count"] == 1
    assert ledger["missing_sources"] == ["source:SKILL.md"]


def test_protected_snapshot_carries_same_handle_identity(tmp_path: Path) -> None:
    root = tmp_path / "subject"
    root.mkdir()
    (root / "SKILL.md").write_text("# Demo\n", encoding="utf-8")

    subject = build_subject(root, "SKILL")

    assert subject.files[0].metadata["same_handle"] is True
    assert subject.files[0].metadata["two_reads_equal"] is True
    assert subject.files[0].metadata["named_streams"] == []
    assert subject.files[0].metadata["file_id"]


def test_verification_keeps_candidate_new_findings_open(tmp_path: Path) -> None:
    root = tmp_path / "source-skill"
    root.mkdir()
    (root / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    subject = build_subject(root, "SKILL")
    original = [
        {
            "risk_id": "old",
            "invariant_id": "OLD",
            "source_id": "source:SKILL.md",
            "affected_refs": ["SKILL.md"],
            "root_cause_id": "root-old",
            "status": "OPEN",
            "evidence_refs": ["source:SKILL.md"],
            "evidence_sha256": "a" * 64,
            "closed_by": None,
            "closed_at": None,
            "verification_check": None,
            "residual_risk": None,
            "taxonomy_category_id": "FUNCTIONAL_FAULT",
            "defect_class_id": "old",
            "subject_id": subject.subject_id,
            "severity": "Low",
            "message": "old",
            "mechanism": "old",
        }
    ]
    new = {**original[0], "risk_id": "new", "invariant_id": "NEW"}
    ledger = verify_repair(
        original_findings=original,
        candidate_results=(
            DetectorResult(
                "text.empty",
                "FINDINGS",
                (new,),
                detector_version="1.0.0",
                taxonomy_category_id="FUNCTIONAL_FAULT",
                evidence_plane="STATIC",
            ),
        ),
        candidate_digest="b" * 64,
        scope_digest="c" * 64,
        required_sources=["source:SKILL.md"],
        expected_detector_ids=["text.empty"],
    )

    assert ledger["open_count"] == 1
    assert ledger["items"][-1]["risk_id"] == "new"


def test_verification_does_not_collapse_new_findings_with_shared_key() -> None:
    base = {
        "risk_id": "new-a",
        "invariant_id": "SHARED",
        "source_id": "source:SKILL.md",
        "affected_refs": ["SKILL.md"],
        "root_cause_id": "root-a",
        "status": "OPEN",
        "evidence_refs": ["source:SKILL.md"],
        "evidence_sha256": "a" * 64,
        "closed_by": None,
        "closed_at": None,
        "verification_check": None,
        "residual_risk": None,
        "taxonomy_category_id": "FUNCTIONAL_FAULT",
        "defect_class_id": "new-a",
        "subject_id": "subject",
        "severity": "High",
        "message": "new-a",
        "mechanism": "new-a",
    }
    second = {
        **base,
        "risk_id": "new-b",
        "root_cause_id": "root-b",
        "defect_class_id": "new-b",
        "message": "new-b",
        "mechanism": "new-b",
    }
    ledger = verify_repair(
        original_findings=[],
        candidate_results=(
            DetectorResult(
                "text.empty",
                "FINDINGS",
                (base, second),
                detector_version="1.0.0",
                taxonomy_category_id="FUNCTIONAL_FAULT",
                evidence_plane="STATIC",
            ),
        ),
        candidate_digest="b" * 64,
        scope_digest="c" * 64,
        required_sources=["source:SKILL.md"],
        expected_detector_ids=["text.empty"],
    )

    assert [item["risk_id"] for item in ledger["items"]] == ["new-a", "new-b"]
    assert ledger["open_count"] == 2


def test_taxonomy_executes_720_qualification_controls(tmp_path: Path) -> None:
    root = tmp_path / "demo-skill"
    root.mkdir()
    (root / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    subject = build_subject(root, "SKILL")
    results = run_default_detectors(subject)
    findings = [finding for result in results for finding in result.findings]
    sources = [f"source:{item.locator}" for item in subject.files]
    ledger = build_risk_ledger(
        scope_digest=subject.tree_digest,
        required_sources=sources,
        findings=findings,
        present_sources=sources,
    )
    taxonomy = default_taxonomy_coverage("SKILL")
    impact = build_impact_graph(subject, findings)
    coverage = build_complete_coverage(
        {item.locator: item.content for item in subject.files}
    )
    context = _taxonomy_context(
        subject,
        results,
        findings,
        ledger,
        taxonomy,
        impact,
        coverage,
    )

    report = qualify_taxonomy(taxonomy, context)

    assert report["cell_count"] == 72
    assert report["qualified_count"] == 72
    assert report["control_count"] == 720
    assert report["all_passed"] is True


def test_repair_receipt_uses_candidate_tree_digest(tmp_path: Path) -> None:
    root = tmp_path / "source-skill"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo",
        encoding="utf-8",
    )
    subject = build_subject(root, "SKILL")
    findings = [
        finding
        for result in run_default_detectors(subject)
        for finding in result.findings
    ]
    candidate = tmp_path / "candidate" / "source-skill"
    receipt = apply_batch(subject, plan_batch(findings), candidate)

    assert receipt["candidate_digest"] == build_subject(candidate, "SKILL").tree_digest
    assert receipt["candidate_digest"] != receipt["receipt_digest"]


def test_package_rejects_runtime_cache_and_fake_review(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    (source / "__pycache__").mkdir()
    (source / "__pycache__" / "x.pyc").write_bytes(b"x")

    with pytest.raises(PackageError, match="runtime cache"):
        build_package_manifest(source)

    fake = {
        "producer": "agent-a",
        "reviewer": "agent-b",
        "verdict": "PASS",
        "subject": {"open_count": 0, "residual_risks": []},
        "subject_digest": canonical_digest(
            {"open_count": 0, "residual_risks": []}
        ),
    }
    with pytest.raises(ReleaseBlocked, match="missing"):
        build_release_claim(fake)
