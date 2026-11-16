from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import cli
from full_inspection_repair.adapters import build_subject
from full_inspection_repair.contracts import ContractError
from full_inspection_repair.impact import (
    assert_impact_closed,
    build_impact_graph,
    cluster_roots,
)


def finding():
    return {
        "risk_id": "finding-1",
        "invariant_id": "TEST-001",
        "source_id": "source:SKILL.md",
        "affected_refs": ["SKILL.md"],
        "root_cause_id": "root-1",
    }


def test_impact_graph_links_findings_and_local_references(tmp_path):
    (tmp_path / "references").mkdir()
    (tmp_path / "SKILL.md").write_text(
        "# Demo\n\nSee [guide](references/guide.md).\n",
        encoding="utf-8",
    )
    (tmp_path / "references" / "guide.md").write_text("guide\n", encoding="utf-8")
    subject = build_subject(tmp_path, "SKILL")

    graph = build_impact_graph(subject, [finding()])

    assert {
        "file:SKILL.md",
        "file:references/guide.md",
        "finding:finding-1",
    }.issubset({node["id"] for node in graph["nodes"]})
    assert {
        ("finding:finding-1", "file:SKILL.md"),
        ("file:SKILL.md", "file:references/guide.md"),
    }.issubset({(edge["from"], edge["to"]) for edge in graph["edges"]})
    assert_impact_closed(graph)


def test_impact_graph_rejects_unresolved_finding_target(tmp_path):
    (tmp_path / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    subject = build_subject(tmp_path, "SKILL")
    graph = build_impact_graph(
        subject,
        [{**finding(), "affected_refs": ["missing.md"]}],
    )

    with pytest.raises(ContractError, match="unresolved impact"):
        assert_impact_closed(graph)


def test_candidate_impact_artifact_rejects_unresolved_reference(tmp_path):
    (tmp_path / "SKILL.md").write_text(
        "# Demo\n\nSee [missing](missing.md).\n",
        encoding="utf-8",
    )
    graph = build_impact_graph(build_subject(tmp_path, "SKILL"), [finding()])

    with pytest.raises(ContractError, match="unresolved reference"):
        cli._candidate_impact_artifact(
            graph,
            {
                "run_id": "run:test",
                "scope_digest": "a" * 64,
                "subject": {"tree_digest": "b" * 64},
                "candidate_digest": "c" * 64,
            },
        )


def test_candidate_impact_artifact_counts_actual_unresolved_kinds(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(cli, "assert_impact_closed", lambda _graph: None)
    artifact = cli._candidate_impact_artifact(
        {
            "nodes": [
                {"id": "import:missing", "kind": "UNRESOLVED_IMPORT"},
                {"id": "finding:open", "kind": "FINDING"},
            ],
            "finding_closure": {
                "finding:open": {"status": "OPEN_TERMINAL_EVIDENCE"},
            },
        },
        {
            "run_id": "run:test",
            "scope_digest": "a" * 64,
            "subject": {"tree_digest": "b" * 64},
            "candidate_digest": "c" * 64,
        },
    )

    assert artifact["unresolved_count"] == 2


def test_shared_root_retains_every_child_finding():
    findings = [
        {**finding(), "risk_id": "finding-a", "root_cause_id": "root-shared"},
        {**finding(), "risk_id": "finding-b", "root_cause_id": "root-shared"},
    ]

    roots = cluster_roots(findings)

    assert len(roots) == 1
    assert roots[0]["root_id"] == "root-shared"
    assert roots[0]["finding_ids"] == ["finding-a", "finding-b"]
