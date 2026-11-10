from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.adapters import build_subject
from full_inspection_repair.contracts import ContractError, canonical_digest
from full_inspection_repair.impact import assert_impact_closed, build_impact_graph


def _finding(target: str, risk_id: str = "r8-finding") -> dict[str, object]:
    return {
        "risk_id": risk_id,
        "invariant_id": "R8-IMPACT-001",
        "source_id": f"source:{target}",
        "affected_refs": [target],
        "root_cause_id": "r8-root",
    }


def _python_subject(root: Path):
    (root / "pkg").mkdir()
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (root / "pkg" / "a.py").write_text(
        "from . import b\n"
        "from .missing import Nope\n"
        "import requests\n",
        encoding="utf-8",
    )
    (root / "pkg" / "b.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "app.py").write_text(
        "from pkg.a import VALUE\n",
        encoding="utf-8",
    )
    return build_subject(root, "PROJECT")


def test_ast_imports_resolve_relative_internal_and_expose_unresolved(
    tmp_path: Path,
) -> None:
    subject = _python_subject(tmp_path)

    graph = build_impact_graph(subject, [_finding("pkg/b.py")])

    edge_pairs = {(edge["from"], edge["to"], edge["kind"]) for edge in graph["edges"]}
    assert (
        "file:pkg/a.py",
        "file:pkg/b.py",
        "IMPORTS",
    ) in edge_pairs
    assert (
        "file:app.py",
        "file:pkg/a.py",
        "IMPORTS",
    ) in edge_pairs
    assert any(
        record["kind"] == "EXTERNAL" and record["module"] == "requests"
        for record in graph["imports"]
    )
    assert any(
        record["kind"] == "UNRESOLVED"
        and record["module"] == ".missing"
        for record in graph["imports"]
    )
    assert any(
        node["kind"] == "EXTERNAL_IMPORT" for node in graph["nodes"]
    )
    assert any(
        node["kind"] == "UNRESOLVED_IMPORT" for node in graph["nodes"]
    )


def test_impact_closure_follows_transitive_consumers(tmp_path: Path) -> None:
    subject = _python_subject(tmp_path)
    graph = build_impact_graph(subject, [_finding("pkg/b.py")])

    closure = graph["finding_closure"]["finding:r8-finding"]

    assert closure["consumers"] == ["file:app.py", "file:pkg/a.py"]
    assert_impact_closed(graph)


def test_impact_closure_rejects_shallow_or_tampered_closure(
    tmp_path: Path,
) -> None:
    subject = _python_subject(tmp_path)
    graph = build_impact_graph(subject, [_finding("pkg/b.py")])
    tampered = copy.deepcopy(graph)
    tampered["edges"] = [
        edge
        for edge in tampered["edges"]
        if (edge["from"], edge["to"], edge["kind"])
        != ("file:app.py", "file:pkg/a.py", "IMPORTS")
    ]
    tampered["graph_digest"] = canonical_digest(
        {key: value for key, value in tampered.items() if key != "graph_digest"}
    )

    with pytest.raises(ContractError, match="incomplete impact closure"):
        assert_impact_closed(tampered)


def test_no_consumer_requires_explicit_evidence_backed_proof(
    tmp_path: Path,
) -> None:
    (tmp_path / "notes.md").write_text("# Notes\n", encoding="utf-8")
    subject = build_subject(tmp_path, "ARTICLE")
    graph = build_impact_graph(subject, [_finding("notes.md")])

    proof = graph["no_consumer_proofs"]["file:notes.md"]
    assert proof["evidence_digest"]
    assert proof["scanned_sources"]
    assert_impact_closed(graph)

    graph["no_consumer_proofs"].pop("file:notes.md")
    graph["graph_digest"] = canonical_digest(
        {key: value for key, value in graph.items() if key != "graph_digest"}
    )
    with pytest.raises(ContractError, match="incomplete impact closure"):
        assert_impact_closed(graph)
