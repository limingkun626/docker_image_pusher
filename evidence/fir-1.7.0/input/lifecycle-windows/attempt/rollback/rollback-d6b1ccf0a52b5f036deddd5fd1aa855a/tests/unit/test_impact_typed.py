from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.adapters import build_subject
from full_inspection_repair.contracts import ContractError
from full_inspection_repair.impact import assert_impact_closed, build_impact_graph


def _finding(target: str) -> dict[str, object]:
    return {
        "risk_id": "typed-impact",
        "invariant_id": "TYPED-IMPACT",
        "source_id": f"source:{target}",
        "affected_refs": [target],
        "root_cause_id": "typed-root",
    }


def test_t_imp_01_shell_and_powershell_commands_are_typed(tmp_path: Path) -> None:
    (tmp_path / "run.ps1").write_text(
        "pwsh scripts/check.ps1\n", encoding="utf-8"
    )
    (tmp_path / "run.sh").write_text(
        'bash "scripts/check.sh"\n', encoding="utf-8"
    )
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "check.ps1").write_text("", encoding="utf-8")
    (tmp_path / "scripts" / "check.sh").write_text("", encoding="utf-8")
    graph = build_impact_graph(
        build_subject(tmp_path, "PROJECT"), [_finding("scripts/check.ps1")]
    )

    assert any(edge["kind"] == "COMMAND_REF" for edge in graph["edges"])


def test_t_imp_02_json_config_reference_is_typed(tmp_path: Path) -> None:
    (tmp_path / "workflow.json").write_text(
        '{"entry":"scripts/check.ps1"}\n', encoding="utf-8"
    )
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "check.ps1").write_text("", encoding="utf-8")
    graph = build_impact_graph(
        build_subject(tmp_path, "PROJECT"), [_finding("scripts/check.ps1")]
    )

    assert any(edge["kind"] == "CONFIG_REF" for edge in graph["edges"])


def test_t_imp_03_unsupported_consumer_blocks_no_consumer_proof(
    tmp_path: Path,
) -> None:
    (tmp_path / "target.txt").write_text("target\n", encoding="utf-8")
    (tmp_path / "consumer.unknown").write_text(
        "target.txt\n", encoding="utf-8"
    )
    graph = build_impact_graph(
        build_subject(tmp_path, "ARTICLE"), [_finding("target.txt")]
    )

    assert "consumer.unknown" in graph["unsupported_sources"]
    with pytest.raises(ContractError, match="incomplete impact closure"):
        assert_impact_closed(graph)


def test_t_imp_04_graph_digest_changes_with_references(tmp_path: Path) -> None:
    (tmp_path / "a.md").write_text("[a](b.md)\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("# B\n", encoding="utf-8")
    first = build_impact_graph(build_subject(tmp_path, "ARTICLE"), [])
    (tmp_path / "a.md").write_text("[c](c.md)\n", encoding="utf-8")
    second = build_impact_graph(build_subject(tmp_path, "ARTICLE"), [])

    assert first["graph_digest"] != second["graph_digest"]
