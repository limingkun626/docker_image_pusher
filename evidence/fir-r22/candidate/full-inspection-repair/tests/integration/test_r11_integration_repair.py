from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import release_skill
from full_inspection_repair.cli import _environment_identity, _RunState, main
from full_inspection_repair.contracts import ContractError
from full_inspection_repair.detector_registry import default_taxonomy_coverage
from full_inspection_repair.observation import ObservationJournal
from full_inspection_repair.review import ReviewBlocked


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_terminal_run_state_cannot_be_reinitialized(tmp_path: Path) -> None:
    path = tmp_path / "run-state.json"
    state = _RunState(path)
    for event in (
        "census",
        "discover",
        "impact",
        "plan",
        "preflight",
        "build_candidate",
        "verify",
        "review",
        "close",
    ):
        state.transition(event)

    with pytest.raises(ContractError, match="already exists"):
        _RunState(path)
    assert read_json(path)["current_state"] == "CLOSED_FOR_DECLARED_UNIVERSE"


def test_cli_wires_frozen_source_inventory_into_ledger(tmp_path: Path) -> None:
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo\n",
        encoding="utf-8",
    )
    output = tmp_path / "check-run"
    taxonomy = tmp_path / "taxonomy.json"
    taxonomy.write_text(
        json.dumps(default_taxonomy_coverage("SKILL")),
        encoding="utf-8",
    )

    exit_code = main(
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

    assert exit_code == 0
    ledger = read_json(output / "risk-ledger.json")
    assert ledger["required_sources"] == ["source:SKILL.md"]
    assert ledger["observed_sources"] == ["source:SKILL.md"]
    assert ledger["required_sources_digest"]
    assert ledger["residual_risks"] == []


def test_cli_rejects_frozen_environment_drift(tmp_path: Path) -> None:
    source = tmp_path / "source-skill"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: source-skill\n---\n\n# Demo\n",
        encoding="utf-8",
    )
    output = tmp_path / "check-run"
    taxonomy = tmp_path / "taxonomy.json"
    taxonomy.write_text(
        json.dumps(default_taxonomy_coverage("SKILL")),
        encoding="utf-8",
    )
    wrong_environment = "0" * 64
    assert _environment_identity() != wrong_environment

    exit_code = main(
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
            "--expected-environment-digest",
            wrong_environment,
        ]
    )

    assert exit_code != 0
    assert read_json(output / "summary.json")["status"] == "BLOCKED_STALE_INPUT"


def test_review_failure_is_persisted_before_blocked_receipt(tmp_path: Path) -> None:
    run_state = tmp_path / "run-state.json"
    manifest = tmp_path / "package-manifest.json"
    digest = "a" * 64
    run_state.write_text(
        json.dumps({"run_id": "run:review", "current_state": "FULL_VERIFICATION"}),
        encoding="utf-8",
    )
    manifest.write_text(
        json.dumps({"tree_digest": digest, "subject_id": "skill:" + digest[:16]}),
        encoding="utf-8",
    )
    args = SimpleNamespace(
        run_state=str(run_state),
        manifest=str(manifest),
        command="review",
    )

    release_skill._record_review_failure(args, ReviewBlocked("gate rejected"))

    journal = ObservationJournal(tmp_path / "observations.jsonl")
    checkpoint = json.loads(
        (tmp_path / "observation-journal-manifest.json").read_text(
            encoding="utf-8"
        )
    )["checkpoint"]
    assert journal.verify(checkpoint=checkpoint) == 1
