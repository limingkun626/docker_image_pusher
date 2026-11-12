from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import cli


def _write_skill(root: Path) -> Path:
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: source\n---\n\nTODO\n",
        encoding="utf-8",
    )
    return root


def test_atomic_json_write_preserves_previous_bytes_on_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "evidence.json"
    path.write_bytes(b'{"old":true}\n')

    def fail_replace(_source, _target):
        raise OSError("injected replace failure")

    monkeypatch.setattr(cli.os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected"):
        cli._write_json(path, {"new": True})

    assert path.read_bytes() == b'{"old":true}\n'
    assert not list(tmp_path.glob(".evidence.json.*.tmp"))


def test_discovery_observation_exists_before_impact_state(tmp_path: Path) -> None:
    source = _write_skill(tmp_path / "source")
    output = tmp_path / "run"
    original_transition = cli._RunState.transition

    def checked_transition(self, event, **bindings):
        if event == "impact":
            journal = output / "observations.jsonl"
            assert journal.is_file()
            assert journal.stat().st_size > 0
        return original_transition(self, event, **bindings)

    checked_transition.__get__(cli._RunState, cli._RunState)
    cli._RunState.transition = checked_transition
    try:
        assert cli.main(
            [
                "check",
                "--target",
                str(source),
                "--kind",
                "SKILL",
                "--output",
                str(output),
            ]
        ) == 0
    finally:
        cli._RunState.transition = original_transition


def test_run_state_binds_subject_policy_environment_and_candidate(
    tmp_path: Path,
) -> None:
    source = _write_skill(tmp_path / "source")
    output = tmp_path / "run"
    repair_output = tmp_path / "repair-run"
    candidate = tmp_path / "candidate" / "source"

    assert cli.main(
        [
            "check",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(output),
        ]
    ) == 0
    state = json.loads((output / "run-state.json").read_text(encoding="utf-8"))
    assert state["tree_digest"]
    assert state["snapshot_digest"]
    assert state["policy_digest"]
    assert state["environment_digest"]

    (source / "SKILL.md").write_text(
        "---\nname: source\n---\n\n# Demo",
        encoding="utf-8",
    )
    assert cli.main(
        [
            "repair",
            "--target",
            str(source),
            "--kind",
            "SKILL",
            "--output",
            str(repair_output),
            "--candidate",
            str(candidate),
        ]
    ) == 0
    repaired = json.loads(
        (repair_output / "run-state.json").read_text(encoding="utf-8")
    )
    assert repaired["current_state"] == "FULL_VERIFICATION"
    assert repaired["candidate_digest"]


def test_environment_identity_changes_with_dependency_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = cli.importlib.metadata.version
    first = cli._environment_identity()

    def changed(name: str) -> str:
        return "0.0.0" if name == "pytest" else original(name)

    monkeypatch.setattr(cli.importlib.metadata, "version", changed)
    assert cli._environment_identity() != first
