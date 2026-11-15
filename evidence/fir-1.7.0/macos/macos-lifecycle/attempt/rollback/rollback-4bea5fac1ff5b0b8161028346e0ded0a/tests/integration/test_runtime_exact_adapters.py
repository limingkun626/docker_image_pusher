from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.external_adapters import (
    ADAPTERS,
    run_external_cell,
    run_for_snapshot,
)
from full_inspection_repair import external_adapters as external_adapters_module
from full_inspection_repair.lifecycle_adapters import (
    dependency_probe,
    install_upgrade_probe,
    process_tree_probe,
    run_for_snapshot as run_lifecycle_snapshot,
)
from full_inspection_repair.r2_engine import (
    compare_semantic_witnesses,
    run_cell,
)


def test_exact_adapter_cells_use_real_or_explicitly_blocked_bindings() -> None:
    expected = {
        "SKILL:FUNCTIONAL_FAULT:BEHAVIOR",
        "SKILL:RISK_EXPOSURE:BEHAVIOR",
        "SKILL:LATENT_DEFECT:BEHAVIOR",
        "SKILL:VULNERABILITY:BEHAVIOR",
        "SKILL:INCONSISTENCY:LIFECYCLE",
        "SKILL:OMISSION:BEHAVIOR",
        "SKILL:BOUNDARY:BEHAVIOR",
    }
    assert expected.issubset(ADAPTERS)
    observed = run_for_snapshot("SKILL:NOT_REGISTERED:BEHAVIOR", {})
    assert observed["status"] == "BLOCKED_ADAPTER"
    assert observed["release_authority"] is False


@pytest.mark.parametrize("cell_id", sorted(ADAPTERS))
def test_every_external_adapter_executes_its_frozen_fixture_pair(
    cell_id: str,
) -> None:
    observed = run_external_cell(cell_id)
    assert observed["status"] == "PASS", observed
    assert observed["fixture_execution"]["positive"]["outcome"] == "FINDING"
    assert observed["fixture_execution"]["negative"]["outcome"] == "CLEAN"


def test_exact_adapter_runs_frozen_fixture_even_without_target_snapshot(
    tmp_path: Path,
) -> None:
    observed = run_external_cell(
        "SKILL:FUNCTIONAL_FAULT:BEHAVIOR",
        tmp_path / "scratch",
    )
    assert observed["release_authority"] is False
    assert observed["tool_identity"]["fixture_digest"]
    assert observed["receipt_digest"]
    assert observed["status"] == "PASS", observed
    assert observed["failure_code"] is None
    assert observed["facts"]
    assert observed["fixture_execution"]["positive"]["outcome"] == "FINDING"
    assert observed["fixture_execution"]["negative"]["outcome"] == "CLEAN"
    assert observed["fixture_binding"]["positive"]["archive_sha256"]
    assert observed["fixture_binding"]["positive"]["selected_member_digest"]
    assert observed["fixture_binding"]["positive"]["extracted_tree_digest"]


def test_exact_adapter_requires_a_target_for_semantic_execution() -> None:
    observed = run_for_snapshot("SKILL:FUNCTIONAL_FAULT:BEHAVIOR", {})

    assert observed["status"] == "BLOCKED_ADAPTER"
    assert observed["failure_code"] == "TARGET_REQUIRED"


def test_exact_adapter_executes_target_not_only_fixtures(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "test_ok.py").write_text(
        "def test_ok():\n"
        "    assert True\n",
        encoding="utf-8",
    )

    observed = run_for_snapshot(
        "SKILL:FUNCTIONAL_FAULT:BEHAVIOR",
        {
            "target_root": str(target),
            "subject_digest": "a" * 64,
            "fixture_scratch_root": str(tmp_path / "fixtures"),
        },
    )

    assert observed["status"] == "PASS", observed
    assert observed["inner_receipt_digest"]
    assert observed["tool_identity"]["target_digest"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink fixture")
def test_exact_adapter_resolves_temporary_parent_before_target_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    scratch = alias / "run"
    scratch.mkdir()

    class TemporaryDirectory:
        name = str(scratch)

        def __enter__(self) -> str:
            return self.name

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(
        external_adapters_module.tempfile,
        "TemporaryDirectory",
        lambda **_: TemporaryDirectory(),
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "test_ok.py").write_text(
        "def test_ok():\n"
        "    assert True\n",
        encoding="utf-8",
    )

    observed = run_for_snapshot(
        "SKILL:FUNCTIONAL_FAULT:BEHAVIOR",
        {
            "target_root": str(target),
            "subject_digest": "a" * 64,
            "fixture_scratch_root": str(tmp_path / "fixtures"),
        },
    )

    assert observed["status"] == "PASS", observed


def test_semantic_witnesses_ignore_labels_and_line_conventions() -> None:
    left = [
        {
            "cell_id": "SKILL:LATENT_DEFECT:BEHAVIOR",
            "invariant_id": "tests must kill semantic mutations",
            "defect_class_id": "tests.surviving-mutant",
            "normalized_locator": ".\\subject.py",
            "logical_unit_id": "subject.run",
            "predicate_id": "surviving-mutant-presence",
            "normalized_value_digest": "1" * 64,
            "method_id": "mutmut",
        }
    ]
    right = [
        {
            "cell_id": "SKILL:LATENT_DEFECT:BEHAVIOR",
            "invariant_id": "tests must kill semantic mutations",
            "defect_class_id": "tests.surviving-mutant",
            "normalized_locator": "subject.py",
            "logical_unit_id": "subject.run",
            "predicate_id": "surviving-mutant-presence",
            "normalized_value_digest": "1" * 64,
            "method_id": "oracle.mutant-result",
        }
    ]

    assert compare_semantic_witnesses(left, right)["comparison"] == "AGREE"
    assert compare_semantic_witnesses(left, [])["comparison"] == "DISAGREE"


def test_run_cell_exact_adapter_uses_target_execution(
    tmp_path: Path,
) -> None:
    (tmp_path / "test_failure.py").write_text(
        "def test_failure():\n"
        "    assert False\n",
        encoding="utf-8",
    )
    observed = run_cell(
        "SKILL:FUNCTIONAL_FAULT:BEHAVIOR",
        {
            "files": {},
            "target_root": str(tmp_path),
            "subject_digest": "a" * 64,
        },
    )
    assert observed["status"] == "FINDING", observed
    assert observed["comparison"]["comparison"] == "AGREE"
    assert observed["duplicate_measurement"] is False


def test_lifecycle_dependency_probe_recomputes_membership(tmp_path: Path) -> None:
    case = {
        "package": "requests",
        "version": "2.19.0",
        "vulnerable": "2.0.0",
        "fixed": "2.20.0",
        "expected_vulnerable": True,
    }
    (tmp_path / "advisory-case.json").write_text(
        json.dumps(case),
        encoding="utf-8",
    )

    observed = dependency_probe(tmp_path)
    assert observed["status"] == "PASS"
    assert observed["facts"]
    assert observed["release_authority"] is False


def test_lifecycle_install_probe_blocks_without_exact_wheels(
    tmp_path: Path,
) -> None:
    observed = install_upgrade_probe(tmp_path)
    assert observed["status"] == "BLOCKED_ADAPTER"
    assert observed["failure_code"] == "LIFECYCLE_FIXTURE_UNAVAILABLE"


def test_lifecycle_process_probe_uses_disposable_scratch(
    tmp_path: Path,
) -> None:
    (tmp_path / "fixture.txt").write_text("stable\n", encoding="utf-8")
    observed = process_tree_probe(tmp_path)

    assert observed["status"] == "PASS"
    assert observed["inner_receipt_digest"]
    assert not (tmp_path / "child.pid").exists()
    assert observed["tool_identity"]["target_digest"]


def test_lifecycle_snapshot_without_target_uses_frozen_process_fixture() -> None:
    observed = run_lifecycle_snapshot(
        "SKILL:RISK_EXPOSURE:LIFECYCLE",
        {},
    )
    assert observed["status"] == "PASS"
    assert observed["fixture_binding"]["descriptor"]["positive"]["spawn_child"]


def test_all_exact_lifecycle_cells_use_frozen_positive_negative_fixtures() -> None:
    for cell_id in (
        "SKILL:FUNCTIONAL_FAULT:LIFECYCLE",
        "SKILL:RISK_EXPOSURE:LIFECYCLE",
        "SKILL:VULNERABILITY:LIFECYCLE",
    ):
        observed = run_lifecycle_snapshot(cell_id, {})
        assert observed["status"] == "PASS"
        assert observed["fixture_binding"]["positive"]
        assert observed["fixture_binding"]["negative"]
        assert observed["fixture_execution"]


def test_lifecycle_dispatch_falls_back_to_import_linter_fixture_pair() -> None:
    observed = run_lifecycle_snapshot(
        "SKILL:INCONSISTENCY:LIFECYCLE",
        {},
    )
    assert observed["status"] == "PASS"
    assert observed["logical_tool_id"] == "import-linter"
    assert observed["fixture_execution"]["positive"]["outcome"] == "FINDING"
    assert observed["fixture_execution"]["negative"]["outcome"] == "CLEAN"
