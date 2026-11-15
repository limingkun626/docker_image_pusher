from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.capabilities import (
    _substitute,
    _materialize_fixture,
    _tree_binding,
    load_fixtures,
    load_pack,
    run_pack,
    run_fixture_case,
    run_slice,
)
from full_inspection_repair.cli import main
import full_inspection_repair.capabilities as capabilities_module


def test_capability_cli_validate(tmp_path):
    output = tmp_path / "capability-validation.json"
    assert main(["capabilities", "validate", "--output", str(output)]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "PASS"
    assert result["slices"] == 22
    assert result["release_authority"] is False


def test_capability_cli_run_records_fail_closed_empty_denominator(tmp_path):
    target = tmp_path / "empty"
    target.mkdir()
    output = tmp_path / "capability-run"
    exit_code = main(
        [
            "capabilities",
            "run",
            "--target",
            str(target),
            "--output",
            str(output),
            "--slice",
            "SLICE-9ae4bc3f41975252",
            "--non-strict",
        ]
    )
    assert exit_code == 0
    evidence = json.loads(
        (output / "capability-evidence.json").read_text(encoding="utf-8")
    )
    assert evidence["status"] == "INCOMPLETE"
    assert evidence["nonterminal"] == ["SLICE-9ae4bc3f41975252"]
    receipt = json.loads(
        (output / "SLICE-9ae4bc3f41975252.json").read_text(encoding="utf-8")
    )
    assert receipt["terminal_status"] == "UNCOVERED"
    assert "outcome" not in receipt


def test_network_deny_blocks_actual_child_process(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows srt-win policy is Windows-specific")
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.txt").write_text("target\n", encoding="utf-8")
    marker = target / "must-not-run.txt"
    manifest = {
        **load_pack(slice_ids=["SLICE-9ae4bc3f41975252"])["slices"][0],
        "mutation_semantics": False,
        "output_format": "TEXT",
        "outcome_rules": [
            {"outcome": "CLEAN", "exit_codes": [0]},
        ],
        "network_policy": "DENY",
        "network_enforcement": "WINDOWS_FIREWALL",
    }
    script = (
        "from pathlib import Path; "
        f"Path({str(marker)!r}).write_text('ran')"
    )
    receipt = run_slice(
        manifest,
        target,
        command_override=[sys.executable, "-c", script],
    )
    assert receipt["terminal_status"] == "BLOCKED"
    assert receipt["failure_code"] == "NETWORK_POLICY_UNENFORCEABLE"
    assert receipt["network_enforced"] is False
    assert not marker.exists()


def test_run_pack_uses_disposable_copy_for_mutation(tmp_path, monkeypatch):
    if os.name != "nt":
        pytest.skip("the pinned ast-grep capability command is Windows-specific")
    manifest = load_pack(slice_ids=["SLICE-87ab5ff8cdbc1770"])["slices"][0]
    manifest = {**manifest, "network_policy": "ALLOW"}
    original_load_pack = capabilities_module.load_pack

    def load_local_pack(*args, **kwargs):
        pack = original_load_pack(*args, **kwargs)
        for item in pack["slices"]:
            item["network_policy"] = "ALLOW"
        return pack

    monkeypatch.setattr(capabilities_module, "load_pack", load_local_pack)
    fixture = load_fixtures()["slices"][manifest["slice_id"]]
    source = _materialize_fixture(
        manifest,
        fixture,
        "positive",
        tmp_path / "fixtures",
    )
    before = _tree_binding(source)
    output = tmp_path / "mutation-run"
    evidence = run_pack(
        target=source,
        output=output,
        slice_ids=[manifest["slice_id"]],
        include_mutation=True,
    )
    assert evidence["status"] == "PASS"
    receipt = evidence["receipts"][0]
    assert receipt["mutation_strategy"] == "DISPOSABLE_COPY"
    assert receipt["mutation_source_unchanged"] is True
    assert receipt["input_mutated_by_tool"] is True
    assert _tree_binding(source)["sha256"] == before["sha256"]
    assert (output / "mutation-candidates" / manifest["slice_id"]).is_dir()


def test_ast_grep_inspect_uses_semantic_object_output(tmp_path):
    if os.name != "nt":
        pytest.skip("the pinned ast-grep capability command is Windows-specific")
    manifest = load_pack(slice_ids=["SLICE-3233bd156148d7e2"])["slices"][0]
    manifest = {**manifest, "network_policy": "ALLOW"}
    fixture = load_fixtures()["slices"][manifest["slice_id"]]
    positive = run_fixture_case(
        manifest,
        fixture,
        "positive",
        scratch_root=tmp_path / "fixtures",
    )
    negative = run_fixture_case(
        manifest,
        fixture,
        "negative",
        scratch_root=tmp_path / "fixtures",
    )
    positive_payload = json.loads(positive["stdout_text"])
    negative_payload = json.loads(negative["stdout_text"])
    assert positive_payload["classification"] == "DEFECT_DETECTED"
    assert positive_payload["results"]
    assert negative_payload == {"classification": "CLEAN", "results": []}
    assert positive["outcome"] == "FINDING"
    assert negative["outcome"] == "CLEAN"


def test_official_pytest_slice_blocks_descendant_powershell(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows srt-win policy is Windows-specific")
    target = tmp_path / "target"
    target.mkdir()
    marker = target / "must-not-run.txt"
    (target / "test_network_child.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    manifest = load_pack(slice_ids=["SLICE-57d9534a5fb62f57"])["slices"][0]
    receipt = run_slice(
        manifest,
        target,
        mutation_copy_digest=_tree_binding(target)["sha256"],
    )
    assert receipt["terminal_status"] == "BLOCKED"
    assert receipt["failure_code"] == "NETWORK_POLICY_UNENFORCEABLE"
    assert receipt["network_enforced"] is False
    assert not marker.exists()


def test_network_guard_serializes_concurrent_processes(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows srt-win policy is Windows-specific")
    target = tmp_path / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    probe = (
        "import sys\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
        "from full_inspection_repair.capabilities import load_pack, run_slice\n"
        "manifest = {**load_pack(slice_ids=['SLICE-9ae4bc3f41975252'])['slices'][0],"
        "'network_policy':'DENY','network_enforcement':'WINDOWS_FIREWALL',"
        "'output_format':'TEXT','outcome_rules':"
        "[{'outcome':'CLEAN','exit_codes':[0]}]}\n"
        "receipt = run_slice(manifest, Path(sys.argv[1]))\n"
        "print(receipt['terminal_status'])\n"
        "raise SystemExit(0 if receipt['terminal_status']=='BLOCKED' "
        "and receipt['failure_code']=='NETWORK_POLICY_UNENFORCEABLE' else 2)\n"
    )
    started = time.monotonic()
    first = subprocess.Popen(
        [sys.executable, "-B", "-c", probe, str(target)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    second = subprocess.Popen(
        [sys.executable, "-B", "-c", probe, str(target)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    first_out, first_err = first.communicate(timeout=30)
    second_out, second_err = second.communicate(timeout=30)
    elapsed = time.monotonic() - started
    assert first.returncode == 0, first_err or first_out
    assert second.returncode == 0, second_err or second_out
    assert elapsed < 10
