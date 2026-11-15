from __future__ import annotations

import json
import os
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.capabilities import (
    CAPABILITY_ROOT,
    ORACLE_SLICES,
    CapabilityBlocked,
    _classify,
    _tree_binding,
    load_fixtures,
    load_pack,
    run_slice,
    validate_pack,
    validate_receipt,
)
from full_inspection_repair.contracts import canonical_digest
import full_inspection_repair.capabilities as capabilities_module


def test_capability_pack_is_complete_and_non_authoritative():
    result = validate_pack()
    assert result["status"] == "PASS"
    assert result["slices"] == 22
    assert result["oracle_slices"] == 2
    pack = load_pack()
    ids = {item["slice_id"] for item in pack["slices"]}
    assert len(ids) == 22
    assert {
        item["slice_id"] for item in pack["slices"] if item["oracle_only"]
    } == ORACLE_SLICES
    assert all(item["release_authority"] is False for item in pack["slices"])


def test_fixture_map_covers_every_admitted_slice():
    pack = load_pack()
    fixtures = load_fixtures()["slices"]
    assert {item["slice_id"] for item in pack["slices"]} == set(fixtures)
    assert all("positive_target" in item and "negative_target" in item for item in fixtures.values())


def test_empty_target_is_uncovered_and_receipt_is_valid(tmp_path):
    pack = load_pack(slice_ids=["SLICE-9ae4bc3f41975252"])
    target = tmp_path / "empty"
    target.mkdir()
    receipt = run_slice(pack["slices"][0], target)
    assert receipt["terminal_status"] == "UNCOVERED"
    assert receipt["failure_code"] == "EMPTY_DENOMINATOR"
    validate_receipt(receipt)


def test_unknown_command_is_blocked_without_outcome(tmp_path):
    pack = load_pack(slice_ids=["SLICE-9ae4bc3f41975252"])
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.txt").write_text("target\n", encoding="utf-8")
    receipt = run_slice(
        pack["slices"][0],
        target,
        command_override=["definitely-not-a-real-tool"],
    )
    assert receipt["terminal_status"] == "UNSUPPORTED"
    assert "outcome" not in receipt
    validate_receipt(receipt)


@pytest.mark.parametrize(
    ("stdout", "failure_code"),
    [
        ("", "EMPTY_JSON_OUTPUT"),
        ("{}", "JSON_FIELD_MISSING"),
        ("[]", "JSON_ROOT_MISMATCH"),
        ('{"unexpected": true}', "JSON_FIELD_MISSING"),
        (
            '{"classification": "UNEXPECTED", "errors": []}',
            "JSON_FIELD_VALUE_INVALID",
        ),
        (
            '{"classification": "INVALID_CONTRACT", "errors": [], "results": []}',
            "INVALID_OUTPUT_CONTRACT",
        ),
    ],
)
def test_json_output_must_match_declared_semantics(stdout, failure_code):
    manifest = {
        "output_format": "JSON",
        "json_root": "object",
        "json_required_fields": ["classification", "errors"],
        "json_enum_fields": {"classification": ["VALID", "INVALID"]},
        "finding_markers": [],
        "outcome_rules": [{"outcome": "CLEAN", "exit_codes": [0]}],
    }
    outcome, _, observed_failure = _classify(manifest, 0, stdout)
    assert outcome is None
    assert observed_failure == failure_code


def test_json_array_items_require_declared_fields():
    manifest = {
        "output_format": "JSON",
        "json_root": "array",
        "json_required_fields": [],
        "json_array_item_required_fields": ["file"],
        "finding_markers": [],
        "outcome_rules": [{"outcome": "CLEAN", "exit_codes": [0]}],
    }
    outcome, _, failure = _classify(manifest, 0, "[{}]")
    assert outcome is None
    assert failure == "JSON_ARRAY_ITEM_INVALID"


def test_valid_json_semantics_can_be_clean():
    manifest = {
        "output_format": "JSON",
        "json_root": "object",
        "json_required_fields": ["modules", "summary"],
        "finding_markers": [],
        "outcome_rules": [{"outcome": "CLEAN", "exit_codes": [0]}],
    }
    outcome, findings, failure = _classify(
        manifest,
        0,
        '{"modules": {}, "summary": {"totalDependenciesCruised": 0}}',
    )
    assert (outcome, findings, failure) == ("CLEAN", [], None)


def test_hard_linked_target_is_rejected(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    alias = tmp_path / "alias.txt"
    try:
        os.link(target, alias)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    with pytest.raises(CapabilityBlocked, match="hard-linked target"):
        _tree_binding(alias)


def test_symlink_or_reparse_target_is_rejected(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    alias = tmp_path / "alias.txt"
    try:
        alias.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(CapabilityBlocked, match="link/reparse point"):
        _tree_binding(alias)


def test_mutation_requires_explicit_disposable_copy(tmp_path):
    manifest = load_pack(slice_ids=["SLICE-87ab5ff8cdbc1770"])["slices"][0]
    target = tmp_path / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    receipt = run_slice(
        manifest,
        target,
        command_override=[sys.executable, "-c", "raise SystemExit(0)"],
    )
    assert receipt["terminal_status"] == "BLOCKED"
    assert receipt["failure_code"] == "MUTATION_REQUIRES_DISPOSABLE_COPY"
    assert "outcome" not in receipt


def test_capability_pack_does_not_bind_source_tooling_path():
    serialized = json.dumps(load_pack(), ensure_ascii=False)
    serialized += json.dumps(load_fixtures(), ensure_ascii=False)
    assert str(CAPABILITY_ROOT) not in serialized


def test_json_adapter_schema_requires_output_descriptors(tmp_path):
    pack = load_pack()
    for manifest in pack["slices"]:
        manifest.pop("json_root", None)
        manifest.pop("json_required_fields", None)
        manifest.pop("json_enum_fields", None)
    pack["pack_digest"] = canonical_digest(
        {key: value for key, value in pack.items() if key != "pack_digest"}
    )
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(pack), encoding="utf-8")
    with pytest.raises(CapabilityBlocked, match="json_root"):
        validate_pack(path)


def test_classification_output_requires_allowed_values(tmp_path):
    pack = load_pack()
    manifest = next(
        item for item in pack["slices"]
        if item["candidate_id"] == "jsonschema"
    )
    manifest["json_enum_fields"] = {}
    pack["pack_digest"] = canonical_digest(
        {key: value for key, value in pack.items() if key != "pack_digest"}
    )
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(pack), encoding="utf-8")
    with pytest.raises(CapabilityBlocked, match="classification"):
        validate_pack(path)


def test_nonmutation_source_change_blocks(tmp_path, monkeypatch):
    manifest = load_pack(slice_ids=["SLICE-9ae4bc3f41975252"])["slices"][0]
    manifest = {
        **manifest,
        "mutation_semantics": False,
        "output_format": "TEXT",
        "outcome_rules": [{"outcome": "CLEAN", "exit_codes": [0]}],
        "network_policy": "DENY",
        "network_enforcement": "LOOPBACK_ONLY",
    }
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.txt").write_text("target\n", encoding="utf-8")
    script = "from pathlib import Path; Path('mutated.txt').write_text('x')"

    def fake_sandbox(command, **kwargs):
        completed = subprocess.run(
            command,
            cwd=kwargs["cwd"],
            capture_output=True,
            check=False,
        )
        return SimpleNamespace(
            status="PASS" if completed.returncode == 0 else "BLOCKED",
            failure_code=None if completed.returncode == 0 else "NONZERO_EXIT",
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            elapsed_seconds=0.0,
            peak_rss_mib=0.0,
            output_bytes=len(completed.stdout) + len(completed.stderr),
            network_enforced=True,
            network_cleanup_verified=True,
            network_canary={"status": "PASS"},
            backend_id="test.sandbox",
            receipt=lambda: {
                "process_tree": {
                    "descendants_empty": True,
                    "termination_method": "test",
                    "root_pid": 1,
                    "child_pids": [],
                }
            },
        )

    monkeypatch.setattr(capabilities_module, "run_sandboxed", fake_sandbox)
    receipt = run_slice(
        manifest,
        target,
        command_override=[sys.executable, "-c", script],
    )
    assert (target / "mutated.txt").is_file()
    assert receipt["terminal_status"] == "BLOCKED"
    assert receipt["failure_code"] == "SOURCE_MUTATED"
    assert "outcome" not in receipt
    validate_receipt(receipt)


def test_windows_firewall_guard_fails_closed_on_posix(tmp_path):
    if os.name == "nt":
        pytest.skip("the non-Windows fail-closed branch is POSIX-specific")
    manifest = load_pack(slice_ids=["SLICE-9ae4bc3f41975252"])["slices"][0]
    manifest = {
        **manifest,
        "mutation_semantics": False,
        "output_format": "TEXT",
        "outcome_rules": [{"outcome": "CLEAN", "exit_codes": [0]}],
        "network_enforcement": "WINDOWS_FIREWALL",
    }
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.txt").write_text("target\n", encoding="utf-8")
    script = "from pathlib import Path; Path('must-not-run.txt').write_text('x')"

    receipt = run_slice(
        manifest,
        target,
        command_override=[sys.executable, "-c", script],
    )

    assert not (target / "must-not-run.txt").exists()
    assert receipt["terminal_status"] == "BLOCKED"
    assert receipt["failure_code"] == "NETWORK_POLICY_UNENFORCEABLE"
    validate_receipt(receipt)


def test_output_inside_target_is_rejected_before_creation(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.txt").write_text("source\n", encoding="utf-8")
    output = target / "evidence"
    with pytest.raises(CapabilityBlocked, match="outside target"):
        capabilities_module.run_pack(
            target=target,
            output=output,
            slice_ids=["SLICE-9ae4bc3f41975252"],
        )
    assert not output.exists()


def test_firewall_cleanup_failure_is_recorded(monkeypatch):
    guard = capabilities_module._NetworkGuard(
        {"network_policy": "DENY", "network_enforcement": "WINDOWS_FIREWALL"},
        [sys.executable],
    )
    guard.rule_names = ["FIR-CAP-test"]

    def fake_run(command, **kwargs):
        script = " ".join(command)
        if "Remove-NetFirewallRule" in script:
            return SimpleNamespace(returncode=1, stdout="", stderr="denied")
        if ".Count" in script:
            return SimpleNamespace(returncode=0, stdout="1", stderr="")
        raise AssertionError(script)

    monkeypatch.setattr(capabilities_module.subprocess, "run", fake_run)
    guard._remove_rules()
    assert guard.rule_names == ["FIR-CAP-test"]
    assert "denied" in guard.cleanup_error
    assert "temporary rules remain" in guard.cleanup_error


def test_stale_guard_state_survives_failed_rule_cleanup(
    tmp_path,
    monkeypatch,
):
    state_path = tmp_path / "guard-state.json"
    state_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pid": 1,
                "profiles_before": {
                    "Domain": False,
                    "Private": False,
                    "Public": False,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        capabilities_module,
        "NETWORK_GUARD_STATE",
        state_path,
    )
    monkeypatch.setattr(
        capabilities_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=3,
            stdout="",
            stderr="rules remain",
        ),
    )
    with pytest.raises(CapabilityBlocked, match="stale rule cleanup failed"):
        capabilities_module._NetworkGuard._recover_stale_state()
    assert state_path.is_file()


def test_stale_guard_state_is_removed_after_verified_recovery(
    tmp_path,
    monkeypatch,
):
    state_path = tmp_path / "guard-state.json"
    state_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pid": 1,
                "profiles_before": {
                    "Domain": False,
                    "Private": False,
                    "Public": False,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        capabilities_module,
        "NETWORK_GUARD_STATE",
        state_path,
    )

    def fake_run(command, **kwargs):
        script = " ".join(command)
        if "Remove-NetFirewallRule" in script:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "Set-NetFirewallProfile" in script:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "Get-NetFirewallProfile" in script:
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    [
                        {"Name": "Domain", "Enabled": False},
                        {"Name": "Private", "Enabled": False},
                        {"Name": "Public", "Enabled": False},
                    ]
                ),
                stderr="",
            )
        raise AssertionError(script)

    monkeypatch.setattr(capabilities_module.subprocess, "run", fake_run)
    capabilities_module._NetworkGuard._recover_stale_state()
    assert not state_path.exists()
