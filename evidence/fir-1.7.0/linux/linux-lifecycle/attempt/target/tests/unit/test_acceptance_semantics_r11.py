from __future__ import annotations

import copy
import io
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import full_inspection_repair.capabilities as capabilities_module
import full_inspection_repair.sandbox as sandbox_module
from full_inspection_repair.capabilities import CapabilityBlocked
from full_inspection_repair.contracts import (
    ContractError,
    build_execution_receipt,
    validate_contract,
)
from full_inspection_repair.sandbox import (
    NETWORK_POLICY_UNENFORCEABLE,
    PROCESS_TREE_NOT_EMPTY,
    SandboxLimits,
    SandboxResult,
    WindowsJobSandbox,
)


def test_t_cap_01_empty_positive_assertions_block_capability_pack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixtures = copy.deepcopy(capabilities_module.load_fixtures())
    slice_id = next(iter(fixtures["slices"]))
    fixtures["slices"][slice_id]["positive_assertions"] = []
    monkeypatch.setattr(
        capabilities_module,
        "load_fixtures",
        lambda: fixtures,
    )

    with pytest.raises(CapabilityBlocked) as caught:
        capabilities_module.validate_pack()

    assert str(caught.value) == (
        f"{slice_id} positive assertions must be non-empty"
    )
    assert caught.value.status == "BLOCKED_TAXONOMY"
    assert caught.value.failure_code == "CELL_FIXTURE_ASSERTION_MISSING"


def test_t_cap_03_matrix_without_fixture_archive_digest_blocks_evidence() -> None:
    matrix = _capability_matrix()
    validate_contract("capability-matrix", matrix)
    matrix.pop("fixture_archive_sha256")

    with pytest.raises(ContractError) as caught:
        validate_contract("capability-matrix", matrix)

    assert caught.value.code == "BLOCKED_EVIDENCE"
    assert "fixture_archive_sha256" in str(caught.value)


def test_t_run_02_successful_deny_canary_blocks_network_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    connected = SandboxResult(
        backend_id="test.deny-enforcement",
        backend_version="1.0",
        status="PASS",
        failure_code=None,
        returncode=0,
        stdout=b"CONNECTED\n",
        stderr=b"",
        elapsed_seconds=0.0,
        peak_rss_mib=0.0,
        output_bytes=10,
        root_pid=6100,
        child_pids=(),
        descendants_empty=True,
        termination_method="natural-exit",
        network_policy="DENY",
        network_enforced=False,
        network_cleanup_verified=True,
        network_canary={"status": "NOT_REQUIRED"},
    )
    backend = WindowsJobSandbox(srt_win=None)
    backend.srt_win = "srt-win-test"
    backend.srt_version = "test"
    backend._srt_available = True
    monkeypatch.setattr(sandbox_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        backend,
        "_execute_job",
        lambda *args, **kwargs: connected,
    )

    observed = backend.run(
        [sys.executable, "-B", "-c", "print('must not run')"],
        cwd=tmp_path,
        env=None,
        limits=SandboxLimits(timeout_seconds=5),
        network_policy="DENY",
    )

    assert observed.status == "BLOCKED_ADAPTER"
    assert observed.failure_code == NETWORK_POLICY_UNENFORCEABLE
    assert observed.network_canary == {
        "status": "BLOCKED",
        "policy": "DENY",
        "loopback_connected": True,
        "loopback_blocked": False,
        "returncode": 0,
        "failure_code": None,
        "cleanup_verified": True,
    }
    receipt_error = _execution_receipt_error(
        replace(observed, descendants_empty=True),
        descendants_remaining=[],
        network_cleanup_verified=observed.network_cleanup_verified,
    )
    assert receipt_error.code == "BLOCKED_EVIDENCE"
    assert "does not prove network cleanup" in str(receipt_error)


def test_t_run_04_surviving_root_grandchild_emits_blocked_process_tree(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    grandchild_pid = 7201

    class FakeProcess:
        pid = 7200
        _handle = 123
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

    process = FakeProcess()
    terminated = 0

    class FakeJob:
        def __init__(self, memory_limit: int) -> None:
            del memory_limit

        def assign(self, process_handle: int) -> None:
            assert process_handle == process._handle

        def process_ids(self) -> list[int]:
            return [grandchild_pid]

        def terminate(self) -> None:
            nonlocal terminated
            terminated += 1

        def close(self) -> None:
            return

    def resume(observed: FakeProcess) -> None:
        observed.returncode = 0

    monkeypatch.setattr(sandbox_module, "_WindowsJob", FakeJob)
    monkeypatch.setattr(
        sandbox_module.subprocess,
        "Popen",
        lambda *args, **kwargs: process,
    )
    monkeypatch.setattr(
        sandbox_module,
        "_resume_suspended_process",
        resume,
    )
    monkeypatch.setattr(
        sandbox_module,
        "_alive_pids",
        lambda pids: grandchild_pid in pids,
    )

    observed = WindowsJobSandbox(srt_win=None)._execute_job(
        ["ignored.exe"],
        cwd=tmp_path,
        env=None,
        limits=SandboxLimits(timeout_seconds=5),
    )

    assert observed.status == PROCESS_TREE_NOT_EMPTY
    assert observed.failure_code == PROCESS_TREE_NOT_EMPTY
    assert observed.descendants_empty is False
    assert observed.child_pids == (grandchild_pid,)
    assert observed.termination_method == "job-terminate"
    assert terminated == 1
    assert observed.receipt()["process_tree"] == {
        "root_pid": 7200,
        "child_pids": [grandchild_pid],
        "descendants_empty": False,
        "termination_method": "job-terminate",
    }
    receipt_error = _execution_receipt_error(
        observed,
        descendants_remaining=[grandchild_pid],
        network_cleanup_verified=True,
    )
    assert receipt_error.code == "BLOCKED_EVIDENCE"
    assert "live descendants" in str(receipt_error)


def _capability_matrix() -> dict[str, object]:
    digest = "a" * 64
    return {
        "schema_version": 2,
        "pack_digest": digest,
        "runtime_registry_digest": digest,
        "execution_schema_digest": digest,
        "adapter_schema_digest": digest,
        "fixture_archive_sha256": digest,
        "fixture_member_manifest_digest": digest,
        "fixture_definition_digest": digest,
        "tool_identity_digests": [digest],
        "runtime_closure_digests": [digest],
        "environment_digest": digest,
        "evaluator_digest": digest,
        "certification_row_digest": digest,
        "rows": [
            {
                "capability_slice_id": "SLICE-0123456789abcdef",
                "test_class": "positive",
                "status": "PASS",
                "fixture_member_id": "fixtures/demo",
                "fixture_tree_digest": digest,
                "tool_identity_digest": digest,
                "runtime_closure_digest": digest,
                "command_digest": digest,
                "semantic_assertion_digest": digest,
                "raw_receipt": {"receipt_digest": digest},
                "row_digest": digest,
            }
        ],
        "row_count": 1,
        "failures": [],
        "status": "PASS",
        "matrix_digest": digest,
    }


def _execution_receipt_error(
    observed: SandboxResult,
    *,
    descendants_remaining: list[int],
    network_cleanup_verified: bool,
) -> ContractError:
    digest = "b" * 64
    with pytest.raises(ContractError) as caught:
        build_execution_receipt(
            run_id="scope-r11:1",
            receipt_kind="DETECTOR",
            cell_id="SKILL:FUNCTIONAL_FAULT:RUNTIME",
            binding_id="detector.runtime",
            tool_closure_digest=digest,
            subject_tree_digest=digest,
            candidate_digest=digest,
            snapshot_digest=digest,
            execution={
                "argv_digest": digest,
                "environment_digest": digest,
                "rule_set_digest": digest,
                "exit_code": int(observed.returncode or 0),
                "stdout_digest": digest,
                "stderr_digest": digest,
                "parse_status": "PASS",
            },
            resources={
                "elapsed_seconds": observed.elapsed_seconds,
                "peak_rss_mib": observed.peak_rss_mib,
                "input_files": 0,
                "output_bytes": observed.output_bytes,
                "limit_hit": None,
            },
            process_tree={
                "root_pid": observed.root_pid or 1,
                "descendants_seen": list(observed.child_pids),
                "descendants_remaining": descendants_remaining,
                "termination_method": observed.termination_method,
                "empty_verified": observed.descendants_empty,
            },
            network={
                "policy": observed.network_policy,
                "backend": (
                    "srt"
                    if observed.network_policy != "ALLOW"
                    else "job-object"
                ),
                "enforced": observed.network_enforced,
                "namespace_or_job_identity": "job-r11",
                "canary_receipt_digest": digest,
                "cleanup_verified": network_cleanup_verified,
            },
            terminal_status="BLOCKED",
            failure_code=observed.failure_code,
        )
    return caught.value
