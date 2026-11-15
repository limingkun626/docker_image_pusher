from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import full_inspection_repair.sandbox as sandbox_module
from full_inspection_repair.sandbox import (
    INPUT_FILE_LIMIT,
    JOB_OBJECT_QUERY_FAILED,
    NETWORK_POLICY_UNENFORCEABLE,
    LinuxNsjailSandbox,
    MacSandboxRuntimeBackend,
    SandboxLimits,
    WindowsJobSandbox,
    run_sandboxed,
)


def test_stdout_and_stderr_share_one_budget() -> None:
    observed = run_sandboxed(
        [
            sys.executable,
            "-B",
            "-c",
            "import sys; sys.stdout.write('x'*700); "
            "sys.stderr.write('y'*700)",
        ],
        limits=SandboxLimits(
            timeout_seconds=10,
            max_output_bytes=1024,
            max_rss_mib=256,
        ),
    )

    assert observed.status == "OUTPUT_OVERFLOW"
    assert observed.failure_code == "OUTPUT_OVERFLOW"
    assert observed.output_bytes == 1024
    assert observed.descendants_empty is True


def test_input_file_ceiling_is_checked_before_launch(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-run.txt"
    observed = run_sandboxed(
        [
            sys.executable,
            "-B",
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
        ],
        limits=SandboxLimits(
            timeout_seconds=10,
            max_output_bytes=1024,
            max_rss_mib=256,
            max_input_files=1,
        ),
        input_file_count=2,
    )

    assert observed.status == "BLOCKED"
    assert observed.failure_code == INPUT_FILE_LIMIT
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object backend")
def test_windows_network_deny_requires_verified_srt_win() -> None:
    backend = WindowsJobSandbox(srt_win=None)
    observed = backend.run(
        [sys.executable, "-B", "-c", "print('must not run')"],
        cwd=None,
        env=None,
        limits=SandboxLimits(timeout_seconds=5),
        network_policy="DENY",
    )

    assert observed.status == "BLOCKED_ADAPTER"
    assert observed.failure_code == NETWORK_POLICY_UNENFORCEABLE
    assert observed.returncode is None


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object backend")
def test_windows_job_object_tracks_and_cleans_descendants(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    code = (
        "import subprocess,sys,time\n"
        "from pathlib import Path\n"
        "p=subprocess.Popen([sys.executable,'-B','-c',"
        "'import time;time.sleep(30)'])\n"
        f"Path({str(pid_file)!r}).write_text(str(p.pid),encoding='utf-8')\n"
        "time.sleep(.1)\n"
    )
    observed = run_sandboxed(
        [sys.executable, "-B", "-I", "-c", code],
        limits=SandboxLimits(
            timeout_seconds=10,
            max_output_bytes=65536,
            max_rss_mib=256,
        ),
    )

    assert observed.status == "PASS"
    assert pid_file.is_file()
    assert observed.child_pids
    assert observed.descendants_empty is True


def test_linux_backend_uses_a_new_network_namespace() -> None:
    backend = LinuxNsjailSandbox("/usr/bin/nsjail")
    command = backend._wrap(
        ["/bin/true"],
        cwd=Path("."),
        limits=SandboxLimits(timeout_seconds=5),
        policy="DENY",
    )

    assert "--clone_newnet" in command
    assert command[-1] == "/bin/true"


def test_windows_job_assigns_suspended_process_before_resume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeProcess:
        pid = 4100
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

    class FakeJob:
        def __init__(self, memory_limit: int) -> None:
            del memory_limit

        def assign(self, process_handle: int) -> None:
            assert process_handle == process._handle
            events.append("assign")

        def process_ids(self) -> list[int]:
            return []

        def terminate(self) -> None:
            events.append("terminate")

        def close(self) -> None:
            return

    def fake_popen(*args: object, **kwargs: object) -> FakeProcess:
        del args
        events.append("spawn")
        assert int(kwargs["creationflags"]) & sandbox_module.CREATE_SUSPENDED
        return process

    def fake_resume(observed: FakeProcess) -> None:
        assert observed is process
        events.append("resume")
        process.returncode = 0

    monkeypatch.setattr(sandbox_module, "_WindowsJob", FakeJob)
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        sandbox_module,
        "_resume_suspended_process",
        fake_resume,
    )

    observed = WindowsJobSandbox(srt_win=None)._execute_job(
        ["ignored.exe"],
        cwd=Path("."),
        env=None,
        limits=SandboxLimits(timeout_seconds=5),
    )

    assert events[:3] == ["spawn", "assign", "resume"]
    assert observed.status == "PASS"
    assert observed.descendants_empty is True


def test_windows_job_query_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        pid = 4200
        _handle = 234
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        returncode: int | None = 0

        def poll(self) -> int | None:
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return int(self.returncode or 0)

    class FakeJob:
        def __init__(self, memory_limit: int) -> None:
            del memory_limit

        def assign(self, process_handle: int) -> None:
            del process_handle

        def process_ids(self) -> list[int]:
            raise sandbox_module._JobObjectQueryError(
                5,
                "QueryInformationJobObject failed",
            )

        def terminate(self) -> None:
            return

        def close(self) -> None:
            return

    monkeypatch.setattr(sandbox_module, "_WindowsJob", FakeJob)
    monkeypatch.setattr(
        sandbox_module.subprocess,
        "Popen",
        lambda *args, **kwargs: FakeProcess(),
    )
    monkeypatch.setattr(
        sandbox_module,
        "_resume_suspended_process",
        lambda process: None,
    )

    observed = WindowsJobSandbox(srt_win=None)._execute_job(
        ["ignored.exe"],
        cwd=Path("."),
        env=None,
        limits=SandboxLimits(timeout_seconds=5),
    )

    assert observed.status == "BLOCKED"
    assert observed.failure_code == JOB_OBJECT_QUERY_FAILED
    assert observed.descendants_empty is False
    assert observed.network_cleanup_verified is False


def test_windows_job_query_api_failure_raises() -> None:
    class FakeKernel32:
        @staticmethod
        def QueryInformationJobObject(*args: object) -> int:
            del args
            return 0

    job = sandbox_module._WindowsJob.__new__(sandbox_module._WindowsJob)
    job.handle = 1
    job.kernel32 = FakeKernel32()

    with pytest.raises(sandbox_module._JobObjectQueryError):
        job.process_ids()


def test_macos_streams_one_budget_and_rechecks_process_group(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class ChunkStream:
        def __init__(self, chunks: list[bytes]) -> None:
            self._chunks = iter(chunks)

        def read(self, size: int) -> bytes:
            del size
            return next(self._chunks, b"")

    class FakeProcess:
        pid = 4300
        returncode: int | None = None
        stdout = ChunkStream([b"a" * 6, b"b" * 6])
        stderr = ChunkStream([b"c" * 6])

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
    resource_calls: list[tuple[int, tuple[int, int]]] = []
    group_queries = 0
    killed = 0
    post_kill_queries = 0

    class FakeResource:
        RLIMIT_AS = 1
        RLIMIT_CPU = 2
        RLIMIT_NOFILE = 3

        def setrlimit(
            self,
            resource_id: int,
            values: tuple[int, int],
        ) -> None:
            resource_calls.append((resource_id, values))

    def fake_popen(*args: object, **kwargs: object) -> FakeProcess:
        del args
        assert kwargs["start_new_session"] is True
        preexec = kwargs["preexec_fn"]
        assert callable(preexec)
        preexec()
        return process

    def fake_killpg(pid: int, sig: int) -> None:
        nonlocal killed
        assert pid == process.pid
        assert sig == sandbox_module.signal.SIGKILL
        killed += 1
        process.returncode = -9

    def fake_group_pids(pgid: int) -> list[int]:
        nonlocal group_queries, post_kill_queries
        assert pgid == process.pid
        group_queries += 1
        if not killed:
            return [4400]
        post_kill_queries += 1
        return [4400] if post_kill_queries == 1 else []

    backend = MacSandboxRuntimeBackend("/usr/bin/srt")
    monkeypatch.setattr(
        backend,
        "_resource",
        lambda: (FakeResource(), ""),
    )
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        sandbox_module.os,
        "killpg",
        fake_killpg,
        raising=False,
    )
    monkeypatch.setattr(
        sandbox_module.signal,
        "SIGKILL",
        9,
        raising=False,
    )
    monkeypatch.setattr(
        sandbox_module,
        "_process_group_pids",
        fake_group_pids,
    )
    monkeypatch.setattr(
        sandbox_module,
        "_tree_memory_mib",
        lambda pid: 1.0,
    )

    observed = backend._execute(
        ["/bin/true"],
        cwd=tmp_path,
        env=None,
        limits=SandboxLimits(
            timeout_seconds=5,
            max_output_bytes=8,
            max_rss_mib=64,
        ),
    )

    assert observed.status == "OUTPUT_OVERFLOW"
    assert observed.output_bytes == 8
    assert len(observed.stdout) + len(observed.stderr) == 8
    assert killed >= 2
    assert group_queries == 2
    assert observed.child_pids == (4400,)
    assert observed.descendants_empty is True
    assert observed.termination_method == "process-group"
    assert {item[0] for item in resource_calls} == {
        FakeResource.RLIMIT_AS,
        FakeResource.RLIMIT_CPU,
        FakeResource.RLIMIT_NOFILE,
    }


def test_macos_network_canary_failure_blocks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    backend = MacSandboxRuntimeBackend("/usr/bin/srt")
    monkeypatch.setattr(sandbox_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        sandbox_module,
        "_network_canary",
        lambda executor, policy: ({"status": "BLOCKED"}, False),
    )
    monkeypatch.setattr(
        backend,
        "_execute",
        lambda *args, **kwargs: pytest.fail("target code must not execute"),
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
    assert observed.network_cleanup_verified is False
    assert observed.network_canary["status"] == "BLOCKED"
