from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

import psutil


BLOCKED_ADAPTER = "BLOCKED_ADAPTER"
NETWORK_POLICY_UNENFORCEABLE = "NETWORK_POLICY_UNENFORCEABLE"
PROCESS_TREE_NOT_EMPTY = "PROCESS_TREE_NOT_EMPTY"
INPUT_FILE_LIMIT = "INPUT_FILE_LIMIT"
OUTPUT_OVERFLOW = "OUTPUT_OVERFLOW"
JOB_OBJECT_QUERY_FAILED = "JOB_OBJECT_QUERY_FAILED"
CREATE_SUSPENDED = 0x00000004
THREAD_SUSPEND_RESUME = 0x0002


class _JobObjectQueryError(OSError):
    pass


def _create_flags(name: str) -> int:
    return int(getattr(subprocess, name, 0))


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    return int(getter()) if getter is not None else 0


@dataclass(frozen=True)
class SandboxLimits:
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1024 * 1024
    max_rss_mib: float = 1024.0
    max_input_files: int | None = None

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if self.max_rss_mib <= 0:
            raise ValueError("max_rss_mib must be positive")
        if self.max_input_files is not None and self.max_input_files < 0:
            raise ValueError("max_input_files cannot be negative")


@dataclass
class _OutputBudget:
    limit: int
    total: int = 0
    overflow: threading.Event | None = None
    stdout: bytearray | None = None
    stderr: bytearray | None = None
    lock: threading.Lock | None = None

    def __post_init__(self) -> None:
        self.overflow = threading.Event()
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.lock = threading.Lock()

    def append(self, stream_name: str, data: bytes) -> bool:
        assert self.lock is not None
        assert self.overflow is not None
        assert self.stdout is not None
        assert self.stderr is not None
        with self.lock:
            remaining = max(0, self.limit - self.total)
            accepted = data[:remaining]
            if accepted:
                target = self.stdout if stream_name == "stdout" else self.stderr
                target.extend(accepted)
                self.total += len(accepted)
            if len(data) > remaining:
                self.overflow.set()
                return False
            return True


@dataclass(frozen=True)
class SandboxResult:
    backend_id: str
    backend_version: str
    status: str
    failure_code: str | None
    returncode: int | None
    stdout: bytes
    stderr: bytes
    elapsed_seconds: float
    peak_rss_mib: float
    output_bytes: int
    root_pid: int | None
    child_pids: tuple[int, ...]
    descendants_empty: bool
    termination_method: str
    network_policy: str
    network_enforced: bool
    network_cleanup_verified: bool
    network_canary: Mapping[str, Any]
    error: str | None = None

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", "replace")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", "replace")

    def receipt(self) -> dict[str, Any]:
        value = {
            "backend_id": self.backend_id,
            "backend_version": self.backend_version,
            "status": self.status,
            "failure_code": self.failure_code,
            "returncode": self.returncode,
            "stdout_sha256": hashlib.sha256(self.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(self.stderr).hexdigest(),
            "resource": {
                "elapsed_seconds": self.elapsed_seconds,
                "peak_rss_mib": self.peak_rss_mib,
                "output_bytes": self.output_bytes,
            },
            "process_tree": {
                "root_pid": self.root_pid,
                "child_pids": list(self.child_pids),
                "descendants_empty": self.descendants_empty,
                "termination_method": self.termination_method,
            },
            "network": {
                "policy": self.network_policy,
                "enforced": self.network_enforced,
                "cleanup_verified": self.network_cleanup_verified,
                "canary": dict(self.network_canary),
            },
            "error": self.error,
        }
        value["receipt_digest"] = hashlib.sha256(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return value


class SandboxBackend(Protocol):
    backend_id: str
    backend_version: str

    def probe(self) -> dict[str, Any]: ...

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | Path | None,
        env: Mapping[str, str] | None,
        limits: SandboxLimits,
        network_policy: str,
        input_file_count: int | None = None,
    ) -> SandboxResult: ...


def _blocked(
    backend_id: str,
    backend_version: str,
    failure_code: str,
    *,
    status: str = "BLOCKED",
    network_policy: str,
    error: str | None = None,
    stdout: bytes = b"",
    stderr: bytes = b"",
    descendants_empty: bool = True,
    network_cleanup_verified: bool = True,
    network_canary: Mapping[str, Any] | None = None,
) -> SandboxResult:
    return SandboxResult(
        backend_id=backend_id,
        backend_version=backend_version,
        status=status,
        failure_code=failure_code,
        returncode=None,
        stdout=stdout,
        stderr=stderr,
        elapsed_seconds=0.0,
        peak_rss_mib=0.0,
        output_bytes=len(stdout) + len(stderr),
        root_pid=None,
        child_pids=(),
        descendants_empty=descendants_empty,
        termination_method="not-started",
        network_policy=network_policy,
        network_enforced=False,
        network_cleanup_verified=network_cleanup_verified,
        network_canary=network_canary or {"status": "NOT_RUN"},
        error=error,
    )


def _normalize_policy(value: str) -> str:
    normalized = value.upper()
    if normalized == "OFFLINE_CACHE_ONLY":
        return "DENY"
    if normalized in {"ALLOW", "DENY", "LOOPBACK_ONLY"}:
        return normalized
    raise ValueError(f"unsupported network policy: {value}")


def _read_stream(
    stream: Any,
    stream_name: str,
    budget: _OutputBudget,
    terminate: Callable[[], None],
) -> None:
    while True:
        data = stream.read(65536)
        if not data:
            return
        if not budget.append(stream_name, data):
            terminate()
            return


def _tree_memory_mib(pid: int) -> float:
    try:
        root = psutil.Process(pid)
        processes = [root, *root.children(recursive=True)]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0.0
    total = 0
    for process in processes:
        try:
            if process.is_running():
                total += process.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return total / (1024 * 1024)


def _alive_pids(pids: Sequence[int]) -> list[int]:
    alive: list[int] = []
    for pid in sorted(set(pids)):
        try:
            if psutil.Process(pid).is_running():
                alive.append(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return alive


class _WindowsBasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _WindowsIoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _WindowsExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _WindowsBasicLimits),
        ("IoInfo", _WindowsIoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _WindowsPidList(ctypes.Structure):
    _fields_ = [
        ("NumberOfAssignedProcesses", ctypes.c_uint32),
        ("NumberOfProcessIdsInList", ctypes.c_uint32),
        ("ProcessIdList", ctypes.c_size_t),
    ]


class _WindowsJob:
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3

    def __init__(self, memory_limit_bytes: int) -> None:
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        self.kernel32.SetInformationJobObject.restype = ctypes.c_int
        self.kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        self.kernel32.QueryInformationJobObject.restype = ctypes.c_int
        self.kernel32.TerminateJobObject.restype = ctypes.c_int
        self.kernel32.CloseHandle.restype = ctypes.c_int
        self.handle = self.kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
        info = _WindowsExtendedLimits()
        info.BasicLimitInformation.LimitFlags = (
            self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | self.JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | self.JOB_OBJECT_LIMIT_JOB_MEMORY
        )
        info.ProcessMemoryLimit = memory_limit_bytes
        info.JobMemoryLimit = memory_limit_bytes
        if not self.kernel32.SetInformationJobObject(
            self.handle,
            self.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            error = ctypes.get_last_error()
            self.close()
            raise OSError(error, "SetInformationJobObject failed")

    def assign(self, process_handle: int) -> None:
        if not self.kernel32.AssignProcessToJobObject(
            self.handle, ctypes.c_void_p(process_handle)
        ):
            raise OSError(
                ctypes.get_last_error(),
                "AssignProcessToJobObject failed",
            )

    def process_ids(self) -> list[int]:
        capacity = 128
        while True:
            size = ctypes.sizeof(_WindowsPidList) + (capacity - 1) * ctypes.sizeof(
                ctypes.c_size_t
            )
            buffer = ctypes.create_string_buffer(size)
            if not self.kernel32.QueryInformationJobObject(
                self.handle,
                self.JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                buffer,
                size,
                None,
            ):
                raise _JobObjectQueryError(
                    _last_error(),
                    "QueryInformationJobObject failed",
                )
            row = ctypes.cast(buffer, ctypes.POINTER(_WindowsPidList)).contents
            if row.NumberOfProcessIdsInList > capacity:
                capacity = row.NumberOfProcessIdsInList
                continue
            start = _WindowsPidList.ProcessIdList.offset
            values = (ctypes.c_size_t * row.NumberOfProcessIdsInList).from_buffer(
                buffer, start
            )
            return [int(value) for value in values]

    def terminate(self) -> None:
        if self.handle:
            self.kernel32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None


def _resume_suspended_process(process: subprocess.Popen[bytes]) -> None:
    try:
        threads = psutil.Process(process.pid).threads()
    except (psutil.Error, OSError) as error:
        raise OSError(
            f"cannot enumerate suspended process threads: {error}"
        ) from error
    if len(threads) != 1:
        raise OSError(
            "suspended process must have exactly one primary thread"
        )
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenThread.restype = ctypes.c_void_p
    kernel32.OpenThread.argtypes = [
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint32,
    ]
    kernel32.ResumeThread.restype = ctypes.c_uint32
    kernel32.ResumeThread.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    thread_handle = kernel32.OpenThread(
        THREAD_SUSPEND_RESUME,
        False,
        threads[0].id,
    )
    if not thread_handle:
        raise OSError(ctypes.get_last_error(), "OpenThread failed")
    try:
        previous_count = kernel32.ResumeThread(thread_handle)
        if previous_count == 0xFFFFFFFF:
            raise OSError(ctypes.get_last_error(), "ResumeThread failed")
        if previous_count != 1:
            raise OSError(
                f"unexpected suspended thread count: {previous_count}"
            )
    finally:
        kernel32.CloseHandle(thread_handle)


def _resolve_srt_win() -> str | None:
    configured = os.environ.get("FIR_SRT_WIN") or os.environ.get("SRT_WIN")
    candidates = [configured] if configured else []
    candidates.extend(["srt-win", "srt"])
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file():
            return str(path.resolve())
        resolved = shutil.which(candidate)
        if resolved:
            return str(Path(resolved).resolve())
    return None


def _srt_version(executable: str) -> str | None:
    try:
        completed = subprocess.run(
            [executable, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except OSError:
        return None
    output = completed.stdout.strip()
    if completed.returncode != 0 or not output:
        return None
    return output.splitlines()[0][:256]


def _network_canary(
    executor: callable,
    policy: str,
) -> tuple[dict[str, Any], bool]:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2.0)
        port = listener.getsockname()[1]
        code = (
            "import socket,sys\n"
            "try:\n"
            f" s=socket.create_connection(('127.0.0.1',{port}),0.5); s.close(); "
            "print('CONNECTED'); raise SystemExit(0)\n"
            "except OSError:\n"
            " print('BLOCKED'); raise SystemExit(7)\n"
        )
        observed = executor(
            [sys.executable, "-B", "-I", "-c", code],
            SandboxLimits(
                timeout_seconds=5.0,
                max_output_bytes=8192,
                max_rss_mib=128.0,
                max_input_files=0,
            ),
        )
    cleanup_verified = observed.descendants_empty
    connected = (
        cleanup_verified
        and observed.returncode == 0
        and "CONNECTED" in observed.stdout_text
    )
    blocked = (
        cleanup_verified
        and observed.returncode == 7
        and "BLOCKED" in observed.stdout_text
    )
    passed = blocked if policy == "DENY" else connected
    receipt = {
        "status": "PASS" if passed else "BLOCKED",
        "policy": policy,
        "loopback_connected": connected,
        "loopback_blocked": blocked,
        "returncode": observed.returncode,
        "failure_code": observed.failure_code,
        "cleanup_verified": cleanup_verified,
    }
    return receipt, passed


class WindowsJobSandbox:
    backend_id = "windows.job-object"
    backend_version = "1.1.0"

    def __init__(self, srt_win: str | None = None) -> None:
        self.srt_win = srt_win
        self.srt_version = _srt_version(srt_win) if srt_win else None
        self._srt_available = bool(srt_win and self.srt_version)

    def probe(self) -> dict[str, Any]:
        return {
            "backend_id": self.backend_id,
            "backend_version": self.backend_version,
            "platform_supported": os.name == "nt",
            "job_objects": os.name == "nt",
            "srt_win": self.srt_win,
            "srt_version": self.srt_version,
            "network_enforcement": self._srt_available,
        }

    def _settings(self, policy: str, cwd: Path) -> dict[str, Any]:
        allowed = ["127.0.0.1", "localhost"] if policy == "LOOPBACK_ONLY" else []
        return {
            "network": {
                "allowedDomains": allowed,
                "deniedDomains": [],
                "strictAllowlist": True,
            },
            "filesystem": {
                "denyRead": [],
                "allowRead": [str(cwd)],
                "allowWrite": [str(cwd), tempfile.gettempdir()],
                "denyWrite": [],
            },
        }

    def _wrapped(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        policy: str,
        settings_path: Path,
    ) -> list[str]:
        if policy == "ALLOW":
            return list(argv)
        assert self.srt_win is not None
        return [
            self.srt_win,
            "--settings",
            str(settings_path),
            "--",
            *argv,
        ]

    def _execute_job(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None,
        limits: SandboxLimits,
    ) -> SandboxResult:
        started = time.monotonic()
        budget = _OutputBudget(limits.max_output_bytes)
        job: _WindowsJob | None = None
        process: subprocess.Popen[bytes] | None = None
        reader_threads: list[threading.Thread] = []
        failure: str | None = None
        termination_method = "natural-exit"
        peak = 0.0
        child_pids: list[int] = []
        try:
            job = _WindowsJob(max(1, int(limits.max_rss_mib * 1024 * 1024)))
            creationflags = (
                _create_flags("CREATE_NEW_PROCESS_GROUP")
                | _create_flags("CREATE_BREAKAWAY_FROM_JOB")
                | CREATE_SUSPENDED
            )
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=dict(env) if env is not None else None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=creationflags,
            )
            job.assign(int(process._handle))  # type: ignore[attr-defined]
            _resume_suspended_process(process)

            def terminate_tree() -> None:
                nonlocal termination_method
                if job is not None:
                    termination_method = "job-terminate"
                    job.terminate()

            assert process.stdout is not None
            assert process.stderr is not None
            reader_threads = [
                threading.Thread(
                    target=_read_stream,
                    args=(process.stdout, "stdout", budget, terminate_tree),
                    daemon=True,
                ),
                threading.Thread(
                    target=_read_stream,
                    args=(process.stderr, "stderr", budget, terminate_tree),
                    daemon=True,
                ),
            ]
            for thread in reader_threads:
                thread.start()
            deadline = started + limits.timeout_seconds
            while process.poll() is None:
                child_pids = sorted(set(child_pids) | set(job.process_ids()))
                peak = max(peak, _tree_memory_mib(process.pid))
                if budget.overflow and budget.overflow.is_set():
                    failure = OUTPUT_OVERFLOW
                    terminate_tree()
                    break
                if peak > limits.max_rss_mib:
                    failure = "OOM"
                    terminate_tree()
                    break
                if time.monotonic() >= deadline:
                    failure = "TIMEOUT"
                    terminate_tree()
                    break
                time.sleep(0.01)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                terminate_tree()
                process.wait(timeout=5)
            child_pids = sorted(set(child_pids) | set(job.process_ids()))
            if _alive_pids(child_pids):
                terminate_tree()
                time.sleep(0.1)
            for thread in reader_threads:
                thread.join(timeout=2)
            if budget.overflow and budget.overflow.is_set():
                failure = OUTPUT_OVERFLOW
            if failure is None and process.returncode != 0:
                error_text = bytes(budget.stderr or b"")
                if (
                    b"MemoryError" in error_text
                    or b"out of memory" in error_text.lower()
                    or b"cannot allocate memory" in error_text.lower()
                ):
                    failure = "OOM"
            remaining = job.process_ids()
            descendants_empty = not _alive_pids(remaining)
            if not descendants_empty:
                failure = PROCESS_TREE_NOT_EMPTY
            return SandboxResult(
                backend_id=self.backend_id,
                backend_version=self.backend_version,
                status=(
                    failure
                    or ("PASS" if process.returncode == 0 else "BLOCKED")
                ),
                failure_code=(
                    failure
                    if failure
                    else None
                    if process.returncode == 0
                    else "NONZERO_EXIT"
                ),
                returncode=process.returncode,
                stdout=bytes(budget.stdout or b""),
                stderr=bytes(budget.stderr or b""),
                elapsed_seconds=time.monotonic() - started,
                peak_rss_mib=peak,
                output_bytes=budget.total,
                root_pid=process.pid,
                child_pids=tuple(child_pids),
                descendants_empty=descendants_empty,
                termination_method=termination_method,
                network_policy="ALLOW",
                network_enforced=False,
                network_cleanup_verified=True,
                network_canary={"status": "NOT_REQUIRED"},
            )
        except _JobObjectQueryError as error:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            return _blocked(
                self.backend_id,
                self.backend_version,
                JOB_OBJECT_QUERY_FAILED,
                network_policy="ALLOW",
                error=f"{type(error).__name__}: {error}",
                descendants_empty=False,
                network_cleanup_verified=False,
            )
        except Exception as error:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            return _blocked(
                self.backend_id,
                self.backend_version,
                failure or "JOB_OBJECT_FAILURE",
                network_policy="ALLOW",
                error=f"{type(error).__name__}: {error}",
                descendants_empty=process is None,
                network_cleanup_verified=process is None,
            )
        finally:
            if job is not None:
                job.close()

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | Path | None,
        env: Mapping[str, str] | None,
        limits: SandboxLimits,
        network_policy: str,
        input_file_count: int | None = None,
    ) -> SandboxResult:
        policy = _normalize_policy(network_policy)
        if os.name != "nt":
            return _blocked(
                self.backend_id,
                self.backend_version,
                BLOCKED_ADAPTER,
                network_policy=policy,
                error="Windows Job Object backend is unavailable",
            )
        if limits.max_input_files is not None and input_file_count is not None:
            if input_file_count > limits.max_input_files:
                return _blocked(
                    self.backend_id,
                    self.backend_version,
                    INPUT_FILE_LIMIT,
                    network_policy=policy,
                )
        if not argv:
            return _blocked(
                self.backend_id,
                self.backend_version,
                "EMPTY_ARGV",
                network_policy=policy,
            )
        cwd_path = Path(cwd or os.getcwd()).resolve()
        if policy != "ALLOW" and not self._srt_available:
            return _blocked(
                self.backend_id,
                self.backend_version,
                NETWORK_POLICY_UNENFORCEABLE,
                status=BLOCKED_ADAPTER,
                network_policy=policy,
                error="verified srt-win is unavailable",
            )
        with tempfile.TemporaryDirectory(prefix="fir-srt-") as directory:
            settings_path = Path(directory) / "settings.json"
            settings_path.write_text(
                json.dumps(self._settings(policy, cwd_path), sort_keys=True),
                encoding="utf-8",
            )
            wrapped = self._wrapped(
                argv,
                cwd=cwd_path,
                policy=policy,
                settings_path=settings_path,
            )
            canary = {"status": "NOT_REQUIRED"}
            if policy != "ALLOW":
                canary, passed = _network_canary(
                    lambda canary_argv, canary_limits: self._execute_job(
                        self._wrapped(
                            canary_argv,
                            cwd=cwd_path,
                            policy=policy,
                            settings_path=settings_path,
                        ),
                        cwd=cwd_path,
                        env=env,
                        limits=canary_limits,
                    ),
                    policy,
                )
                if not passed:
                    return _blocked(
                        self.backend_id,
                        self.backend_version,
                        NETWORK_POLICY_UNENFORCEABLE,
                        status=BLOCKED_ADAPTER,
                        network_policy=policy,
                        error=json.dumps(canary, sort_keys=True),
                        descendants_empty=False,
                        network_cleanup_verified=False,
                        network_canary=canary,
                    )
            observed = self._execute_job(
                wrapped,
                cwd=cwd_path,
                env=env,
                limits=limits,
            )
            return SandboxResult(
                **{
                    **observed.__dict__,
                    "network_policy": policy,
                    "network_enforced": policy != "ALLOW",
                    "network_cleanup_verified": (
                        observed.descendants_empty
                        and (policy == "ALLOW" or canary.get("status") == "PASS")
                    ),
                    "network_canary": canary,
                }
            )


class LinuxNsjailSandbox:
    backend_id = "linux.nsjail"
    backend_version = "3.6"

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable

    def probe(self) -> dict[str, Any]:
        return {
            "backend_id": self.backend_id,
            "backend_version": self.backend_version,
            "platform_supported": sys.platform.startswith("linux"),
            "executable": self.executable,
            "available": bool(self.executable),
        }

    def _resource(self) -> tuple[int, str]:
        for name in ("resource",):
            try:
                return __import__(name), ""
            except ImportError:
                continue
        return None, "resource module unavailable"

    def _wrap(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        limits: SandboxLimits,
        policy: str,
    ) -> list[str]:
        assert self.executable
        prefix = [
            self.executable,
            "--quiet",
            "--mode",
            "o",
            "--cwd",
            str(cwd),
            "--time_limit",
            str(max(1, int(limits.timeout_seconds))),
            "--rlimit_as",
            str(max(1, int(limits.max_rss_mib))),
            "--rlimit_nofile",
            "256",
        ]
        if policy != "ALLOW":
            prefix.append("--clone_newnet")
        if policy == "LOOPBACK_ONLY":
            command = [
                "/bin/sh",
                "-c",
                'ip link set dev lo up 2>/dev/null || true; exec "$@"',
                "fir-nsjail",
                *argv,
            ]
        else:
            command = list(argv)
        return [*prefix, "--", *command]

    def _execute(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None,
        limits: SandboxLimits,
    ) -> SandboxResult:
        started = time.monotonic()
        budget = _OutputBudget(limits.max_output_bytes)
        process: subprocess.Popen[bytes] | None = None
        failure: str | None = None
        peak = 0.0
        child_pids: list[int] = []
        termination_method = "natural-exit"

        resource_module, resource_error = self._resource()
        if resource_error:
            return _blocked(
                self.backend_id,
                self.backend_version,
                BLOCKED_ADAPTER,
                network_policy="ALLOW",
                error=resource_error,
            )

        def limit_resources() -> None:
            resource_module.setrlimit(
                resource_module.RLIMIT_AS,
                (
                    max(1, int(limits.max_rss_mib * 1024 * 1024)),
                    max(1, int(limits.max_rss_mib * 1024 * 1024)),
                ),
            )
            resource_module.setrlimit(
                resource_module.RLIMIT_NOFILE,
                (256, 256),
            )

        def terminate_tree() -> None:
            nonlocal termination_method
            if process is None:
                return
            termination_method = "process-group"
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()

        try:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=dict(env) if env is not None else None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
                preexec_fn=limit_resources,
            )
            assert process.stdout is not None
            assert process.stderr is not None
            threads = [
                threading.Thread(
                    target=_read_stream,
                    args=(process.stdout, "stdout", budget, terminate_tree),
                    daemon=True,
                ),
                threading.Thread(
                    target=_read_stream,
                    args=(process.stderr, "stderr", budget, terminate_tree),
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()
            deadline = started + limits.timeout_seconds
            while process.poll() is None:
                if budget.overflow and budget.overflow.is_set():
                    failure = OUTPUT_OVERFLOW
                    terminate_tree()
                    break
                peak = max(peak, _tree_memory_mib(process.pid))
                if peak > limits.max_rss_mib:
                    failure = "OOM"
                    terminate_tree()
                    break
                if time.monotonic() >= deadline:
                    failure = "TIMEOUT"
                    terminate_tree()
                    break
                time.sleep(0.01)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                terminate_tree()
                process.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=2)
            child_pids = sorted(
                {
                    item.pid
                    for item in psutil.Process(process.pid).children(recursive=True)
                }
            )
            descendants_empty = not _alive_pids(child_pids)
            if not descendants_empty:
                failure = PROCESS_TREE_NOT_EMPTY
                terminate_tree()
            return SandboxResult(
                backend_id=self.backend_id,
                backend_version=self.backend_version,
                status=failure or ("PASS" if process.returncode == 0 else "BLOCKED"),
                failure_code=(
                    failure
                    if failure
                    else None
                    if process.returncode == 0
                    else "NONZERO_EXIT"
                ),
                returncode=process.returncode,
                stdout=bytes(budget.stdout or b""),
                stderr=bytes(budget.stderr or b""),
                elapsed_seconds=time.monotonic() - started,
                peak_rss_mib=peak,
                output_bytes=budget.total,
                root_pid=process.pid,
                child_pids=tuple(child_pids),
                descendants_empty=descendants_empty,
                termination_method=termination_method,
                network_policy="ALLOW",
                network_enforced=False,
                network_cleanup_verified=True,
                network_canary={"status": "NOT_REQUIRED"},
            )
        except Exception as error:
            if process is not None and process.poll() is None:
                terminate_tree()
                process.wait(timeout=5)
            return _blocked(
                self.backend_id,
                self.backend_version,
                "NSJAIL_FAILURE",
                network_policy="ALLOW",
                error=f"{type(error).__name__}: {error}",
            )

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | Path | None,
        env: Mapping[str, str] | None,
        limits: SandboxLimits,
        network_policy: str,
        input_file_count: int | None = None,
    ) -> SandboxResult:
        policy = _normalize_policy(network_policy)
        if limits.max_input_files is not None and input_file_count is not None:
            if input_file_count > limits.max_input_files:
                return _blocked(
                    self.backend_id,
                    self.backend_version,
                    INPUT_FILE_LIMIT,
                    network_policy=policy,
                )
        if not argv:
            return _blocked(
                self.backend_id,
                self.backend_version,
                "EMPTY_ARGV",
                network_policy=policy,
            )
        if policy != "ALLOW" and not self.executable:
            return _blocked(
                self.backend_id,
                self.backend_version,
                NETWORK_POLICY_UNENFORCEABLE,
                status=BLOCKED_ADAPTER,
                network_policy=policy,
                error="nsjail is unavailable",
            )
        cwd_path = Path(cwd or os.getcwd()).resolve()
        wrapped = self._wrap(
            argv,
            cwd=cwd_path,
            limits=limits,
            policy=policy,
        )
        canary = {"status": "NOT_REQUIRED"}
        if policy != "ALLOW":
            canary, passed = _network_canary(
                lambda canary_argv, canary_limits: self._execute(
                    self._wrap(
                        canary_argv,
                        cwd=cwd_path,
                        limits=canary_limits,
                        policy=policy,
                    ),
                    cwd=cwd_path,
                    env=env,
                    limits=canary_limits,
                ),
                policy,
            )
            if not passed:
                return _blocked(
                    self.backend_id,
                    self.backend_version,
                    NETWORK_POLICY_UNENFORCEABLE,
                    network_policy=policy,
                    error=json.dumps(canary, sort_keys=True),
                )
        observed = self._execute(
            wrapped,
            cwd=cwd_path,
            env=env,
            limits=limits,
        )
        return SandboxResult(
            **{
                **observed.__dict__,
                "network_policy": policy,
                "network_enforced": policy != "ALLOW",
                "network_cleanup_verified": True,
                "network_canary": canary,
            }
        )


def _process_group_pids(pgid: int) -> list[int]:
    pids: list[int] = []
    try:
        for process in psutil.process_iter(["pid"]):
            if process.pid == pgid:
                continue
            try:
                if os.getpgid(process.pid) != pgid:
                    continue
                if (
                    process.is_running()
                    and process.status() != psutil.STATUS_ZOMBIE
                ):
                    pids.append(process.pid)
            except psutil.NoSuchProcess:
                continue
    except (psutil.Error, OSError) as error:
        raise OSError(f"process group enumeration failed: {error}") from error
    return sorted(set(pids))


class MacSandboxRuntimeBackend:
    backend_id = "macos.sandbox-runtime"
    backend_version = "1.1.0"

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable

    def probe(self) -> dict[str, Any]:
        return {
            "backend_id": self.backend_id,
            "backend_version": self.backend_version,
            "platform_supported": sys.platform == "darwin",
            "executable": self.executable,
            "available": sys.platform == "darwin" and bool(self.executable),
        }

    def _resource(self) -> tuple[Any, str]:
        try:
            resource_module = __import__("resource")
        except ImportError:
            return None, "resource module unavailable"
        for name in ("RLIMIT_AS", "RLIMIT_NOFILE"):
            if not hasattr(resource_module, name):
                return None, f"{name} unavailable"
        return resource_module, ""

    def _wrap(
        self,
        argv: Sequence[str],
        *,
        policy: str,
        settings_path: Path,
    ) -> list[str]:
        if policy == "ALLOW":
            return list(argv)
        assert self.executable is not None
        return [
            self.executable,
            "--settings",
            str(settings_path),
            "--",
            *argv,
        ]

    def _execute(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None,
        limits: SandboxLimits,
    ) -> SandboxResult:
        started = time.monotonic()
        budget = _OutputBudget(limits.max_output_bytes)
        process: subprocess.Popen[bytes] | None = None
        failure: str | None = None
        peak = 0.0
        child_pids: set[int] = set()
        termination_method = "natural-exit"

        resource_module, resource_error = self._resource()
        if resource_error:
            return _blocked(
                self.backend_id,
                self.backend_version,
                BLOCKED_ADAPTER,
                network_policy="ALLOW",
                error=resource_error,
            )

        def limit_resources() -> None:
            memory_bytes = max(1, int(limits.max_rss_mib * 1024 * 1024))
            resource_module.setrlimit(
                resource_module.RLIMIT_AS,
                (memory_bytes, memory_bytes),
            )
            resource_module.setrlimit(
                resource_module.RLIMIT_NOFILE,
                (256, 256),
            )
            if hasattr(resource_module, "RLIMIT_CPU"):
                cpu_seconds = max(1, int(limits.timeout_seconds) + 1)
                resource_module.setrlimit(
                    resource_module.RLIMIT_CPU,
                    (cpu_seconds, cpu_seconds),
                )

        def terminate_tree() -> None:
            nonlocal termination_method
            if process is None:
                return
            termination_method = "process-group"
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                termination_method = "process"
                process.kill()

        try:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=dict(env) if env is not None else None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
                preexec_fn=limit_resources,
            )
            assert process.stdout is not None
            assert process.stderr is not None
            threads = [
                threading.Thread(
                    target=_read_stream,
                    args=(process.stdout, "stdout", budget, terminate_tree),
                    daemon=True,
                ),
                threading.Thread(
                    target=_read_stream,
                    args=(process.stderr, "stderr", budget, terminate_tree),
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()
            deadline = started + limits.timeout_seconds
            while process.poll() is None:
                if budget.overflow and budget.overflow.is_set():
                    failure = OUTPUT_OVERFLOW
                    terminate_tree()
                    break
                peak = max(peak, _tree_memory_mib(process.pid))
                if peak > limits.max_rss_mib:
                    failure = "OOM"
                    terminate_tree()
                    break
                if time.monotonic() >= deadline:
                    failure = "TIMEOUT"
                    terminate_tree()
                    break
                time.sleep(0.01)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                terminate_tree()
                process.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=2)
            if budget.overflow and budget.overflow.is_set():
                failure = OUTPUT_OVERFLOW
            remaining = _process_group_pids(process.pid)
            child_pids.update(remaining)
            if remaining:
                terminate_tree()
                time.sleep(0.1)
                remaining = _process_group_pids(process.pid)
                child_pids.update(remaining)
            descendants_empty = not remaining
            if not descendants_empty:
                failure = PROCESS_TREE_NOT_EMPTY
            return SandboxResult(
                backend_id=self.backend_id,
                backend_version=self.backend_version,
                status=failure or ("PASS" if process.returncode == 0 else "BLOCKED"),
                failure_code=(
                    failure
                    if failure
                    else None
                    if process.returncode == 0
                    else "NONZERO_EXIT"
                ),
                returncode=process.returncode,
                stdout=bytes(budget.stdout or b""),
                stderr=bytes(budget.stderr or b""),
                elapsed_seconds=time.monotonic() - started,
                peak_rss_mib=peak,
                output_bytes=budget.total,
                root_pid=process.pid,
                child_pids=tuple(sorted(child_pids)),
                descendants_empty=descendants_empty,
                termination_method=termination_method,
                network_policy="ALLOW",
                network_enforced=False,
                network_cleanup_verified=descendants_empty,
                network_canary={"status": "NOT_REQUIRED"},
            )
        except Exception as error:
            if process is not None and process.poll() is None:
                terminate_tree()
                process.wait(timeout=5)
            return _blocked(
                self.backend_id,
                self.backend_version,
                "SANDBOX_RUNTIME_FAILURE",
                network_policy="ALLOW",
                error=f"{type(error).__name__}: {error}",
                descendants_empty=False,
                network_cleanup_verified=False,
            )

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | Path | None,
        env: Mapping[str, str] | None,
        limits: SandboxLimits,
        network_policy: str,
        input_file_count: int | None = None,
    ) -> SandboxResult:
        policy = _normalize_policy(network_policy)
        if sys.platform != "darwin" or (policy != "ALLOW" and not self.executable):
            return _blocked(
                self.backend_id,
                self.backend_version,
                NETWORK_POLICY_UNENFORCEABLE,
                status=BLOCKED_ADAPTER,
                network_policy=policy,
                error="sandbox-runtime is unavailable",
            )
        if limits.max_input_files is not None and input_file_count is not None:
            if input_file_count > limits.max_input_files:
                return _blocked(
                    self.backend_id,
                    self.backend_version,
                    INPUT_FILE_LIMIT,
                    network_policy=policy,
                )
        if not argv:
            return _blocked(
                self.backend_id,
                self.backend_version,
                "EMPTY_ARGV",
                network_policy=policy,
            )
        cwd_path = Path(cwd or os.getcwd()).resolve()
        settings = {
            "network": {
                "allowedDomains": (
                    ["localhost", "127.0.0.1"]
                    if policy == "LOOPBACK_ONLY"
                    else []
                ),
                "deniedDomains": [],
                "strictAllowlist": True,
            },
            "filesystem": {
                "denyRead": [],
                "allowRead": [str(cwd_path)],
                "allowWrite": [str(cwd_path)],
                "denyWrite": [],
            },
        }
        with tempfile.TemporaryDirectory(prefix="fir-srt-") as directory:
            settings_path = Path(directory) / "settings.json"
            settings_path.write_text(json.dumps(settings), encoding="utf-8")
            canary = {"status": "NOT_REQUIRED"}
            if policy != "ALLOW":
                canary, passed = _network_canary(
                    lambda canary_argv, canary_limits: self._execute(
                        self._wrap(
                            canary_argv,
                            policy=policy,
                            settings_path=settings_path,
                        ),
                        cwd=cwd_path,
                        env=env,
                        limits=canary_limits,
                    ),
                    policy,
                )
                if not passed:
                    return _blocked(
                        self.backend_id,
                        self.backend_version,
                        NETWORK_POLICY_UNENFORCEABLE,
                        status=BLOCKED_ADAPTER,
                        network_policy=policy,
                        error=json.dumps(canary, sort_keys=True),
                        descendants_empty=False,
                        network_cleanup_verified=False,
                        network_canary=canary,
                    )
            observed = self._execute(
                self._wrap(
                    argv,
                    policy=policy,
                    settings_path=settings_path,
                ),
                cwd=cwd_path,
                env=env,
                limits=limits,
            )
            return SandboxResult(
                **{
                    **observed.__dict__,
                    "network_policy": policy,
                    "network_enforced": policy != "ALLOW",
                    "network_cleanup_verified": (
                        observed.descendants_empty
                        and (policy == "ALLOW" or canary.get("status") == "PASS")
                    ),
                    "network_canary": canary,
                }
            )


def get_backend(
    network_policy: str = "ALLOW",
    *,
    nsjail: str | None = None,
    srt_win: str | None = None,
    mac_sandbox_runtime: str | None = None,
) -> SandboxBackend:
    policy = _normalize_policy(network_policy)
    if os.name == "nt":
        return WindowsJobSandbox(srt_win=srt_win or _resolve_srt_win())
    if sys.platform.startswith("linux"):
        executable = nsjail or os.environ.get("FIR_NSJAIL") or shutil.which("nsjail")
        return LinuxNsjailSandbox(executable=executable)
    if sys.platform == "darwin":
        executable = (
            mac_sandbox_runtime
            or os.environ.get("FIR_SRT")
            or shutil.which("srt")
        )
        return MacSandboxRuntimeBackend(executable=executable)
    return WindowsJobSandbox(srt_win=None)


def run_sandboxed(
    argv: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    limits: SandboxLimits | None = None,
    network_policy: str = "ALLOW",
    input_file_count: int | None = None,
    backend: SandboxBackend | None = None,
) -> SandboxResult:
    limits = limits or SandboxLimits()
    selected = backend or get_backend(network_policy)
    return selected.run(
        argv,
        cwd=cwd,
        env=env,
        limits=limits,
        network_policy=network_policy,
        input_file_count=input_file_count,
    )
