from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping

import psutil
from jsonschema import Draft202012Validator

from .contracts import ContractError, canonical_digest, canonical_json
from .sandbox import (
    SandboxLimits,
    get_backend,
    run_sandboxed,
)
from .strict import fsync_directory, write_all


CAPABILITY_ROOT = Path(__file__).resolve().parents[2] / "capabilities"
DEFAULT_PACK = CAPABILITY_ROOT / "pack.json"
DEFAULT_FIXTURES = CAPABILITY_ROOT / "fixtures.json"
DEFAULT_PROVENANCE = CAPABILITY_ROOT / "provenance.json"
EXECUTION_SCHEMA = (
    Path(__file__).resolve().parents[2] / "contracts/execution-receipt.schema.json"
)
ADAPTER_SCHEMA = (
    Path(__file__).resolve().parents[2] / "contracts/capability-adapter.schema.json"
)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
NETWORK_GUARD_LOCK = threading.Lock()
NETWORK_GUARD_STATE = (
    Path(tempfile.gettempdir()) / "fir-capability-network-guard-state.json"
)
NETWORK_GUARD_OS_LOCK = (
    Path(tempfile.gettempdir()) / "fir-capability-network-guard.lock"
)
ORACLE_SLICES = {
    "SLICE-edfb454882dfc164",
    "SLICE-15323d9fb3ed2b72",
}

TOOL_PATH_CANDIDATES = {
    "ast-grep": (
        "node/ast-grep/node_modules/.bin/ast-grep.cmd",
        "node/ast-grep/node_modules/.bin/ast-grep",
    ),
    "dependency-cruiser": (
        "node/dependency-cruiser/node_modules/.bin/depcruise.cmd",
        "node/dependency-cruiser/node_modules/.bin/depcruise",
    ),
    "eslint": ("node/eslint/node_modules/eslint/bin/eslint.js",),
    "hypothesis": ("py/hypothesis/Scripts/pytest.exe",),
    "import-linter": ("py/import-linter/Scripts/lint-imports.exe",),
    "jsonschema": ("py/jsonschema/Scripts/python.exe",),
    "mypy": ("py/ruff/Scripts/mypy.exe",),
    "mutmut": ("wsl/mutmut/bin/python", "wsl/mutmut/bin/python3"),
    "opengrep": ("opengrep/bin/opengrep.exe",),
    "opengrep-rules": ("opengrep/rules.yaml",),
    "pytest": ("py/hypothesis/Scripts/pytest.exe",),
    "ruff": ("py/ruff/Scripts/ruff.exe",),
    "schemathesis": ("py/schemathesis/Scripts/python.exe",),
    "strykerjs": (
        "node/strykerjs/node_modules/@stryker-mutator/core/bin/stryker.js",
    ),
    "syft": ("bin/syft/v1.57.1/syft.exe",),
    "tree-sitter": ("tree-sitter-web/node_modules/web-tree-sitter/web-tree-sitter.cjs",),
    "trivy": ("bin/trivy/v0.76.2/trivy.exe",),
    "osv-scanner": ("bin/osv-scanner/v2.7.1/osv-scanner.exe",),
}

LOGICAL_TOOL_ALIASES = {
    "@python": ("python",),
    "@node": ("node",),
    "@tool:ast-grep": ("ast-grep",),
    "@tool:dependency-cruiser": ("dependency-cruiser",),
    "@tool:eslint": ("eslint",),
    "@tool:hypothesis-pytest": ("pytest", "hypothesis"),
    "@tool:import-linter": ("import-linter",),
    "@tool:jsonschema-python": ("jsonschema",),
    "@tool:mutmut": ("mutmut",),
    "@tool:mypy": ("mypy",),
    "@tool:opengrep": ("opengrep",),
    "@tool:opengrep-rules": ("opengrep-rules",),
    "@tool:pytest": ("pytest",),
    "@tool:ruff": ("ruff",),
    "@tool:schemathesis-python": ("schemathesis",),
    "@tool:strykerjs": ("strykerjs",),
    "@tool:syft": ("syft",),
    "@tool:tree-sitter-runtime": ("tree-sitter",),
    "@tool:trivy": ("trivy",),
}
PATH_TOOL_ALIASES = {
    "hypothesis": ("pytest", "hypothesis"),
    "import-linter": ("lint-imports", "import-linter"),
    "opengrep": ("opengrep",),
    "pytest": ("pytest",),
    "schemathesis": ("schemathesis",),
}

PYTHON_DISTRIBUTIONS = {
    "jsonschema": "jsonschema",
    "schemathesis": "schemathesis",
}


class CapabilityBlocked(ValueError):
    """Raised when capability evidence cannot produce a trustworthy outcome."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _provenance_root() -> Path | None:
    if not DEFAULT_PROVENANCE.is_file():
        return None
    value = _read_json(DEFAULT_PROVENANCE).get("toolchain_root")
    if not isinstance(value, str) or not value:
        return None
    return Path(value)


def _runtime_registry_tool(tool_id: str) -> Path | None:
    registry_path = (
        Path(__file__).resolve().parents[2]
        / "policies"
        / "runtime-registry-v3.json"
    )
    if not registry_path.is_file():
        return None

    def walk(value: Any) -> Path | None:
        if isinstance(value, dict):
            identifiers = {
                str(value.get(key, ""))
                for key in ("tool_id", "logical_tool_id", "id", "name")
            }
            if tool_id in identifiers:
                for key in ("executable", "path", "resolved_path"):
                    candidate = value.get(key)
                    if isinstance(candidate, str) and Path(candidate).is_file():
                        return Path(candidate).resolve()
                candidates = value.get("executable_candidates")
                if isinstance(candidates, list):
                    for candidate in candidates:
                        if isinstance(candidate, str):
                            resolved = shutil.which(candidate)
                            if resolved:
                                return Path(resolved).resolve()
            for child in value.values():
                resolved = walk(child)
                if resolved is not None:
                    return resolved
        elif isinstance(value, list):
            for child in value:
                resolved = walk(child)
                if resolved is not None:
                    return resolved
        return None

    try:
        return walk(_read_json(registry_path))
    except CapabilityBlocked:
        return None


def _candidate_path(candidate_id: str) -> Path | None:
    registry_path = _runtime_registry_tool(candidate_id)
    if registry_path is not None:
        return registry_path
    root = _provenance_root()
    if root is not None:
        for relative in TOOL_PATH_CANDIDATES.get(candidate_id, ()):
            path = root / relative
            try:
                if path.is_file():
                    return path.resolve()
            except OSError:
                continue
    aliases = PATH_TOOL_ALIASES.get(
        candidate_id,
        LOGICAL_TOOL_ALIASES.get(f"@tool:{candidate_id}", ()),
    )
    for alias in aliases:
        resolved = shutil.which(alias)
        if resolved:
            return Path(resolved).resolve()
    if candidate_id == "opengrep-rules":
        bundled = CAPABILITY_ROOT / "opengrep-rules.yaml"
        if bundled.is_file():
            return bundled.resolve()
    return None


def _resolve_logical_token(token: str) -> str | None:
    if token == "@python":
        return str(Path(sys.executable).resolve())
    if token == "@node":
        resolved = shutil.which("node")
        return str(Path(resolved).resolve()) if resolved else None
    if token == "@tool:tree-sitter-grammar":
        root = _provenance_root()
        if root is None:
            return None
        candidate = root / "tree-sitter-python-v0.25.0.proxy.wasm"
        return str(candidate.resolve()) if candidate.is_file() else None
    if token == "@tool:tree-sitter-runtime":
        root = _provenance_root()
        if root is None:
            return None
        candidate = root / "tree-sitter-web"
        return str(candidate.resolve()) if candidate.is_dir() else None
    aliases = LOGICAL_TOOL_ALIASES.get(token)
    if not aliases:
        return None
    for alias in aliases:
        candidate = _candidate_path(alias)
        if candidate is not None:
            return str(candidate)
    return None


def _resolve_logical_command(command: Iterable[str]) -> list[str]:
    result: list[str] = []
    for argument in command:
        if argument.startswith("@"):
            resolved = _resolve_logical_token(argument)
            if resolved is None:
                raise CapabilityBlocked(
                    f"logical tool is unavailable: {argument}"
                )
            result.append(resolved)
        else:
            result.append(argument)
    return result


def _normalize_version(value: str) -> str:
    first = value.strip().splitlines()[0] if value.strip() else ""
    match = re.search(r"\b\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?\b", first)
    return match.group(0) if match else ""


def _package_version(candidate: Path) -> str | None:
    candidates: list[Path] = []
    for parent in [candidate, *candidate.parents]:
        package = parent / "package.json"
        if package.is_file():
            candidates.append(package)
        if len(candidates) >= 2:
            break
    if candidate.suffix.lower() in {".cmd", ".bat"}:
        text = candidate.read_text(encoding="utf-8", errors="replace")
        for relative in re.findall(r"%dp0%\\\.\.\\([^\"\r\n]+)", text):
            resolved = (candidate.parent / ".." / relative).resolve()
            package = resolved / "package.json"
            if package.is_file():
                candidates.append(package)
    for package in candidates:
        try:
            version = json.loads(package.read_text(encoding="utf-8")).get(
                "version"
            )
        except (OSError, ValueError):
            continue
        if isinstance(version, str) and version:
            return _normalize_version(version)
    return None


def _python_distribution_version(
    interpreter: Path,
    distribution: str,
) -> str | None:
    for parent in interpreter.parents:
        site_packages = parent / "Lib" / "site-packages"
        candidates = [site_packages] if site_packages.is_dir() else []
        venv_root = parent
        candidates.extend(
            sorted(venv_root.glob("lib/python*/site-packages"))
        )
        if not candidates:
            continue
        site_packages = next(
            (item for item in candidates if item.is_dir()),
            None,
        )
        if site_packages is None:
            continue
        wanted = distribution.replace("-", "_").lower()
        for metadata in sorted(site_packages.glob("*.dist-info/METADATA")):
            name = None
            version = None
            try:
                for line in metadata.read_text(
                    encoding="utf-8",
                    errors="replace",
                ).splitlines():
                    if line.lower().startswith("name:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("version:"):
                        version = line.split(":", 1)[1].strip()
                    if name and version:
                        break
            except OSError:
                continue
            if (
                name
                and version
                and name.replace("-", "_").lower() == wanted
            ):
                return _normalize_version(version)
        break
    return None


def _version_command(candidate: Path) -> list[str]:
    suffix = candidate.suffix.lower()
    if suffix == ".js":
        node = shutil.which("node")
        if node is None:
            return []
        return [node, str(candidate), "--version"]
    return [str(candidate), "--version"]


def _observe_version(
    manifest: Mapping[str, Any],
    command: Sequence[str],
) -> tuple[str | None, str]:
    candidate_id = str(manifest.get("candidate_id"))
    candidate = _candidate_path(candidate_id)
    if candidate_id in PYTHON_DISTRIBUTIONS:
        interpreter = (
            candidate
            if candidate is not None
            else Path(command[0]) if command else None
        )
        if interpreter is not None:
            observed = _python_distribution_version(
                interpreter,
                PYTHON_DISTRIBUTIONS[candidate_id],
            )
            if observed:
                return observed, "PACKAGE_METADATA"
    if candidate_id == "mutmut" and candidate is not None:
        observed = _python_distribution_version(candidate, "mutmut")
        if observed:
            return observed, "PACKAGE_METADATA"
    if candidate_id == "mutmut":
        root = _provenance_root()
        if root is not None:
            observed = _python_distribution_version(
                root / "wsl" / "mutmut" / "bin" / "python3.12",
                "mutmut",
            )
            if observed:
                return observed, "PACKAGE_METADATA"
        wsl = shutil.which("wsl.exe")
        if wsl:
            try:
                completed = subprocess.run(
                    [
                        wsl,
                        "-d",
                        "Ubuntu2404",
                        "--",
                        "/mnt/f/Codex/reports/fir-capability-admission-r1-20261114/"
                        "work/runtimes/wsl/mutmut/bin/mutmut",
                        "--version",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=20,
                    check=False,
                )
            except OSError:
                completed = None
            if completed is not None and completed.returncode == 0:
                observed = _normalize_version(completed.stdout)
                if observed:
                    return observed, "OBSERVED"
    if candidate is None and command:
        first = Path(command[0])
        if first.is_file():
            candidate = first.resolve()
    if candidate is None:
        return None, "UNAVAILABLE"
    version_command = _version_command(candidate)
    if not version_command:
        return None, "VERSION_COMMAND_UNAVAILABLE"
    try:
        completed = subprocess.run(
            version_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
    except OSError:
        return None, "VERSION_EXECUTION_FAILED"
    if completed.returncode != 0:
        observed = None
    else:
        observed = _normalize_version(completed.stdout)
    if observed:
        return observed, "OBSERVED"
    package_version = _package_version(candidate)
    if package_version:
        return package_version, "PACKAGE_MANIFEST"
    return None, "VERSION_EXECUTION_FAILED"


def _tool_identity(
    manifest: Mapping[str, Any],
    command: Sequence[str],
) -> dict[str, Any]:
    candidate = _candidate_path(str(manifest.get("candidate_id")))
    observed, source = _observe_version(manifest, command)
    expected = str(manifest.get("exact_version", ""))
    if source == "UNAVAILABLE" and str(manifest.get("candidate_id")).startswith("IC-"):
        observed = expected.removeprefix("v")
        source = "PROJECT_REGISTRY"
    expected_normalized = expected.removeprefix("v")
    version_matches = bool(
        observed
        and (
            observed == expected_normalized
            or observed.startswith(expected_normalized)
            or expected_normalized.startswith(observed)
        )
    )
    interpreter = Path(command[0]).resolve() if command else None
    closure: list[dict[str, str]] = []
    candidates = [
        interpreter,
        candidate,
        *[
            Path(value)
            for value in command
            if Path(value).is_file()
            and Path(value).suffix.lower() in {".js", ".py", ".exe", ".yaml", ".yml"}
        ],
    ]
    seen: set[Path] = set()
    for path in candidates:
        if path is None or path in seen or not path.is_file():
            continue
        seen.add(path)
        closure.append(
            {
                "path": str(path.resolve()),
                "sha256": _sha256_file(path),
                "size": str(path.stat().st_size),
            }
        )
    return {
        "candidate_id": manifest.get("candidate_id"),
        "expected_version": expected,
        "observed_version": observed,
        "version_source": source,
        "version_matches": version_matches,
        "executable": str(candidate.resolve()) if candidate else None,
        "executable_sha256": (
            _sha256_file(candidate) if candidate and candidate.is_file() else None
        ),
        "interpreter": str(interpreter) if interpreter else None,
        "interpreter_sha256": (
            _sha256_file(interpreter)
            if interpreter and interpreter.is_file()
            else None
        ),
        "argv": list(command),
        "argv_digest": canonical_digest(list(command)),
        "closure": sorted(closure, key=lambda item: item["path"]),
        "closure_digest": canonical_digest(
            sorted(closure, key=lambda item: item["path"])
        ),
    }


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CapabilityBlocked(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CapabilityBlocked(f"JSON root must be an object: {path}")
    return value


def _is_link(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _assert_target_safe(target: Path) -> Path:
    absolute = Path(os.path.abspath(target))
    current = absolute
    while True:
        if _is_link(current):
            raise CapabilityBlocked(f"target link/reparse point rejected: {current}")
        if current.parent == current:
            break
        current = current.parent
    if not absolute.exists():
        raise CapabilityBlocked(f"capability target does not exist: {absolute}")
    return absolute


def _target_files(target: Path) -> list[Path]:
    target = _assert_target_safe(target)
    if target.is_file():
        if target.stat().st_nlink > 1:
            raise CapabilityBlocked(f"hard-linked target rejected: {target}")
        return [target]
    files: list[Path] = []
    stack = [target]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if _is_link(path):
                    raise CapabilityBlocked(
                        f"target link/reparse point rejected: {path}"
                    )
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                elif entry.is_file(follow_symlinks=False):
                    if path.stat().st_nlink > 1:
                        raise CapabilityBlocked(
                            f"hard-linked target rejected: {path}"
                        )
                    files.append(path)
                else:
                    raise CapabilityBlocked(
                        f"special target resource rejected: {path}"
                    )
    return sorted(files, key=lambda item: item.relative_to(target).as_posix())


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        payload = (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        try:
            write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        try:
            write_all(descriptor, value.encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _durable_unlink(path: Path) -> None:
    path.unlink(missing_ok=True)
    fsync_directory(path.parent)


def _tree_binding(target: Path) -> dict[str, Any]:
    target = _assert_target_safe(target)
    if target.is_file():
        if target.stat().st_nlink > 1:
            raise CapabilityBlocked(f"hard-linked target rejected: {target}")
        digest = _sha256_file(target)
        return {
            "kind": "FILE",
            "sha256": digest,
            "file_count": 1,
        }
    if not target.is_dir():
        raise CapabilityBlocked(f"capability target does not exist: {target}")
    files = _target_files(target)
    digest = hashlib.sha256()
    for item in files:
        digest.update(item.relative_to(target).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(_sha256_file(item)))
        digest.update(b"\n")
    return {
        "kind": "DIRECTORY" if files else "EMPTY_DIRECTORY",
        "sha256": digest.hexdigest(),
        "file_count": len(files),
    }


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        root = psutil.Process(process.pid)
        children = root.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        children = []
        root = None
    for child in reversed(children):
        try:
            child.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if root is not None:
        try:
            root.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def _read_stream(
    stream: Any,
    limit: int,
    chunks: list[bytes],
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    total = 0
    while True:
        data = stream.read(65536)
        if not data:
            return
        total += len(data)
        if total <= limit:
            chunks.append(data)
        else:
            overflow.set()
            _kill_tree(process)
            return


def _substitute(command: list[str], values: dict[str, str]) -> list[str]:
    result = []
    for item in command:
        try:
            result.append(item.format(**values))
        except KeyError as exc:
            raise CapabilityBlocked(
                f"unknown command template key: {exc}"
            ) from exc
    return result


def _environment(
    manifest: dict[str, Any],
    values: dict[str, str],
) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PATHEXT": os.environ.get("PATHEXT", ""),
        "SystemRoot": os.environ.get("SystemRoot", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    if manifest["network_policy"] == "LOOPBACK_ONLY":
        env.update(
            {
                "NO_PROXY": "127.0.0.1,localhost",
                "no_proxy": "127.0.0.1,localhost",
                "HTTP_PROXY": "",
                "HTTPS_PROXY": "",
                "ALL_PROXY": "",
            }
        )
    else:
        env.update(
            {
                "HTTP_PROXY": "http://127.0.0.1:9",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "ALL_PROXY": "http://127.0.0.1:9",
                "NO_PROXY": "",
            }
        )
    env.update(
        {
            str(key): str(value).format(**values)
            for key, value in manifest.get("environment_overrides", {}).items()
        }
    )
    return env


def _powershell() -> str:
    for candidate in (
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ):
        if Path(candidate).is_file():
            return candidate
    return "powershell.exe"


class _NetworkGuard:
    def __init__(self, manifest: dict[str, Any], command: list[str]):
        self.manifest = manifest
        self.command = command
        self.rule_names: list[str] = []
        self.active = False
        self.method = str(manifest.get("network_enforcement", "ENV_PROXY"))
        self.profile_states_before: dict[str, bool] = {}
        self.profile_states_after: dict[str, bool] = {}
        self.receipt: dict[str, Any] = {}
        self.cleanup_error: str | None = None
        self.os_lock_fd: int | None = None

    def _acquire_guard(self) -> None:
        NETWORK_GUARD_LOCK.acquire()
        descriptor = os.open(
            NETWORK_GUARD_OS_LOCK,
            os.O_RDWR | os.O_CREAT,
            0o600,
        )
        try:
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            while True:
                try:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(
                            descriptor,
                            fcntl.LOCK_EX | fcntl.LOCK_NB,
                        )
                    break
                except OSError:
                    time.sleep(0.1)
        except Exception:
            os.close(descriptor)
            NETWORK_GUARD_LOCK.release()
            raise
        self.os_lock_fd = descriptor

    def _release_guard(self) -> None:
        if self.os_lock_fd is not None:
            try:
                os.lseek(self.os_lock_fd, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(self.os_lock_fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self.os_lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self.os_lock_fd)
                self.os_lock_fd = None
        if NETWORK_GUARD_LOCK.locked():
            NETWORK_GUARD_LOCK.release()

    @staticmethod
    def _recover_stale_state() -> None:
        if not NETWORK_GUARD_STATE.is_file():
            return
        state = _read_json(NETWORK_GUARD_STATE)
        profiles = state.get("profiles_before")
        if not isinstance(profiles, dict):
            raise CapabilityBlocked(
                "NETWORK_POLICY_UNENFORCEABLE: invalid stale guard state"
            )
        completed = subprocess.run(
            [
                _powershell(),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    "$ErrorActionPreference='Stop'; "
                    "$rules=@(Get-NetFirewallRule -PolicyStore ActiveStore "
                    "-ErrorAction Stop | Where-Object {$_.Group -eq "
                    "'FIR capability temporary'}); "
                    "if($rules){$rules | Remove-NetFirewallRule}; "
                    "$remaining=@(Get-NetFirewallRule -PolicyStore ActiveStore "
                    "-ErrorAction Stop | Where-Object {$_.Group -eq "
                    "'FIR capability temporary'}).Count; "
                    "if($remaining -ne 0){exit 3}"
                ),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            raise CapabilityBlocked(
                "NETWORK_POLICY_UNENFORCEABLE: stale rule cleanup failed"
            )
        expected_profiles = {
            str(key): bool(value) for key, value in profiles.items()
        }
        _NetworkGuard._set_firewall_profiles(expected_profiles)
        if _NetworkGuard._firewall_profiles() != expected_profiles:
            raise CapabilityBlocked(
                "NETWORK_POLICY_UNENFORCEABLE: stale profile restore mismatch"
            )
        _durable_unlink(NETWORK_GUARD_STATE)

    @staticmethod
    def _resolve_program(value: str) -> str | None:
        candidate = Path(value)
        if candidate.is_absolute():
            return str(candidate) if candidate.is_file() else None
        resolved = shutil.which(value)
        return str(Path(resolved).resolve()) if resolved else None

    def _programs(self) -> list[str]:
        declared = [
            str(Path(item).resolve())
            for item in self.manifest.get("network_programs", [])
        ]
        launcher = self.command[0]
        if Path(launcher).suffix.lower() not in {".bat", ".cmd"}:
            actual = self._resolve_program(launcher)
            if actual is None:
                raise CapabilityBlocked(
                    f"network guard command program is unresolved: {launcher}"
                )
            declared.insert(0, actual)
            sibling_python = Path(actual).with_name("python.exe")
            if sibling_python.is_file():
                declared.append(str(sibling_python))
        programs = list(dict.fromkeys(declared))
        for program in programs:
            if not Path(program).is_file():
                raise CapabilityBlocked(
                    f"network guard executable missing: {program}"
                )
        if not programs:
            raise CapabilityBlocked("NETWORK_PROGRAM_ALLOWLIST_EMPTY")
        return programs

    @staticmethod
    def _firewall_profiles() -> dict[str, bool]:
        command = [
            _powershell(),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$ErrorActionPreference='Stop'; "
                "Get-NetFirewallProfile | Select-Object Name,Enabled | "
                "ConvertTo-Json -Compress"
            ),
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            raise CapabilityBlocked(
                "NETWORK_POLICY_UNENFORCEABLE: "
                + completed.stderr.strip()[-500:]
            )
        try:
            rows = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise CapabilityBlocked(
                "NETWORK_POLICY_UNENFORCEABLE: invalid firewall profile state"
            ) from exc
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            raise CapabilityBlocked(
                "NETWORK_POLICY_UNENFORCEABLE: invalid firewall profile state"
            )
        return {
            str(row["Name"]): bool(row["Enabled"])
            for row in rows
            if isinstance(row, dict) and "Name" in row and "Enabled" in row
        }

    @staticmethod
    def _set_firewall_profiles(states: dict[str, bool]) -> None:
        allowed = {"Domain", "Private", "Public"}
        if not states or not set(states).issubset(allowed):
            raise CapabilityBlocked(
                "NETWORK_POLICY_UNENFORCEABLE: firewall profiles incomplete"
            )
        clauses = [
            (
                f"Set-NetFirewallProfile -Profile '{name}' "
                f"-Enabled {'True' if enabled else 'False'}"
            )
            for name, enabled in sorted(states.items())
        ]
        completed = subprocess.run(
            [
                _powershell(),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference='Stop'; " + "; ".join(clauses),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            raise CapabilityBlocked(
                "NETWORK_POLICY_UNENFORCEABLE: "
                + completed.stderr.strip()[-500:]
            )

    def __enter__(self) -> dict[str, Any]:
        if self.manifest["network_policy"] == "LOOPBACK_ONLY":
            self.active = True
            self.method = "LOOPBACK_ONLY"
            return {
                "method": self.method,
                "enforced": True,
                "rules": [],
            }
        if self.method == "WSL_NETNS":
            probe = (CAPABILITY_ROOT / "tooling/mutmut_probe.py").resolve()
            if (
                len(self.command) < 2
                or Path(self.command[1]).resolve() != probe
            ):
                raise CapabilityBlocked(
                    "NETWORK_POLICY_UNENFORCEABLE: WSL_NETNS requires bundled probe"
                )
            self.active = True
            return {
                "method": self.method,
                "enforced": True,
                "programs": [str(Path(shutil.which("wsl.exe") or "wsl.exe"))],
                "rules": [],
            }
        if self.method != "WINDOWS_FIREWALL" or os.name != "nt":
            raise CapabilityBlocked("NETWORK_POLICY_UNENFORCEABLE")
        programs = self._programs()
        self._acquire_guard()
        try:
            self._recover_stale_state()
            self.profile_states_before = self._firewall_profiles()
            _atomic_json(
                NETWORK_GUARD_STATE,
                {
                    "schema_version": 1,
                    "pid": os.getpid(),
                    "profiles_before": self.profile_states_before,
                },
            )
            self._set_firewall_profiles(
                {name: True for name in self.profile_states_before}
            )
            rule_name = f"FIR-CAP-{uuid.uuid4().hex}"
            escaped_name = rule_name.replace("'", "''")
            completed = subprocess.run(
                [
                    _powershell(),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    (
                        "$ErrorActionPreference='Stop'; "
                        f"New-NetFirewallRule -DisplayName '{escaped_name}' "
                        "-Group 'FIR capability temporary' -Direction Outbound "
                        "-Action Block -Profile Any -Protocol Any | Out-Null"
                    ),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )
            if completed.returncode != 0:
                raise CapabilityBlocked(
                    "NETWORK_POLICY_UNENFORCEABLE: "
                    + completed.stderr.strip()[-500:]
                )
            self.rule_names.append(rule_name)
        except Exception as setup_exc:
            cleanup_errors: list[str] = []
            try:
                self._remove_rules()
            except Exception as cleanup_exc:
                cleanup_errors.append(str(cleanup_exc))
            if self.cleanup_error is not None:
                cleanup_errors.append(self.cleanup_error)
            if self.profile_states_before:
                try:
                    self._set_firewall_profiles(self.profile_states_before)
                except CapabilityBlocked as restore_exc:
                    cleanup_errors.append(str(restore_exc))
            if not cleanup_errors:
                _durable_unlink(NETWORK_GUARD_STATE)
            self._release_guard()
            if cleanup_errors:
                raise CapabilityBlocked(
                    "NETWORK_POLICY_UNENFORCEABLE: setup failed and "
                    "firewall cleanup failed: " + "; ".join(cleanup_errors)
                ) from setup_exc
            raise
        self.active = True
        self.receipt = {
            "method": self.method,
            "enforced": True,
            "programs": programs,
            "rules": list(self.rule_names),
            "scope": "ALL_PROCESSES",
            "process_serialized": True,
            "profiles_enabled_temporarily": {
                name: enabled
                for name, enabled in self.profile_states_before.items()
                if not enabled
            },
        }
        return self.receipt

    def _remove_rules(self) -> None:
        failures: list[str] = []
        for rule_name in self.rule_names:
            escaped = rule_name.replace("'", "''")
            completed = subprocess.run(
                [
                    _powershell(),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    (
                        "$ErrorActionPreference='Stop'; "
                        f"Remove-NetFirewallRule -DisplayName '{escaped}'"
                    ),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )
            if completed.returncode != 0:
                failures.append(
                    f"{rule_name}: {completed.stderr.strip()[-200:]}"
                )
        remaining = self._firewall_rule_count()
        if remaining:
            failures.append(f"{remaining} temporary rules remain")
        if failures:
            self.cleanup_error = "; ".join(failures)
        else:
            self.rule_names = []

    @staticmethod
    def _firewall_rule_count() -> int:
        completed = subprocess.run(
            [
                _powershell(),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    "$ErrorActionPreference='Stop'; "
                    "@(Get-NetFirewallRule -PolicyStore ActiveStore "
                    "-ErrorAction Stop | Where-Object {$_.Group -eq "
                    "'FIR capability temporary'}).Count"
                ),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            raise CapabilityBlocked(
                "NETWORK_POLICY_UNENFORCEABLE: "
                + completed.stderr.strip()[-500:]
            )
        try:
            return int(completed.stdout.strip())
        except ValueError as exc:
            raise CapabilityBlocked(
                "NETWORK_POLICY_UNENFORCEABLE: invalid firewall rule count"
            ) from exc

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.method == "WINDOWS_FIREWALL" and self.active:
            cleanup_errors: list[str] = []
            try:
                self._remove_rules()
            except Exception as cleanup_exc:
                cleanup_errors.append(str(cleanup_exc))
            if self.cleanup_error is not None:
                cleanup_errors.append(self.cleanup_error)
            try:
                self._set_firewall_profiles(self.profile_states_before)
            except Exception as restore_exc:
                cleanup_errors.append(str(restore_exc))
            try:
                self.profile_states_after = self._firewall_profiles()
                if self.profile_states_after != self.profile_states_before:
                    cleanup_errors.append("firewall profile restore mismatch")
            except Exception as verify_exc:
                cleanup_errors.append(str(verify_exc))
            self.cleanup_error = (
                "; ".join(cleanup_errors) if cleanup_errors else None
            )
            self.receipt["profiles_after"] = self.profile_states_after
            self.receipt["cleanup_error"] = self.cleanup_error
            if self.cleanup_error is None:
                _durable_unlink(NETWORK_GUARD_STATE)
            self._release_guard()
        self.active = False


def _findings_from_json(payload: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        classification = str(payload.get("classification", "")).upper()
        if classification in {"INVALID", "DEFECT_DETECTED", "FINDING"}:
            findings.append(
                {"kind": "CLASSIFICATION", "classification": classification}
            )
        if payload.get("hasError") is True:
            findings.append({"kind": "PARSE_ERROR"})
        results = payload.get("results")
        if isinstance(results, list):
            findings.extend(
                {"kind": "RESULT", "index": index}
                for index, _ in enumerate(results)
            )
        artifacts = payload.get("artifacts")
        if isinstance(artifacts, list) and artifacts:
            findings.append(
                {"kind": "PACKAGE_INVENTORY", "count": len(artifacts)}
            )
        summary = payload.get("summary")
        if (
            isinstance(summary, dict)
            and int(summary.get("totalDependenciesCruised") or 0) > 0
        ):
            findings.append(
                {
                    "kind": "DEPENDENCY_EDGE",
                    "count": summary["totalDependenciesCruised"],
                }
            )
        trivy_results = payload.get("Results")
        if isinstance(trivy_results, list):
            for index, result in enumerate(trivy_results):
                if not isinstance(result, dict):
                    continue
                for field in ("Vulnerabilities", "Packages", "Secrets", "Licenses"):
                    if result.get(field):
                        findings.append(
                            {
                                "kind": f"TRIVY_{field.upper()}",
                                "index": index,
                                "count": len(result[field]),
                            }
                        )
        projections = payload.get("projections")
        if isinstance(projections, list):
            findings.extend(
                {"kind": "BLOCKING_PROJECTION", "case": item.get("case")}
                for item in projections
                if isinstance(item, dict)
                and item.get("aggregate_status") in {"BLOCKED", "MISALIGNED"}
            )
        receipts = payload.get("receipts")
        if isinstance(receipts, list):
            findings.extend(
                {"kind": "INVALID_RECEIPT", "case": item.get("case")}
                for item in receipts
                if isinstance(item, dict)
                and str(item.get("classification", "")).upper() == "INVALID"
            )
        for value in payload.values():
            if isinstance(value, (dict, list)):
                findings.extend(_findings_from_json(value))
    elif isinstance(payload, list):
        for value in payload:
            findings.extend(_findings_from_json(value))
    return findings


def _classify(
    manifest: dict[str, Any],
    exit_code: int,
    stdout_text: str,
) -> tuple[str | None, list[dict[str, Any]], str | None]:
    findings: list[dict[str, Any]] = []
    payload: Any = None
    if manifest.get("output_format") == "JSON":
        if not stdout_text.strip():
            return None, [], "EMPTY_JSON_OUTPUT"
        try:
            payload = json.loads(stdout_text)
        except json.JSONDecodeError:
            return None, [], "MALFORMED_OUTPUT"
        expected_root = manifest.get("json_root")
        if expected_root == "object" and not isinstance(payload, dict):
            return None, [], "JSON_ROOT_MISMATCH"
        if expected_root == "array" and not isinstance(payload, list):
            return None, [], "JSON_ROOT_MISMATCH"
        if expected_root == "array":
            item_fields = manifest.get("json_array_item_required_fields")
            if not item_fields:
                return None, [], "JSON_ARRAY_CONTRACT_MISSING"
            for item in payload:
                if (
                    not isinstance(item, dict)
                    or set(item_fields) - set(item)
                ):
                    return None, [], "JSON_ARRAY_ITEM_INVALID"
        if expected_root == "object":
            missing_fields = sorted(
                set(manifest.get("json_required_fields", [])) - set(payload)
            )
            if missing_fields:
                return None, [], "JSON_FIELD_MISSING"
            if str(payload.get("classification", "")).upper() == (
                "INVALID_CONTRACT"
            ):
                return None, [], "INVALID_OUTPUT_CONTRACT"
        for field, allowed in manifest.get("json_enum_fields", {}).items():
            if payload.get(field) not in allowed:
                return None, [], "JSON_FIELD_VALUE_INVALID"
        findings.extend(_findings_from_json(payload))
    lowered = stdout_text.lower()
    for marker in manifest.get("finding_markers", []):
        if marker.lower() in lowered:
            findings.append({"kind": "OUTPUT_MARKER", "marker": marker})
    for rule in manifest.get("outcome_rules", []):
        if exit_code not in rule["exit_codes"]:
            continue
        if rule["outcome"] == "FINDING":
            if not findings:
                findings.append(
                    {"kind": rule.get("finding_kind", "FINDING")}
                )
            return "FINDING", findings, None
        return ("FINDING" if findings else "CLEAN"), findings, None
    return None, findings, "UNKNOWN_EXIT_CODE"


def _contains_absolute_host_path(value: Any) -> bool:
    if isinstance(value, str):
        if "://" in value:
            return False
        candidate = value.replace("\\", "/")
        return bool(
            candidate.startswith("/")
            or (
                len(candidate) >= 3
                and candidate[1:3] == ":/"
                and candidate[0].isalpha()
            )
            or candidate.startswith("//")
        )
    if isinstance(value, dict):
        return any(_contains_absolute_host_path(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_absolute_host_path(item) for item in value)
    return False


def _fixture_archive_identity(
    path: str | Path = CAPABILITY_ROOT / "fixtures.zip",
) -> dict[str, Any]:
    archive = Path(path).resolve()
    if not archive.is_file():
        raise CapabilityBlocked(f"fixture archive is missing: {archive}")
    members: list[dict[str, Any]] = []
    seen: set[str] = set()
    with zipfile.ZipFile(archive) as handle:
        for item in handle.infolist():
            raw_name = item.filename.replace("\\", "/")
            normalized = raw_name.rstrip("/")
            parts = Path(normalized).parts
            if (
                not normalized
                or raw_name.startswith("/")
                or (len(raw_name) > 1 and raw_name[1] == ":")
                or any(part in {"", ".", ".."} for part in parts)
                or raw_name in seen
            ):
                raise CapabilityBlocked(
                    f"unsafe fixture archive member: {item.filename}"
                )
            seen.add(raw_name)
            mode = (item.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise CapabilityBlocked(
                    f"fixture archive link rejected: {item.filename}"
                )
            payload = b"" if item.is_dir() else handle.read(item)
            members.append(
                {
                    "path": normalized,
                    "kind": "DIRECTORY" if item.is_dir() else "FILE",
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
    members.sort(key=lambda item: item["path"])
    return {
        "archive": str(archive),
        "archive_sha256": _sha256_file(archive),
        "archive_size": archive.stat().st_size,
        "member_table_digest": canonical_digest(members),
        "tree_digest": canonical_digest(
            [
                {
                    "path": item["path"],
                    "sha256": item["sha256"],
                }
                for item in members
                if item["kind"] == "FILE"
            ]
        ),
        "members": members,
    }


def fixture_case_identity(
    fixture: Mapping[str, Any],
    mode: str,
) -> dict[str, Any]:
    archive = _fixture_archive_identity()
    selected = fixture[f"{mode}_target"].replace("\\", "/").rstrip("/")
    selected_members = [
        item
        for item in archive["members"]
        if item["path"] == selected
        or item["path"].startswith(selected + "/")
    ]
    if not selected_members:
        raise CapabilityBlocked(
            f"fixture target is absent from archive: {selected}"
        )
    identity = {
        "archive_sha256": archive["archive_sha256"],
        "archive_size": archive["archive_size"],
        "member_table_digest": archive["member_table_digest"],
        "selected_member": selected,
        "selected_member_digest": canonical_digest(selected_members),
        "extracted_tree_digest": canonical_digest(
            [
                {
                    "path": item["path"],
                    "sha256": item["sha256"],
                }
                for item in selected_members
                if item["kind"] == "FILE"
            ]
        ),
        "positive_assertions_digest": canonical_digest(
            fixture["positive_assertions"]
        ),
        "negative_assertions_digest": canonical_digest(
            fixture["negative_assertions"]
        ),
    }
    identity["fixture_digest"] = canonical_digest(identity)
    return identity


def _extract_fixture_archive(
    archive: Path,
    destination: Path,
) -> None:
    destination.mkdir(parents=True)
    with zipfile.ZipFile(archive) as handle:
        for item in handle.infolist():
            relative = Path(item.filename.replace("\\", "/"))
            if relative.is_absolute() or ".." in relative.parts:
                raise CapabilityBlocked(
                    f"unsafe fixture archive member: {item.filename}"
                )
            target = destination.joinpath(*relative.parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with handle.open(item) as source, target.open("xb") as sink:
                shutil.copyfileobj(source, sink)


def validate_pack(path: str | Path = DEFAULT_PACK) -> dict[str, Any]:
    pack_path = Path(path).resolve()
    pack = _read_json(pack_path)
    adapter_schema = _read_json(ADAPTER_SCHEMA)
    validator = Draft202012Validator(adapter_schema)
    slices = pack.get("slices")
    if not isinstance(slices, list) or len(slices) != 22:
        raise CapabilityBlocked("capability pack must contain 22 slices")
    ids = [str(item.get("slice_id")) for item in slices]
    if len(ids) != len(set(ids)):
        raise CapabilityBlocked("capability pack has duplicate slice IDs")
    for item in slices:
        errors = sorted(validator.iter_errors(item), key=lambda error: error.path)
        if errors:
            raise CapabilityBlocked(
                f"{item.get('slice_id')}: {errors[0].message}"
            )
        if item["release_authority"] is not False:
            raise CapabilityBlocked(
                f"{item['slice_id']} may not hold release authority"
            )
        if (
            item.get("output_format") == "JSON"
            and "classification" in item.get("json_required_fields", [])
            and not item.get("json_enum_fields", {}).get("classification")
        ):
            raise CapabilityBlocked(
                f"{item['slice_id']} classification requires declared enum values"
            )
        if item["slice_id"] in ORACLE_SLICES:
            if not item.get("oracle_only") or item["candidate_id"] != "trivy":
                raise CapabilityBlocked(
                    f"{item['slice_id']} must remain a Trivy-only oracle"
                )
        elif item.get("oracle_only"):
            raise CapabilityBlocked(
                f"unexpected oracle slice: {item['slice_id']}"
            )
    if {item["slice_id"] for item in slices if item.get("oracle_only")} != ORACLE_SLICES:
        raise CapabilityBlocked("oracle slice denominator mismatch")
    pack_digest = pack.get("pack_digest")
    material = {key: value for key, value in pack.items() if key != "pack_digest"}
    if pack_digest != canonical_digest(material):
        raise CapabilityBlocked("capability pack digest mismatch")
    fixtures = load_fixtures()
    serialized = json.dumps(pack, ensure_ascii=False)
    serialized += json.dumps(fixtures, ensure_ascii=False)
    if str(CAPABILITY_ROOT) in serialized:
        raise CapabilityBlocked(
            "capability pack must not bind source-tree tooling paths"
        )
    if _contains_absolute_host_path(pack) or _contains_absolute_host_path(fixtures):
        raise CapabilityBlocked(
            "capability pack must use package-relative logical tool IDs"
        )
    if set(fixtures.get("slices", {})) != set(ids):
        raise CapabilityBlocked("capability fixtures do not cover every slice")
    for slice_id, fixture in fixtures["slices"].items():
        for mode in ("positive", "negative"):
            assertions = fixture.get(f"{mode}_assertions")
            if not isinstance(assertions, list) or not assertions:
                raise CapabilityBlocked(
                    f"{slice_id} {mode} assertions must be non-empty"
                )
        if fixture.get("positive_outcome") != "FINDING":
            raise CapabilityBlocked(f"{slice_id} positive outcome must be FINDING")
        if fixture.get("negative_outcome") != "CLEAN":
            raise CapabilityBlocked(f"{slice_id} negative outcome must be CLEAN")
    lifecycle_fixtures = fixtures.get("lifecycle_fixtures")
    expected_lifecycle = {
        "SKILL:FUNCTIONAL_FAULT:LIFECYCLE",
        "SKILL:RISK_EXPOSURE:LIFECYCLE",
        "SKILL:VULNERABILITY:LIFECYCLE",
    }
    if (
        not isinstance(lifecycle_fixtures, dict)
        or set(lifecycle_fixtures) != expected_lifecycle
    ):
        raise CapabilityBlocked(
            "lifecycle fixtures must cover the three exact lifecycle cells"
        )
    for cell_id, fixture in lifecycle_fixtures.items():
        if not fixture.get("positive") or not fixture.get("negative"):
            raise CapabilityBlocked(
                f"{cell_id} lifecycle fixtures require positive and negative cases"
            )
    archive_identity = _fixture_archive_identity()
    return {
        "schema_version": 1,
        "status": "PASS",
        "pack": str(pack_path),
        "pack_digest": pack_digest,
        "slices": len(slices),
        "oracle_slices": len(ORACLE_SLICES),
        "fixture_archive_digest": archive_identity["archive_sha256"],
        "release_authority": False,
    }


def load_pack(
    path: str | Path = DEFAULT_PACK,
    *,
    slice_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    validate_pack(path)
    pack = _read_json(Path(path).resolve())
    selected = set(slice_ids or ())
    if selected:
        missing = selected - {
            str(item["slice_id"]) for item in pack["slices"]
        }
        if missing:
            raise CapabilityBlocked(
                "unknown capability slices: " + ", ".join(sorted(missing))
            )
        pack["slices"] = [
            item for item in pack["slices"] if item["slice_id"] in selected
        ]
    return pack


def run_slice(
    manifest: dict[str, Any],
    target: str | Path,
    *,
    command_override: list[str] | None = None,
    allow_empty: bool = False,
    timeout_seconds: int | None = None,
    memory_mib: int | None = None,
    max_output_bytes: int | None = None,
    mutation_copy_digest: str | None = None,
    fixture_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    target_path = _assert_target_safe(Path(target))
    before = _tree_binding(target_path)
    if before["file_count"] == 0 and not allow_empty:
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "adapter_id": manifest["adapter_id"],
            "slice_id": manifest["slice_id"],
            "candidate_id": manifest["candidate_id"],
            "subject_digest": before["sha256"],
            "input_digest": before["sha256"],
            "adapter_digest": canonical_digest(manifest),
            "tool_digest": None,
            "rules_digest": None,
            "command_digest": canonical_digest(command_override or []),
            "raw_exit_code": None,
            "findings": [],
            "unsupported_cells": [manifest["slice_id"]],
            "stdout_sha256": EMPTY_SHA256,
            "stderr_sha256": EMPTY_SHA256,
            "elapsed_seconds": 0.0,
            "peak_rss_mib": 0.0,
            "terminal_status": "UNCOVERED",
            "failure_code": "EMPTY_DENOMINATOR",
            "input_kind": before["kind"],
            "input_file_count": before["file_count"],
            "input_tree_digest_after": before["sha256"],
            "input_mutated_by_tool": False,
            "stdout_text": "",
            "stderr_text": "",
            "network_policy": manifest["network_policy"],
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        return receipt

    wsl_target = (
        "/mnt/" + target_path.drive.rstrip(":").lower() + target_path.as_posix()[2:]
        if target_path.drive
        else target_path.as_posix()
    )
    values = {
        "target": str(target_path),
        "wsl_target": wsl_target,
        "tooling": str(CAPABILITY_ROOT / "tooling"),
    }
    command = command_override or _substitute(
        list(manifest["command_template"]),
        values,
    )
    try:
        command = _resolve_logical_command(command)
    except CapabilityBlocked as exc:
        receipt = {
            "schema_version": 1,
            "adapter_id": manifest["adapter_id"],
            "slice_id": manifest["slice_id"],
            "candidate_id": manifest["candidate_id"],
            "subject_digest": before["sha256"],
            "input_digest": before["sha256"],
            "adapter_digest": canonical_digest(manifest),
            "tool_digest": None,
            "rules_digest": manifest.get("rules_digest"),
            "command_digest": canonical_digest(command),
            "raw_exit_code": None,
            "findings": [],
            "unsupported_cells": [manifest["slice_id"]],
            "stdout_sha256": EMPTY_SHA256,
            "stderr_sha256": EMPTY_SHA256,
            "elapsed_seconds": 0.0,
            "peak_rss_mib": 0.0,
            "terminal_status": "UNSUPPORTED",
            "failure_code": "LOGICAL_TOOL_UNAVAILABLE",
            "input_kind": before["kind"],
            "input_file_count": before["file_count"],
            "input_tree_digest_after": before["sha256"],
            "input_mutated_by_tool": False,
            "stdout_text": "",
            "stderr_text": str(exc),
            "network_policy": manifest["network_policy"],
            "network_enforced": False,
            "network_guard_receipt": {
                "method": "unavailable",
                "enforced": False,
                "error": str(exc),
            },
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        return receipt
    executable = Path(command[0])
    if (
        executable.is_absolute()
        and not executable.exists()
    ) or (
        not executable.is_absolute()
        and shutil.which(command[0]) is None
    ):
        receipt = {
            "schema_version": 1,
            "adapter_id": manifest["adapter_id"],
            "slice_id": manifest["slice_id"],
            "candidate_id": manifest["candidate_id"],
            "subject_digest": before["sha256"],
            "input_digest": before["sha256"],
            "adapter_digest": canonical_digest(manifest),
            "tool_digest": None,
            "rules_digest": None,
            "command_digest": canonical_digest(command),
            "raw_exit_code": None,
            "findings": [],
            "unsupported_cells": [manifest["slice_id"]],
            "stdout_sha256": EMPTY_SHA256,
            "stderr_sha256": EMPTY_SHA256,
            "elapsed_seconds": 0.0,
            "peak_rss_mib": 0.0,
            "terminal_status": "UNSUPPORTED",
            "failure_code": "TOOL_UNAVAILABLE",
            "input_kind": before["kind"],
            "input_file_count": before["file_count"],
            "input_tree_digest_after": before["sha256"],
            "input_mutated_by_tool": False,
            "stdout_text": "",
            "stderr_text": "",
            "network_policy": manifest["network_policy"],
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        return receipt

    if manifest.get("mutation_semantics"):
        if mutation_copy_digest is None:
            receipt = {
                "schema_version": 1,
                "adapter_id": manifest["adapter_id"],
                "slice_id": manifest["slice_id"],
                "candidate_id": manifest["candidate_id"],
                "subject_digest": before["sha256"],
                "input_digest": before["sha256"],
                "adapter_digest": canonical_digest(manifest),
                "tool_digest": None,
                "rules_digest": None,
                "command_digest": canonical_digest(command),
                "raw_exit_code": None,
                "findings": [],
                "unsupported_cells": [manifest["slice_id"]],
                "stdout_sha256": EMPTY_SHA256,
                "stderr_sha256": EMPTY_SHA256,
                "elapsed_seconds": 0.0,
                "peak_rss_mib": 0.0,
                "terminal_status": "BLOCKED",
                "failure_code": "MUTATION_REQUIRES_DISPOSABLE_COPY",
                "input_kind": before["kind"],
                "input_file_count": before["file_count"],
                "input_tree_digest_after": before["sha256"],
                "input_mutated_by_tool": False,
                "stdout_text": "",
                "stderr_text": "",
                "network_policy": manifest["network_policy"],
                "mutation_strategy": "REQUIRES_DISPOSABLE_COPY",
            }
            receipt["receipt_digest"] = canonical_digest(receipt)
            return receipt
        if mutation_copy_digest != before["sha256"]:
            receipt = {
                "schema_version": 1,
                "adapter_id": manifest["adapter_id"],
                "slice_id": manifest["slice_id"],
                "candidate_id": manifest["candidate_id"],
                "subject_digest": before["sha256"],
                "input_digest": before["sha256"],
                "adapter_digest": canonical_digest(manifest),
                "tool_digest": None,
                "rules_digest": None,
                "command_digest": canonical_digest(command),
                "raw_exit_code": None,
                "findings": [],
                "unsupported_cells": [manifest["slice_id"]],
                "stdout_sha256": EMPTY_SHA256,
                "stderr_sha256": EMPTY_SHA256,
                "elapsed_seconds": 0.0,
                "peak_rss_mib": 0.0,
                "terminal_status": "BLOCKED",
                "failure_code": "MUTATION_COPY_DIGEST_MISMATCH",
                "input_kind": before["kind"],
                "input_file_count": before["file_count"],
                "input_tree_digest_after": before["sha256"],
                "input_mutated_by_tool": False,
                "stdout_text": "",
                "stderr_text": "",
                "network_policy": manifest["network_policy"],
                "mutation_strategy": "DISPOSABLE_COPY",
                "mutation_copy_digest": mutation_copy_digest,
            }
            receipt["receipt_digest"] = canonical_digest(receipt)
            return receipt

    tool_identity = _tool_identity(manifest, command)
    if command_override is None and (
        tool_identity["version_source"]
        in {"OBSERVED", "PACKAGE_MANIFEST", "PACKAGE_METADATA"}
        and tool_identity["version_matches"] is not True
    ):
        receipt = {
            "schema_version": 1,
            "adapter_id": manifest["adapter_id"],
            "slice_id": manifest["slice_id"],
            "candidate_id": manifest["candidate_id"],
            "subject_digest": before["sha256"],
            "input_digest": before["sha256"],
            "adapter_digest": canonical_digest(
                {
                    "manifest": manifest,
                    "fixture": fixture_identity,
                    "tool": tool_identity,
                }
            ),
            "tool_digest": tool_identity["closure_digest"],
            "rules_digest": manifest.get("rules_digest"),
            "command_digest": canonical_digest(command),
            "raw_exit_code": None,
            "findings": [],
            "unsupported_cells": [manifest["slice_id"]],
            "stdout_sha256": EMPTY_SHA256,
            "stderr_sha256": EMPTY_SHA256,
            "elapsed_seconds": 0.0,
            "peak_rss_mib": 0.0,
            "terminal_status": "UNSUPPORTED",
            "failure_code": "TOOL_IDENTITY_MISMATCH",
            "input_kind": before["kind"],
            "input_file_count": before["file_count"],
            "input_tree_digest_after": before["sha256"],
            "input_mutated_by_tool": False,
            "stdout_text": "",
            "stderr_text": (
                f"expected {tool_identity['expected_version']} "
                f"observed {tool_identity['observed_version']}"
            ),
            "network_policy": manifest["network_policy"],
            "network_enforced": False,
            "network_guard_receipt": {
                "method": "tool-identity-preflight",
                "enforced": False,
                "tool_identity": tool_identity,
            },
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        return receipt
    started = time.perf_counter()
    output_limit = int(max_output_bytes or manifest["max_output_bytes"])
    observed = run_sandboxed(
        command,
        cwd=target_path if target_path.is_dir() else target_path.parent,
        env=_environment(manifest, values),
        limits=SandboxLimits(
            timeout_seconds=float(timeout_seconds or manifest["timeout_seconds"]),
            max_output_bytes=output_limit,
            max_rss_mib=float(memory_mib or manifest["memory_mib"]),
            max_input_files=int(manifest["max_input_files"]),
        ),
        network_policy=str(manifest["network_policy"]),
        input_file_count=before["file_count"],
    )
    failure_code: str | None = observed.failure_code
    terminal_status: str | None = (
        "BLOCKED"
        if observed.status != "PASS"
        and failure_code not in {None, "NONZERO_EXIT"}
        else None
    )
    if failure_code == "OUTPUT_OVERFLOW":
        failure_code = "OUTPUT_LIMIT"
    stdout = observed.stdout
    stderr = observed.stderr
    stdout_text = stdout.decode("utf-8", errors="replace")
    outcome = None
    findings: list[dict[str, Any]] = []
    if terminal_status is None and not manifest.get("mutation_semantics"):
        outcome, findings, classification_failure = _classify(
            manifest,
            int(observed.returncode or 0),
            stdout_text,
        )
        if classification_failure is not None:
            terminal_status = "BLOCKED"
            failure_code = classification_failure
        else:
            terminal_status = "PASS"
            failure_code = None

    after = _tree_binding(target_path)
    input_mutated = before["sha256"] != after["sha256"]
    if input_mutated and mutation_copy_digest is None:
        terminal_status = "BLOCKED"
        failure_code = "SOURCE_MUTATED"
        outcome = None
        findings = []
    if terminal_status is None and manifest.get("mutation_semantics"):
        terminal_status = "PASS"
        outcome = (
            "FINDING"
            if before["sha256"] != after["sha256"]
            else "CLEAN"
        )
        findings = [{"kind": "DETERMINISTIC_REWRITE"}] if outcome == "FINDING" else []
    adapter_digest = canonical_digest(
        {
            "manifest": manifest,
            "fixture": fixture_identity,
            "tool": tool_identity,
        }
    )
    receipt = {
        "schema_version": 1,
        "adapter_id": manifest["adapter_id"],
        "slice_id": manifest["slice_id"],
        "candidate_id": manifest["candidate_id"],
        "subject_digest": before["sha256"],
        "input_digest": before["sha256"],
        "adapter_digest": adapter_digest,
        "tool_digest": tool_identity["closure_digest"],
        "rules_digest": manifest.get("rules_digest"),
        "command_digest": canonical_digest(command),
        "raw_exit_code": observed.returncode,
        "findings": findings,
        "unsupported_cells": (
            [] if terminal_status == "PASS" else [manifest["slice_id"]]
        ),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "elapsed_seconds": observed.elapsed_seconds,
        "peak_rss_mib": observed.peak_rss_mib,
        "terminal_status": terminal_status,
        "failure_code": failure_code,
    }
    if outcome is not None:
        receipt["outcome"] = outcome
    receipt["input_kind"] = before["kind"]
    receipt["input_file_count"] = before["file_count"]
    receipt["input_tree_digest_after"] = after["sha256"]
    receipt["input_mutated_by_tool"] = input_mutated
    receipt["stdout_text"] = stdout_text
    receipt["stderr_text"] = stderr.decode("utf-8", errors="replace")
    receipt["network_policy"] = manifest["network_policy"]
    receipt["network_enforced"] = observed.network_enforced
    receipt["network_guard_receipt"] = {
        **dict(observed.network_canary),
        "method": observed.backend_id,
        "enforced": observed.network_enforced,
        "cleanup_verified": observed.network_cleanup_verified,
        "process_tree": dict(observed.receipt()["process_tree"]),
    }
    if mutation_copy_digest is not None:
        receipt["mutation_strategy"] = "DISPOSABLE_COPY"
        receipt["mutation_copy_digest"] = mutation_copy_digest
    if "fixture_error" in receipt:
        receipt["failure_code"] = receipt["fixture_error"]
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt


def run_pack(
    *,
    target: str | Path,
    output: str | Path,
    pack_path: str | Path = DEFAULT_PACK,
    slice_ids: Iterable[str] | None = None,
    strict: bool = True,
    include_mutation: bool = False,
) -> dict[str, Any]:
    output_path = Path(output).resolve()
    pack = load_pack(pack_path, slice_ids=slice_ids)
    source_target = _assert_target_safe(Path(target))
    source_path = source_target if source_target.is_dir() else source_target.parent
    if (
        output_path == source_path
        or output_path.is_relative_to(source_path)
        or source_path.is_relative_to(output_path)
    ):
        raise CapabilityBlocked(
            f"capability output must be outside target: {output_path}"
        )
    if output_path.exists():
        raise CapabilityBlocked(
            f"capability output already exists: {output_path}"
        )
    output_path.mkdir(parents=True)
    if not include_mutation:
        pack["slices"] = [
            item for item in pack["slices"]
            if not item.get("mutation_semantics")
        ]
    receipts = []
    for manifest in sorted(
        pack["slices"],
        key=lambda item: (
            int(item["implementation_order"]),
            item["slice_id"],
        ),
    ):
        source_before = _tree_binding(source_target)
        work_group = (
            "mutation-candidates"
            if manifest.get("mutation_semantics")
            else "slice-candidates"
        )
        work_target = (
            output_path
            / work_group
            / manifest["slice_id"]
            / (
                source_target.name
                if source_target.is_file()
                else "target"
            )
        )
        _copy_target(source_target, work_target)
        receipt = run_slice(
            manifest,
            work_target,
            allow_empty=False,
            mutation_copy_digest=source_before["sha256"],
        )
        source_after = _tree_binding(source_target)
        receipt["source_digest"] = source_before["sha256"]
        receipt["source_unchanged"] = (
            source_before["sha256"] == source_after["sha256"]
        )
        receipt["target_role"] = "DISPOSABLE_COPY"
        if manifest.get("mutation_semantics"):
            receipt["mutation_source_digest"] = source_before["sha256"]
            receipt["mutation_source_unchanged"] = receipt["source_unchanged"]
        if not receipt["source_unchanged"]:
            receipt["terminal_status"] = "BLOCKED"
            receipt["failure_code"] = "SOURCE_MUTATED"
            receipt.pop("outcome", None)
            receipt["unsupported_cells"] = [manifest["slice_id"]]
        receipt["receipt_digest"] = canonical_digest(
            {
                key: value
                for key, value in receipt.items()
                if key != "receipt_digest"
            }
        )
        _atomic_json(
            output_path / f"{manifest['slice_id']}.json",
            receipt,
        )
        receipts.append(receipt)
    nonterminal = [
        row["slice_id"]
        for row in receipts
        if row["terminal_status"] != "PASS"
    ]
    evidence = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "target": str(source_target),
        "pack_digest": pack["pack_digest"],
        "receipts": receipts,
        "terminal_count": len(receipts) - len(nonterminal),
        "nonterminal": nonterminal,
        "status": (
            "PASS"
            if not nonterminal
            else "BLOCKED"
            if strict
            else "INCOMPLETE"
        ),
        "release_authority": False,
    }
    evidence["evidence_digest"] = canonical_digest(evidence)
    _atomic_json(output_path / "capability-evidence.json", evidence)
    return evidence


def load_fixtures(path: str | Path = DEFAULT_FIXTURES) -> dict[str, Any]:
    fixtures = _read_json(Path(path).resolve())
    if fixtures.get("schema_version") != 1:
        raise CapabilityBlocked("fixtures schema_version must be 1")
    if not isinstance(fixtures.get("slices"), dict):
        raise CapabilityBlocked("fixtures slices must be an object")
    return fixtures


def fixture_command(
    manifest: dict[str, Any],
    fixture: dict[str, Any],
    target: Path,
    mode: str,
) -> list[str] | None:
    override = fixture.get(f"{mode}_command")
    values = {
        "target": str(target),
        "tooling": str(CAPABILITY_ROOT / "tooling"),
    }
    if override is not None:
        return _substitute(list(override), values)
    replacements = fixture.get(f"{mode}_replace", {})
    if replacements:
        return _substitute(
            [
                str(replacements.get(item, item))
                for item in manifest["command_template"]
            ],
            values,
        )
    return None


def run_fixture_case(
    manifest: dict[str, Any],
    fixture: dict[str, Any],
    mode: str,
    *,
    scratch_root: Path | None = None,
    network_policy_override: str | None = None,
) -> dict[str, Any]:
    materialization_root = scratch_root or Path(
        tempfile.mkdtemp(prefix="fir-capability-fixture-")
    )
    target = _materialize_fixture(
        manifest,
        fixture,
        mode,
        materialization_root,
    )
    identity = fixture_case_identity(fixture, mode)
    command = fixture_command(manifest, fixture, target, mode)
    mutation_copy_digest = _tree_binding(target)["sha256"]
    execution_manifest = (
        {**manifest, "network_policy": network_policy_override}
        if network_policy_override is not None
        else manifest
    )
    receipt = run_slice(
        execution_manifest,
        target,
        command_override=command,
        allow_empty=bool(fixture.get(f"allow_empty_{mode}", False)),
        mutation_copy_digest=mutation_copy_digest,
        fixture_identity=identity,
    )
    expected = fixture.get(f"{mode}_outcome")
    if expected and receipt.get("outcome") != expected:
        receipt["fixture_error"] = (
            f"expected {expected}, received {receipt.get('outcome')}"
        )
    for assertion in fixture[f"{mode}_assertions"]:
        kind = assertion.get("kind")
        if kind == "normalized-outcome":
            observed = receipt.get("outcome")
            expected_value = assertion.get("expected")
            if observed != expected_value:
                receipt["fixture_error"] = (
                    f"semantic assertion expected {expected_value}, "
                    f"received {observed}"
                )
                break
        elif kind == "candidate-identity":
            expected_value = assertion.get("expected")
            if receipt.get("candidate_id") != expected_value:
                receipt["fixture_error"] = (
                    f"semantic assertion expected candidate {expected_value}"
                )
                break
    assertion = fixture.get(f"{mode}_assert")
    if assertion:
        lowered = (
            receipt.get("stdout_text", "")
            + "\n"
            + receipt.get("stderr_text", "")
        ).lower()
        missing = [
            marker for marker in assertion
            if marker.lower() not in lowered
        ]
        if missing:
            receipt["fixture_error"] = (
                f"missing output markers {missing}"
            )
    expected_mutation = fixture.get(f"{mode}_mutated")
    if (
        expected_mutation is not None
        and receipt.get("input_mutated_by_tool") is not expected_mutation
    ):
        receipt["fixture_error"] = (
            f"expected mutation {expected_mutation}, "
            f"received {receipt.get('input_mutated_by_tool')}"
        )
    if "fixture_error" in receipt:
        receipt["receipt_digest"] = canonical_digest(
            {
                key: value
                for key, value in receipt.items()
                if key != "receipt_digest"
            }
        )
    return receipt


def validate_receipt(receipt: dict[str, Any]) -> None:
    schema = _read_json(EXECUTION_SCHEMA)
    try:
        Draft202012Validator(schema).validate(receipt)
    except Exception as exc:  # jsonschema.ValidationError
        raise CapabilityBlocked(f"execution receipt invalid: {exc}") from exc
    declared = receipt.get("receipt_digest")
    material = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    if declared != canonical_digest(material):
        raise CapabilityBlocked("execution receipt digest mismatch")


def _copy_target(source: Path, destination: Path) -> None:
    source = _assert_target_safe(source)
    if destination.exists():
        raise CapabilityBlocked(f"scratch target exists: {destination}")
    if source.is_dir():
        _target_files(source)
        shutil.copytree(source, destination)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _fixture_target(fixture: dict[str, Any], mode: str) -> Path:
    return (CAPABILITY_ROOT / fixture[f"{mode}_target"]).resolve()


def _materialize_fixture(
    manifest: dict[str, Any],
    fixture: dict[str, Any],
    mode: str,
    scratch_root: Path,
) -> Path:
    archive = CAPABILITY_ROOT / "fixtures.zip"
    extract_root = scratch_root / f"fixture-archive-{uuid.uuid4().hex}"
    if not archive.is_file():
        raise CapabilityBlocked(f"fixture archive is missing: {archive}")
    _extract_fixture_archive(archive, extract_root)
    source = (extract_root / fixture[f"{mode}_target"]).resolve()
    if not source.exists():
        raise CapabilityBlocked(
            f"fixture target does not exist in archive: {source}"
        )
    leaf = f"{mode}-{uuid.uuid4().hex}"
    if source.is_file():
        leaf += f"-{source.name}"
    destination = scratch_root / manifest["slice_id"] / leaf
    _copy_target(source, destination)
    return destination.resolve()


def _matrix_rows() -> list[dict[str, str]]:
    import csv
    import io

    path = CAPABILITY_ROOT / "test-matrix.csv"
    rows = list(
        csv.DictReader(io.StringIO(path.read_text(encoding="utf-8")))
    )
    if len(rows) != 242:
        raise CapabilityBlocked("capability test matrix must contain 242 rows")
    return rows


def run_contract_matrix(output: str | Path) -> dict[str, Any]:
    output_path = Path(output).resolve()
    if output_path.exists():
        raise CapabilityBlocked(f"matrix output exists: {output_path}")
    output_path.mkdir(parents=True)
    scratch = output_path / "scratch"
    scratch.mkdir()
    started_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    subject = scratch / "subject.txt"
    subject.write_text("frozen capability subject\n", encoding="utf-8")
    empty = scratch / "empty"
    empty.mkdir()
    pack = load_pack()
    runner_before = _sha256_file(Path(__file__).resolve())
    execution_schema_before = _sha256_file(EXECUTION_SCHEMA)
    adapter_schema_before = _sha256_file(ADAPTER_SCHEMA)
    pack_file_before = _sha256_file(DEFAULT_PACK)
    fixtures_before = _sha256_file(DEFAULT_FIXTURES)
    matrix_definition_before = _sha256_file(
        CAPABILITY_ROOT / "test-matrix.csv"
    )
    archive_identity = _fixture_archive_identity()
    manifests = {item["slice_id"]: item for item in pack["slices"]}
    fixtures = load_fixtures()["slices"]
    rows: list[dict[str, Any]] = []

    for matrix in _matrix_rows():
        slice_id = matrix["capability_slice_id"]
        test_class = matrix["test_class"]
        manifest = manifests[slice_id]
        fixture = fixtures[slice_id]
        receipt: dict[str, Any]
        observed = ""
        if test_class == "positive":
            receipt = run_fixture_case(
                manifest,
                fixture,
                "positive",
                scratch_root=scratch,
            )
            observed = str(receipt.get("outcome"))
            passed = (
                receipt["terminal_status"] == "PASS"
                and observed == fixture["positive_outcome"]
                and "fixture_error" not in receipt
            )
        elif test_class == "negative":
            receipt = run_fixture_case(
                manifest,
                fixture,
                "negative",
                scratch_root=scratch,
            )
            observed = str(receipt.get("outcome"))
            passed = (
                receipt["terminal_status"] == "PASS"
                and observed == fixture["negative_outcome"]
                and "fixture_error" not in receipt
            )
        elif test_class == "empty_input":
            receipt = run_slice(manifest, empty, allow_empty=False)
            observed = receipt["terminal_status"]
            passed = observed == "UNCOVERED"
        elif test_class == "malformed_output":
            injected = {
                **manifest,
                "mutation_semantics": False,
                "output_format": "JSON",
                "outcome_rules": [{"outcome": "CLEAN", "exit_codes": [0]}],
                "success_codes": [0],
                "network_enforcement": "WINDOWS_FIREWALL",
                "network_programs": [os.sys.executable],
            }
            receipt = run_slice(
                injected,
                subject,
                command_override=[
                    os.sys.executable,
                    "-c",
                    "print('{malformed')",
                ],
            )
            observed = f"{receipt['terminal_status']}:{receipt.get('failure_code')}"
            passed = (
                receipt["terminal_status"] == "BLOCKED"
                and receipt.get("failure_code") == "MALFORMED_OUTPUT"
            )
        elif test_class == "timeout":
            injected = {
                **manifest,
                "mutation_semantics": False,
                "output_format": "TEXT",
                "outcome_rules": [{"outcome": "CLEAN", "exit_codes": [0]}],
                "success_codes": [0],
                "network_enforcement": "WINDOWS_FIREWALL",
                "network_programs": [os.sys.executable],
            }
            receipt = run_slice(
                injected,
                subject,
                command_override=[
                    os.sys.executable,
                    "-c",
                    "import time; time.sleep(5)",
                ],
                timeout_seconds=1,
            )
            observed = f"{receipt['terminal_status']}:{receipt.get('failure_code')}"
            passed = (
                receipt["terminal_status"] == "BLOCKED"
                and receipt.get("failure_code") == "TIMEOUT"
            )
        elif test_class == "oom":
            injected = {
                **manifest,
                "mutation_semantics": False,
                "output_format": "TEXT",
                "outcome_rules": [{"outcome": "CLEAN", "exit_codes": [0]}],
                "success_codes": [0],
                "network_enforcement": "WINDOWS_FIREWALL",
                "network_programs": [os.sys.executable],
            }
            receipt = run_slice(
                injected,
                subject,
                command_override=[
                    os.sys.executable,
                    "-c",
                    (
                        "import time; blocks=[]; "
                        "[blocks.append(bytearray(16*1024*1024)) "
                        "for _ in range(16)]; time.sleep(2)"
                    ),
                ],
                memory_mib=32,
            )
            observed = f"{receipt['terminal_status']}:{receipt.get('failure_code')}"
            passed = (
                receipt["terminal_status"] == "BLOCKED"
                and receipt.get("failure_code") == "MEMORY_LIMIT"
            )
        elif test_class == "output_overflow":
            injected = {
                **manifest,
                "mutation_semantics": False,
                "output_format": "TEXT",
                "outcome_rules": [{"outcome": "CLEAN", "exit_codes": [0]}],
                "success_codes": [0],
                "network_enforcement": "WINDOWS_FIREWALL",
                "network_programs": [os.sys.executable],
            }
            receipt = run_slice(
                injected,
                subject,
                command_override=[
                    os.sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('x'*200000)",
                ],
                max_output_bytes=1024,
            )
            observed = f"{receipt['terminal_status']}:{receipt.get('failure_code')}"
            passed = (
                receipt["terminal_status"] == "BLOCKED"
                and receipt.get("failure_code") == "OUTPUT_LIMIT"
            )
        elif test_class == "tool_failure":
            receipt = run_slice(
                manifest,
                subject,
                command_override=[str(scratch / "missing-tool.exe")],
            )
            observed = receipt["terminal_status"]
            passed = observed == "UNSUPPORTED"
        elif test_class == "offline":
            receipt = run_fixture_case(
                manifest,
                fixture,
                "positive",
                scratch_root=scratch,
            )
            observed = receipt["terminal_status"]
            passed = (
                observed == "PASS"
                and "fixture_error" not in receipt
            )
        elif test_class == "repeatability":
            first = run_fixture_case(
                manifest,
                fixture,
                "negative",
                scratch_root=scratch,
            )
            second = run_fixture_case(
                manifest,
                fixture,
                "negative",
                scratch_root=scratch,
            )
            observed = (
                f"{first.get('outcome')}:{second.get('outcome')}"
            )
            passed = (
                first["terminal_status"] == second["terminal_status"] == "PASS"
                and first.get("outcome") == second.get("outcome")
                and "fixture_error" not in first
                and "fixture_error" not in second
            )
            receipt = {
                "schema_version": 1,
                "status": "PASS" if passed else "BLOCKED",
                "first_receipt_digest": first["receipt_digest"],
                "second_receipt_digest": second["receipt_digest"],
                "outcome": first.get("outcome"),
            }
        elif test_class == "rollback":
            source = _materialize_fixture(
                manifest,
                fixture,
                "negative",
                scratch,
            )
            candidate = _materialize_fixture(
                manifest,
                fixture,
                "negative",
                scratch,
            )
            source_before = _tree_binding(source)
            candidate_before = _tree_binding(candidate)
            if candidate.is_dir():
                shutil.rmtree(candidate)
            else:
                candidate.unlink()
            source_after = _tree_binding(source)
            observed = (
                "ROLLBACK_VERIFIED"
                if (
                    not candidate.exists()
                    and source_before["sha256"] == source_after["sha256"]
                    and candidate_before["sha256"] == source_before["sha256"]
                )
                else "BLOCKED"
            )
            passed = observed == "ROLLBACK_VERIFIED"
            receipt = {
                "schema_version": 1,
                "status": "PASS" if passed else "BLOCKED",
                "source_before": source_before,
                "candidate_before": candidate_before,
                "source_after": source_after,
                "candidate_exists": candidate.exists(),
            }
        else:
            raise CapabilityBlocked(f"unknown test class: {test_class}")
        if "receipt_digest" in receipt:
            validate_receipt(receipt)
        row = {
            "capability_slice_id": slice_id,
            "candidate_id": manifest["candidate_id"],
            "test_class": test_class,
            "expected": matrix["expected"],
            "observed": observed,
            "status": "PASS" if passed else "BLOCKED",
            "fixture_archive_sha256": archive_identity["archive_sha256"],
            "fixture_member_table_digest": archive_identity[
                "member_table_digest"
            ],
            "fixture_tree_digest": archive_identity["tree_digest"],
            "receipt": receipt,
        }
        row["row_digest"] = canonical_digest(row)
        rows.append(row)

    failures = [
        {
            "capability_slice_id": row["capability_slice_id"],
            "test_class": row["test_class"],
            "observed": row["observed"],
        }
        for row in rows
        if row["status"] != "PASS"
    ]
    supplemental_controls: list[dict[str, Any]] = []
    first_manifest = next(iter(manifests.values()))
    unknown_manifest = {
        **first_manifest,
        "mutation_semantics": False,
        "output_format": "TEXT",
        "outcome_rules": [{"outcome": "CLEAN", "exit_codes": [0]}],
        "success_codes": [0],
        "network_enforcement": "WINDOWS_FIREWALL",
        "network_programs": [os.sys.executable],
    }
    unknown_receipt = run_slice(
        unknown_manifest,
        subject,
        command_override=[
            os.sys.executable,
            "-c",
            "raise SystemExit(42)",
        ],
    )
    supplemental_controls.append(
        {
            "id": "UNKNOWN_EXIT_CODE",
            "status": (
                "PASS"
                if (
                    unknown_receipt["terminal_status"] == "BLOCKED"
                    and unknown_receipt.get("failure_code") == "UNKNOWN_EXIT_CODE"
                    and "outcome" not in unknown_receipt
                )
                else "BLOCKED"
            ),
            "observed": (
                f"{unknown_receipt['terminal_status']}:"
                f"{unknown_receipt.get('failure_code')}"
            ),
            "receipt_digest": unknown_receipt["receipt_digest"],
        }
    )
    mutation_manifest = next(
        item for item in manifests.values() if item.get("mutation_semantics")
    )
    mutation_fixture = fixtures[mutation_manifest["slice_id"]]
    mutation_source = _materialize_fixture(
        mutation_manifest,
        mutation_fixture,
        "positive",
        scratch,
    )
    mutation_source_before = _tree_binding(mutation_source)
    mutation_evidence = run_pack(
        target=mutation_source,
        output=output_path / "mutation-disposable-control",
        slice_ids=[mutation_manifest["slice_id"]],
        include_mutation=True,
    )
    mutation_receipt = mutation_evidence["receipts"][0]
    mutation_source_after = _tree_binding(mutation_source)
    mutation_passed = (
        mutation_evidence["status"] == "PASS"
        and mutation_receipt["terminal_status"] == "PASS"
        and mutation_receipt.get("mutation_strategy") == "DISPOSABLE_COPY"
        and mutation_receipt.get("mutation_source_unchanged") is True
        and mutation_source_before["sha256"] == mutation_source_after["sha256"]
    )
    supplemental_controls.append(
        {
            "id": "MUTATION_DISPOSABLE_COPY",
            "status": "PASS" if mutation_passed else "BLOCKED",
            "observed": {
                "source_unchanged": (
                    mutation_source_before["sha256"]
                    == mutation_source_after["sha256"]
                ),
                "strategy": mutation_receipt.get("mutation_strategy"),
                "terminal_status": mutation_receipt["terminal_status"],
            },
            "receipt_digest": mutation_receipt["receipt_digest"],
        }
    )
    self_contained = str(CAPABILITY_ROOT) not in (
        json.dumps(pack, ensure_ascii=False)
        + json.dumps(load_fixtures(), ensure_ascii=False)
    )
    supplemental_controls.append(
        {
            "id": "INSTALLED_PACK_SELF_CONTAINED",
            "status": "PASS" if self_contained else "BLOCKED",
            "observed": self_contained,
        }
    )
    runner_after = _sha256_file(Path(__file__).resolve())
    execution_schema_after = _sha256_file(EXECUTION_SCHEMA)
    adapter_schema_after = _sha256_file(ADAPTER_SCHEMA)
    pack_file_after = _sha256_file(DEFAULT_PACK)
    fixtures_after = _sha256_file(DEFAULT_FIXTURES)
    matrix_definition_after = _sha256_file(
        CAPABILITY_ROOT / "test-matrix.csv"
    )
    identity_stable = (
        runner_before == runner_after
        and execution_schema_before == execution_schema_after
        and adapter_schema_before == adapter_schema_after
        and pack_file_before == pack_file_after
        and fixtures_before == fixtures_after
        and matrix_definition_before == matrix_definition_after
    )
    supplemental_controls.append(
        {
            "id": "MATRIX_RUNNER_IDENTITY_STABLE",
            "status": "PASS" if identity_stable else "BLOCKED",
            "observed": identity_stable,
        }
    )
    supplemental_failures = [
        item["id"]
        for item in supplemental_controls
        if item["status"] != "PASS"
    ]
    result = {
        "schema_version": 1,
        "status": (
            "PASS"
            if not failures and not supplemental_failures
            else "BLOCKED"
        ),
        "started_at": started_at,
        "completed_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "rows": len(rows),
        "passes": len(rows) - len(failures),
        "failures": failures,
        "supplemental_controls": supplemental_controls,
        "supplemental_failures": supplemental_failures,
        "pack_digest": pack["pack_digest"],
        "runner_digest": runner_after,
        "execution_schema_digest": execution_schema_after,
        "adapter_schema_digest": adapter_schema_after,
        "pack_file_digest": pack_file_after,
        "fixtures_digest": fixtures_after,
        "matrix_definition_digest": matrix_definition_after,
        "fixture_archive_sha256": archive_identity["archive_sha256"],
        "fixture_member_table_digest": archive_identity["member_table_digest"],
        "fixture_tree_digest": archive_identity["tree_digest"],
        "release_authority": False,
    }
    result["matrix_digest"] = canonical_digest(result)
    _atomic_json(output_path / "matrix.json", result)
    rows_path = output_path / "matrix.jsonl"
    _atomic_text(
        rows_path,
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
    )
    return result
