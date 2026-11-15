from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Mapping

from .contracts import canonical_digest
from .capabilities import load_fixtures
from .external_adapters import adapter_receipt, run_external_cell
from .sandbox import SandboxLimits, run_sandboxed


LIFECYCLE_CELL_IDS = frozenset(
    {
        "SKILL:FUNCTIONAL_FAULT:LIFECYCLE",
        "SKILL:RISK_EXPOSURE:LIFECYCLE",
        "SKILL:VULNERABILITY:LIFECYCLE",
    }
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_digest(root: Path) -> str:
    records = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": _sha256(path),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]
    return canonical_digest(records)


def _receipt(
    *,
    cell_id: str,
    logical_tool_id: str,
    mechanism_id: str,
    status: str,
    failure_code: str | None,
    expected_version: str,
    observed_version: str | None,
    argv: list[str],
    fixture_digest: str | None,
    target_digest: str | None,
    facts: list[dict[str, Any]] | None = None,
    inner: Mapping[str, Any] | None = None,
    fixture_binding: Mapping[str, Any] | None = None,
    fixture_execution: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    interpreter = Path(sys.executable).resolve()
    closure_digest = canonical_digest(
        [{"path": str(interpreter), "sha256": _sha256(interpreter)}]
    )
    return adapter_receipt(
        cell_id=cell_id,
        logical_tool_id=logical_tool_id,
        mechanism_id=mechanism_id,
        status=status,
        failure_code=failure_code,
        executable=str(interpreter),
        interpreter=str(interpreter),
        expected_version=expected_version,
        observed_version=observed_version,
        argv=argv,
        rule_digest=None,
        fixture_digest=fixture_digest,
        target_digest=target_digest,
        closure_digest=closure_digest,
        facts=facts or [],
        inner_receipt=inner,
        fixture_binding=fixture_binding,
        fixture_execution=fixture_execution,
    )


def _wheel_name(version: str) -> str:
    return f"fir_lifecycle_fixture-{version}-py3-none-any.whl"


def _build_wheel(
    directory: Path,
    version: str,
    *,
    broken_entry: bool,
) -> Path:
    package = "fir_lifecycle_fixture"
    dist_info = f"{package}-{version}.dist-info"
    files = {
        f"{package}/__init__.py": (
            f"__version__ = {version!r}\n"
            f"BROKEN_ENTRY = {broken_entry!r}\n"
        ),
        f"{package}/__main__.py": (
            "import sys\n"
            f"from . import __version__, BROKEN_ENTRY\n"
            "def main():\n"
            "    if BROKEN_ENTRY:\n"
            "        print('broken lifecycle entry', file=sys.stderr)\n"
            "        raise SystemExit(7)\n"
            "    print(__version__)\n"
            "    return 0\n"
            "raise SystemExit(main())\n"
        ),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: fir-lifecycle-fixture\n"
            f"Version: {version}\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: FIR lifecycle fixture\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
        f"{dist_info}/entry_points.txt": (
            "[console_scripts]\n"
            "fir-lifecycle-fixture = fir_lifecycle_fixture.__main__:main\n"
        ),
    }
    records = []
    for path, content in files.items():
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        records.append(
            f"{path},sha256={digest},{len(content.encode('utf-8'))}"
        )
    record_path = f"{dist_info}/RECORD"
    files[record_path] = "\n".join([*records, f"{record_path},,"]) + "\n"
    wheel = directory / _wheel_name(version)
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content in sorted(files.items()):
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content.encode("utf-8"))
    return wheel


def _pip_install(
    wheel: Path,
    target: Path,
    *,
    upgrade: bool,
) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--no-index",
        "--no-deps",
        "--disable-pip-version-check",
        "--target",
        str(target),
    ]
    if upgrade:
        command.extend(["--upgrade", "--force-reinstall"])
    command.append(str(wheel))
    observed = run_sandboxed(
        command,
        cwd=target.parent,
        limits=SandboxLimits(
            timeout_seconds=120,
            max_output_bytes=2 * 1024 * 1024,
            max_rss_mib=1024,
            max_input_files=32,
        ),
        network_policy="ALLOW",
        input_file_count=1,
    )
    return observed.receipt()


def _run_installed_entry(target: Path, cwd: Path) -> dict[str, Any]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(target)
    observed = run_sandboxed(
        [sys.executable, "-B", "-m", "fir_lifecycle_fixture"],
        cwd=cwd,
        env=env,
        limits=SandboxLimits(
            timeout_seconds=20,
            max_output_bytes=65536,
            max_rss_mib=256,
            max_input_files=32,
        ),
        network_policy="ALLOW",
        input_file_count=1,
    )
    return observed.receipt()


def _run_install_scenario(
    definition: Mapping[str, Any],
    scratch: Path,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    baseline_version = str(definition["baseline_version"])
    candidate_version = str(definition["candidate_version"])
    broken = definition["candidate_entry"] == "broken"
    baseline_wheel = _build_wheel(
        scratch,
        baseline_version,
        broken_entry=False,
    )
    candidate_wheel = _build_wheel(
        scratch,
        candidate_version,
        broken_entry=broken,
    )
    target = scratch / "installed"
    receipts: list[dict[str, Any]] = []
    receipts.append(_pip_install(baseline_wheel, target, upgrade=False))
    baseline_run = _run_installed_entry(target, scratch)
    receipts.append(baseline_run)
    receipts.append(_pip_install(candidate_wheel, target, upgrade=True))
    candidate_run = _run_installed_entry(target, scratch)
    receipts.append(candidate_run)
    if target.exists():
        shutil.rmtree(target)
    receipts.append(_pip_install(baseline_wheel, target, upgrade=False))
    rollback_run = _run_installed_entry(target, scratch)
    receipts.append(rollback_run)
    upgrade_failed = (
        candidate_run["status"] != "PASS"
        or candidate_run["failure_code"] == "NONZERO_EXIT"
    )
    outcome = "FINDING" if upgrade_failed else "CLEAN"
    rollback_ok = rollback_run["status"] == "PASS"
    baseline_ok = baseline_run["status"] == "PASS"
    return {
        "status": "PASS" if baseline_ok and rollback_ok else "BLOCKED",
        "outcome": outcome,
        "failure_code": None if baseline_ok and rollback_ok else "ROLLBACK_FAILED",
        "baseline_wheel_sha256": _sha256(baseline_wheel),
        "candidate_wheel_sha256": _sha256(candidate_wheel),
        "receipts": receipts,
    }


def run_frozen_install_pair(cell_id: str) -> dict[str, Any]:
    definition = load_fixtures()["lifecycle_fixtures"][cell_id]
    with tempfile.TemporaryDirectory(prefix="fir-lifecycle-install-pair-") as directory:
        root = Path(directory)
        positive = _run_install_scenario(
            definition["positive"],
            root / "positive",
        )
        negative = _run_install_scenario(
            definition["negative"],
            root / "negative",
        )
        passed = (
            positive["status"] == "PASS"
            and negative["status"] == "PASS"
            and positive["outcome"] == "FINDING"
            and negative["outcome"] == "CLEAN"
        )
        binding = {
            "descriptor": definition,
            "descriptor_digest": canonical_digest(definition),
            "positive": definition["positive"],
            "negative": definition["negative"],
            "positive_artifacts_digest": canonical_digest(
                {
                    "baseline": positive["baseline_wheel_sha256"],
                    "candidate": positive["candidate_wheel_sha256"],
                }
            ),
            "negative_artifacts_digest": canonical_digest(
                {
                    "baseline": negative["baseline_wheel_sha256"],
                    "candidate": negative["candidate_wheel_sha256"],
                }
            ),
        }
        facts = (
            [
                {
                    "cell_id": cell_id,
                    "predicate_id": "install-upgrade-rollback",
                    "normalized_locator": ".",
                    "logical_unit_id": "L01",
                    "normalized_value_digest": canonical_digest(
                        {
                            "positive": positive["outcome"],
                            "negative": negative["outcome"],
                        }
                    ),
                }
            ]
            if passed
            else []
        )
        return _receipt(
            cell_id=cell_id,
            logical_tool_id="pip-lifecycle-fixture",
            mechanism_id="L01",
            status="PASS" if passed else "BLOCKED_ADAPTER",
            failure_code=None if passed else "LIFECYCLE_FIXTURE_FAILED",
            expected_version=f"{platform.python_version()} / pip",
            observed_version=platform.python_version(),
            argv=[
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
            ],
            fixture_digest=canonical_digest(binding),
            target_digest=canonical_digest(binding),
            facts=facts,
            inner={"positive": positive, "negative": negative},
            fixture_binding=binding,
            fixture_execution={"positive": positive, "negative": negative},
        )


def _run_process_scenario(
    definition: Mapping[str, Any],
    scratch: Path,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    pid_file = scratch / "child.pid"
    spawn_child = bool(definition["spawn_child"])
    sleep_seconds = int(definition.get("child_sleep_seconds", 0))
    code = (
        "import subprocess,sys,time\n"
        "from pathlib import Path\n"
        f"spawn_child={spawn_child!r}\n"
        f"sleep_seconds={sleep_seconds!r}\n"
        "if spawn_child:\n"
        "    p=subprocess.Popen([sys.executable,'-B','-c',"
        "'import time; time.sleep(30)'])\n"
        f"    Path({str(pid_file)!r}).write_text(str(p.pid),encoding='utf-8')\n"
        "time.sleep(.1)\n"
    )
    observed = run_sandboxed(
        [sys.executable, "-B", "-I", "-c", code],
        cwd=scratch,
        limits=SandboxLimits(
            timeout_seconds=10,
            max_output_bytes=65536,
            max_rss_mib=256,
            max_input_files=16,
        ),
        network_policy="ALLOW",
        input_file_count=0,
    )
    child_pid = (
        int(pid_file.read_text(encoding="utf-8"))
        if pid_file.is_file()
        else None
    )
    passed = observed.status == "PASS" and observed.descendants_empty
    return {
        "status": "PASS" if passed else "BLOCKED",
        "outcome": "PROTECTED" if passed else "BLOCKED",
        "failure_code": None if passed else "PROCESS_TREE_NOT_EMPTY",
        "child_pid": child_pid,
        "receipt": observed.receipt(),
    }


def run_frozen_process_pair(cell_id: str) -> dict[str, Any]:
    definition = load_fixtures()["lifecycle_fixtures"][cell_id]
    with tempfile.TemporaryDirectory(prefix="fir-lifecycle-process-pair-") as directory:
        root = Path(directory)
        positive = _run_process_scenario(definition["positive"], root / "positive")
        negative = _run_process_scenario(definition["negative"], root / "negative")
        passed = (
            positive["status"] == "PASS"
            and negative["status"] == "PASS"
            and positive["outcome"] == "PROTECTED"
            and negative["outcome"] == "PROTECTED"
        )
        binding = {
            "descriptor": definition,
            "descriptor_digest": canonical_digest(definition),
            "positive": definition["positive"],
            "negative": definition["negative"],
            "positive_receipt_digest": positive["receipt"]["receipt_digest"],
            "negative_receipt_digest": negative["receipt"]["receipt_digest"],
        }
        return _receipt(
            cell_id=cell_id,
            logical_tool_id="windows.job-object",
            mechanism_id="L04",
            status="PASS" if passed else "BLOCKED_ADAPTER",
            failure_code=None if passed else "PROCESS_TREE_PROBE_FAILED",
            expected_version=platform.python_version(),
            observed_version=platform.python_version(),
            argv=[sys.executable, "-B", "-I", "-c", "<frozen-process-tree-fixture>"],
            fixture_digest=canonical_digest(binding),
            target_digest=canonical_digest(binding),
            facts=[],
            inner={"positive": positive, "negative": negative},
            fixture_binding=binding,
            fixture_execution={"positive": positive, "negative": negative},
        )


def _dependency_case(
    definition: Mapping[str, Any],
) -> tuple[bool, str]:
    from packaging.version import Version

    version = Version(str(definition["version"]))
    introduced = Version(str(definition["introduced"]))
    fixed = Version(str(definition["fixed"]))
    vulnerable = introduced <= version < fixed
    return (
        vulnerable == bool(definition["expected_vulnerable"]),
        "FINDING" if vulnerable else "CLEAN",
    )


def run_frozen_dependency_pair(cell_id: str) -> dict[str, Any]:
    definition = load_fixtures()["lifecycle_fixtures"][cell_id]
    try:
        positive_ok, positive_outcome = _dependency_case(definition["positive"])
        negative_ok, negative_outcome = _dependency_case(definition["negative"])
    except (ImportError, KeyError, ValueError) as error:
        return _receipt(
            cell_id=cell_id,
            logical_tool_id="dependency-lockfile-fixture",
            mechanism_id="L05",
            status="BLOCKED_ADAPTER",
            failure_code="DEPENDENCY_PROBE_UNAVAILABLE",
            expected_version=platform.python_version(),
            observed_version=platform.python_version(),
            argv=[],
            fixture_digest=canonical_digest(definition),
            target_digest=None,
            inner={"error": f"{type(error).__name__}: {error}"},
        )
    passed = (
        positive_ok
        and negative_ok
        and positive_outcome == "FINDING"
        and negative_outcome == "CLEAN"
    )
    binding = {
        "descriptor": definition,
        "descriptor_digest": canonical_digest(definition),
        "positive": definition["positive"],
        "negative": definition["negative"],
    }
    facts = (
        [
            {
                "cell_id": cell_id,
                "predicate_id": "dependency-lockfile-membership",
                "normalized_locator": definition["positive"]["package"],
                "logical_unit_id": "L05",
                "normalized_value_digest": canonical_digest(
                    {
                        "positive": positive_outcome,
                        "negative": negative_outcome,
                    }
                ),
            }
        ]
        if passed
        else []
    )
    return _receipt(
        cell_id=cell_id,
        logical_tool_id="dependency-lockfile-fixture",
        mechanism_id="L05",
        status="PASS" if passed else "BLOCKED_ADAPTER",
        failure_code=None if passed else "DEPENDENCY_PROBE_DISAGREEMENT",
        expected_version=platform.python_version(),
        observed_version=platform.python_version(),
        argv=[sys.executable, "-c", "packaging.version.Version membership"],
        fixture_digest=canonical_digest(binding),
        target_digest=canonical_digest(binding),
        facts=facts,
        inner={
            "positive": {
                "status": "PASS" if positive_ok else "BLOCKED",
                "outcome": positive_outcome,
            },
            "negative": {
                "status": "PASS" if negative_ok else "BLOCKED",
                "outcome": negative_outcome,
            },
        },
        fixture_binding=binding,
        fixture_execution={"positive": positive_outcome, "negative": negative_outcome},
    )


def install_upgrade_probe(
    fixture: str | Path,
    *,
    cell_id: str = "SKILL:FUNCTIONAL_FAULT:LIFECYCLE",
) -> dict[str, Any]:
    root = Path(fixture).resolve()
    if not root.is_dir():
        return _receipt(
            cell_id=cell_id,
            logical_tool_id="pip-lifecycle-fixture",
            mechanism_id="L01",
            status="BLOCKED_ADAPTER",
            failure_code="LIFECYCLE_FIXTURE_UNAVAILABLE",
            expected_version=f"{platform.python_version()} / pip",
            observed_version=platform.python_version(),
            argv=[],
            fixture_digest=None,
            target_digest=None,
        )
    wheels = sorted(root.glob("*.whl"))
    before = _tree_digest(root)
    if len(wheels) < 2:
        return _receipt(
            cell_id=cell_id,
            logical_tool_id="pip-lifecycle-fixture",
            mechanism_id="L01",
            status="BLOCKED_ADAPTER",
            failure_code="LIFECYCLE_FIXTURE_UNAVAILABLE",
            expected_version=f"{platform.python_version()} / pip",
            observed_version=platform.python_version(),
            argv=[],
            fixture_digest=before,
            target_digest=None,
        )
    with tempfile.TemporaryDirectory(prefix="fir-lifecycle-install-") as directory:
        target = Path(directory) / "installed"
        commands = [
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--disable-pip-version-check",
                "--target",
                str(target),
                str(wheels[0]),
            ],
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--upgrade",
                "--force-reinstall",
                "--disable-pip-version-check",
                "--target",
                str(target),
                str(wheels[1]),
            ],
        ]
        steps: list[dict[str, Any]] = []
        for command in commands:
            observed = run_sandboxed(
                command,
                cwd=target.parent,
                limits=SandboxLimits(
                    timeout_seconds=120,
                    max_output_bytes=2 * 1024 * 1024,
                    max_rss_mib=1024,
                    max_input_files=32,
                ),
                network_policy="ALLOW",
                input_file_count=len(wheels),
            )
            steps.append(observed.receipt())
            if observed.status != "PASS":
                after = _tree_digest(root)
                return _receipt(
                    cell_id=cell_id,
                    logical_tool_id="pip-lifecycle-fixture",
                    mechanism_id="L01",
                    status="BLOCKED_ADAPTER",
                    failure_code=observed.failure_code or "INSTALL_UPGRADE_FAILED",
                    expected_version=f"{platform.python_version()} / pip",
                    observed_version=platform.python_version(),
                    argv=command,
                    fixture_digest=before,
                    target_digest=after,
                    inner={
                        "steps": steps,
                        "target_unchanged": before == after,
                    },
                )
        installed = {
            path.relative_to(target).as_posix()
            for path in target.rglob("*")
            if path.is_file()
        }
        after = _tree_digest(root)
        passed = bool(installed) and before == after
        failure_code = (
            None
            if passed
            else "LIFECYCLE_TARGET_MUTATED"
            if before != after
            else "UPGRADE_READBACK_EMPTY"
        )
        return _receipt(
            cell_id=cell_id,
            logical_tool_id="pip-lifecycle-fixture",
            mechanism_id="L01",
            status="PASS" if passed else "BLOCKED_ADAPTER",
            failure_code=failure_code,
            expected_version=f"{platform.python_version()} / pip",
            observed_version=platform.python_version(),
            argv=commands[-1],
            fixture_digest=before,
            target_digest=after,
            facts=(
                [
                    {
                        "cell_id": cell_id,
                        "predicate_id": "install-upgrade-readback",
                        "normalized_locator": ".",
                        "logical_unit_id": "L01",
                        "normalized_value_digest": canonical_digest(
                            sorted(installed)
                        ),
                    }
                ]
                if passed
                else []
            ),
            inner={
                "steps": steps,
                "installed_files": sorted(installed),
                "target_unchanged": before == after,
                "disposable_scratch": str(target.parent),
            },
        )


def process_tree_probe(
    fixture: str | Path,
    *,
    cell_id: str = "SKILL:RISK_EXPOSURE:LIFECYCLE",
) -> dict[str, Any]:
    root = Path(fixture).resolve()
    if not root.is_dir():
        return _receipt(
            cell_id=cell_id,
            logical_tool_id="process-tree-probe",
            mechanism_id="L04",
            status="BLOCKED_ADAPTER",
            failure_code="LIFECYCLE_FIXTURE_UNAVAILABLE",
            expected_version=platform.python_version(),
            observed_version=platform.python_version(),
            argv=[],
            fixture_digest=None,
            target_digest=None,
        )
    before = _tree_digest(root)
    with tempfile.TemporaryDirectory(prefix="fir-lifecycle-process-") as directory:
        scratch = Path(directory)
        pid_file = scratch / "child.pid"
        code = (
            "import subprocess,sys,time\n"
            "from pathlib import Path\n"
            "p=subprocess.Popen([sys.executable,'-B','-c',"
            "'import time; time.sleep(30)'])\n"
            f"Path({str(pid_file)!r}).write_text(str(p.pid),encoding='utf-8')\n"
            "time.sleep(0.2)\n"
        )
        observed = run_sandboxed(
            [sys.executable, "-B", "-I", "-c", code],
            cwd=scratch,
            limits=SandboxLimits(
                timeout_seconds=10,
                max_output_bytes=65536,
                max_rss_mib=256,
                max_input_files=16,
            ),
            network_policy="ALLOW",
            input_file_count=0,
        )
        child_pid = (
            int(pid_file.read_text(encoding="utf-8"))
            if pid_file.is_file()
            else None
        )
        after = _tree_digest(root)
        passed = (
            observed.status == "PASS"
            and observed.descendants_empty
            and child_pid is not None
            and before == after
        )
        facts = []
        if child_pid is not None:
            facts.append(
                {
                    "cell_id": cell_id,
                    "predicate_id": "process-tree-cleanup",
                    "normalized_locator": ".",
                    "logical_unit_id": observed.backend_id,
                    "normalized_value_digest": canonical_digest(
                        {
                            "child_pid_observed": child_pid,
                            "descendants_empty": observed.descendants_empty,
                            "target_unchanged": before == after,
                        }
                    ),
                }
            )
        return _receipt(
            cell_id=cell_id,
            logical_tool_id=observed.backend_id,
            mechanism_id="L04",
            status="PASS" if passed else "BLOCKED_ADAPTER",
            failure_code=(
                None
                if passed
                else "LIFECYCLE_TARGET_MUTATED"
                if before != after
                else "PROCESS_TREE_PROBE_FAILED"
            ),
            expected_version=platform.python_version(),
            observed_version=platform.python_version(),
            argv=[sys.executable, "-B", "-I", "-c", code],
            fixture_digest=before,
            target_digest=after,
            facts=facts,
            inner={
                **observed.receipt(),
                "target_unchanged": before == after,
                "disposable_scratch": str(scratch),
            },
        )


def dependency_probe(
    fixture: str | Path,
    *,
    cell_id: str = "SKILL:VULNERABILITY:LIFECYCLE",
) -> dict[str, Any]:
    root = Path(fixture).resolve()
    case_path = root / "advisory-case.json"
    if not case_path.is_file():
        return _receipt(
            cell_id=cell_id,
            logical_tool_id="dependency-advisory-probe",
            mechanism_id="L05",
            status="BLOCKED_ADAPTER",
            failure_code="DEPENDENCY_EVIDENCE_UNAVAILABLE",
            expected_version=platform.python_version(),
            observed_version=platform.python_version(),
            argv=[],
            fixture_digest=None,
            target_digest=None,
        )
    case = json.loads(case_path.read_text(encoding="utf-8"))
    try:
        from packaging.version import Version

        version = Version(str(case["version"]))
        fixed = case.get("fixed")
        vulnerable = case.get("vulnerable")
        actual = (
            (vulnerable is None or version >= Version(str(vulnerable)))
            and (fixed is None or version < Version(str(fixed)))
        )
        expected = bool(case.get("expected_vulnerable"))
        passed = actual == expected
    except (ImportError, KeyError, ValueError) as error:
        return _receipt(
            cell_id=cell_id,
            logical_tool_id="dependency-advisory-probe",
            mechanism_id="L05",
            status="BLOCKED_ADAPTER",
            failure_code="DEPENDENCY_PROBE_UNAVAILABLE",
            expected_version=platform.python_version(),
            observed_version=platform.python_version(),
            argv=[sys.executable, "-c", "from packaging.version import Version"],
            fixture_digest=_sha256(case_path),
            target_digest=None,
            inner={"error": f"{type(error).__name__}: {error}"},
        )
    facts = [
        {
            "cell_id": cell_id,
            "predicate_id": "dependency-version-membership",
            "normalized_locator": case.get("package", "unknown"),
            "logical_unit_id": "L05",
            "normalized_value_digest": canonical_digest(
                {
                    "package": case.get("package"),
                    "version": case.get("version"),
                    "vulnerable": actual,
                }
            ),
        }
    ]
    return _receipt(
        cell_id=cell_id,
        logical_tool_id="dependency-advisory-probe",
        mechanism_id="L05",
        status="PASS" if passed else "BLOCKED_ADAPTER",
        failure_code=None if passed else "DEPENDENCY_PROBE_DISAGREEMENT",
        expected_version=platform.python_version(),
        observed_version=platform.python_version(),
        argv=[sys.executable, "-c", "packaging.version.Version membership"],
        fixture_digest=_sha256(case_path),
        target_digest=canonical_digest(case),
        facts=facts,
        inner={"observed_vulnerable": actual, "expected_vulnerable": expected},
    )


def run_for_snapshot(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    target_root = snapshot.get("target_root")
    if isinstance(target_root, (str, Path)) and Path(target_root).is_dir():
        if cell_id == "SKILL:INCONSISTENCY:LIFECYCLE":
            from .external_adapters import run_for_snapshot as run_external_target

            return run_external_target(cell_id, snapshot)
        return _receipt(
            cell_id=cell_id,
            logical_tool_id="lifecycle",
            mechanism_id="target-lifecycle",
            status="BLOCKED_ADAPTER",
            failure_code="TARGET_LIFECYCLE_EXECUTION_UNQUALIFIED",
            expected_version=platform.python_version(),
            observed_version=platform.python_version(),
            argv=[],
            fixture_digest=None,
            target_digest=str(snapshot.get("subject_digest") or ""),
        )
    if cell_id == "SKILL:INCONSISTENCY:LIFECYCLE":
        scratch_root = snapshot.get("fixture_scratch_root")
        supplied_identity = snapshot.get("fixture_identity")
        return run_external_cell(
            cell_id,
            scratch_root if isinstance(scratch_root, str) else None,
            fixture_identity=(
                supplied_identity
                if isinstance(supplied_identity, dict)
                else None
            ),
        )
    if cell_id == "SKILL:FUNCTIONAL_FAULT:LIFECYCLE":
        return run_frozen_install_pair(cell_id)
    if cell_id == "SKILL:RISK_EXPOSURE:LIFECYCLE":
        return run_frozen_process_pair(cell_id)
    if cell_id == "SKILL:VULNERABILITY:LIFECYCLE":
        return run_frozen_dependency_pair(cell_id)
    return _receipt(
        cell_id=cell_id,
        logical_tool_id="lifecycle",
        mechanism_id="unregistered",
        status="BLOCKED_ADAPTER",
        failure_code="LIFECYCLE_ADAPTER_NOT_REGISTERED",
        expected_version=platform.python_version(),
        observed_version=platform.python_version(),
        argv=[],
        fixture_digest=None,
        target_digest=None,
    )
