from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from r15_identity import (
    CANDIDATE_DIGEST,
    FIXTURE_SAN,
    MACOS_WORKFLOW,
    WRONG_FIXTURE_SAN,
)

ROOT = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def workflow_identity_errors(text: str) -> list[str]:
    errors: list[str] = []
    if FIXTURE_SAN not in text:
        errors.append("authorized R7 fixture SAN is missing")
    if WRONG_FIXTURE_SAN in text:
        errors.append("wrong R13 fixture SAN is present")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    candidate = args.candidate.resolve()
    output = args.output.resolve()
    if output.exists():
        raise RuntimeError(f"output already exists: {output}")

    sys.path.insert(0, str(candidate / "scripts"))
    from full_inspection_repair.package import build_package_manifest

    before = build_package_manifest(candidate)["tree_digest"]
    workflow_path = ROOT / "github-r15" / MACOS_WORKFLOW
    if not workflow_path.is_file():
        workflow_path = Path.cwd() / MACOS_WORKFLOW
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow_errors = workflow_identity_errors(workflow_text)
    negative_control = workflow_identity_errors(
        workflow_text.replace(FIXTURE_SAN, WRONG_FIXTURE_SAN)
    )
    output.mkdir(parents=True)
    mutated = output / "candidate"
    shutil.copytree(
        candidate,
        mutated,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            ".mypy_cache",
        ),
    )

    strict_path = (
        mutated / "scripts" / "full_inspection_repair" / "strict.py"
    )
    source = strict_path.read_text(encoding="utf-8")
    start_marker = (
        "        if (\n"
        '            sys.platform == "darwin"\n'
    )
    end_marker = (
        "        return os.open(parts[-1], effective_flags, mode, "
        "dir_fd=parent_fd)\n"
    )
    try:
        start = source.index(start_marker)
        end = source.index(end_marker, start)
    except ValueError as exc:
        raise RuntimeError("Darwin branch mutation anchors were not found") from exc
    strict_path.write_text(
        source[:start] + end_marker + source[end + len(end_marker) :],
        encoding="utf-8",
    )

    command = [
        sys.executable,
        "-B",
        "-m",
        "pytest",
        "tests/unit/test_r14_darwin_open_semantics.py",
        "-q",
        "-rs",
        "-p",
        "no:cacheprovider",
    ]
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        command,
        cwd=mutated,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    (output / "mutation.stdout.txt").write_text(
        completed.stdout,
        encoding="utf-8",
    )
    (output / "mutation.stderr.txt").write_text(
        completed.stderr,
        encoding="utf-8",
    )

    after = build_package_manifest(candidate)["tree_digest"]
    expected = "test_darwin_never_issues_old_create_without_exclusive"
    observed = (
        completed.returncode != 0
        and expected in completed.stdout
        and "failed" in completed.stdout.casefold()
    )
    passed = (
        observed
        and before == after == CANDIDATE_DIGEST
        and not workflow_errors
        and bool(negative_control)
    )
    status = "PASS" if passed else "BLOCKED"
    result = {
        "schema_version": 1,
        "status": status,
        "candidate_digest": before,
        "candidate_digest_after": after,
        "mutated_strict_sha256": sha256(strict_path),
        "command": command,
        "expected_failure": expected,
        "exit_code": completed.returncode,
        "expected_failure_observed": observed,
        "fixture_san": FIXTURE_SAN,
        "workflow_errors": workflow_errors,
        "wrong_san_negative_control": negative_control,
    }
    write_json(output / "mutation-result.json", result)
    print(json.dumps(result, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)
