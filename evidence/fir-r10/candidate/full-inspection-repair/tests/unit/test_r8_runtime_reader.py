from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import protected_reader
from full_inspection_repair.protected_reader import (
    MAX_FILE_BYTES,
    ProtectedObjectError,
    snapshot_tree,
)


def _assert_structured_snapshot_failure(path: Path) -> None:
    script = (
        "import sys\n"
        f"from pathlib import Path\n"
        f"sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
        "from full_inspection_repair.protected_reader import "
        "ProtectedObjectError, snapshot_tree\n"
        "try:\n"
        f"    snapshot_tree(Path({str(path)!r}))\n"
        "except ProtectedObjectError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(3)\n"
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", script],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX special files")
def test_fifo_is_rejected_without_blocking(tmp_path) -> None:
    root = Path(tempfile.mkdtemp(prefix="fir-r8-fifo-"))
    try:
        os.mkfifo(root / "pipe")
        _assert_structured_snapshot_failure(root)
    finally:
        shutil.rmtree(root)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlink_root_is_rejected_before_dereference(tmp_path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    _assert_structured_snapshot_failure(link)


def test_reader_os_error_is_structured(monkeypatch, tmp_path) -> None:
    walker = "_walk_windows" if os.name == "nt" else "_walk_posix"

    def fail(_root):
        raise PermissionError("denied")

    monkeypatch.setattr(protected_reader, walker, fail)
    with pytest.raises(ProtectedObjectError, match="protected read failed"):
        snapshot_tree(tmp_path)


def test_read_interruption_is_retried(tmp_path, monkeypatch) -> None:
    path = tmp_path / "data.bin"
    path.write_bytes(b"payload")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    original = protected_reader.os.read
    calls = {"count": 0}

    def interrupted_read(handle, size):
        if calls["count"] == 0:
            calls["count"] += 1
            raise InterruptedError
        return original(handle, size)

    monkeypatch.setattr(protected_reader.os, "read", interrupted_read)
    try:
        assert protected_reader._read_all(fd, 7) == b"payload"
    finally:
        os.close(fd)
    assert calls["count"] == 1


def test_oversized_file_is_rejected_before_read(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "large.bin").write_bytes(b"x" * (MAX_FILE_BYTES + 1))

    def forbidden(_fd, _size):
        raise AssertionError("oversized file reached the reader")

    monkeypatch.setattr(protected_reader, "_read_all", forbidden)
    with pytest.raises(ProtectedObjectError, match="size policy"):
        snapshot_tree(root)
