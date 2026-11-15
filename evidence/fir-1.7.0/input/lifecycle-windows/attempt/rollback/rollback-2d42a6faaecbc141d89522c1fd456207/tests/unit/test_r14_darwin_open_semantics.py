from __future__ import annotations

import errno
import os
import sys
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import strict as strict_module

SECURITY_FLAGS = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _simulate_posix(
    monkeypatch: pytest.MonkeyPatch, platform: str = "darwin"
) -> None:
    monkeypatch.setattr(strict_module.os, "name", "posix")
    if not hasattr(strict_module, "sys"):
        monkeypatch.setattr(strict_module, "sys", sys, raising=False)
    monkeypatch.setattr(strict_module.sys, "platform", platform)
    monkeypatch.setattr(
        strict_module,
        "_absolute_no_resolve",
        lambda path: PurePosixPath(str(path)),
    )


def _fake_final_opens(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[object],
) -> list[dict[str, object]]:
    next_fd = iter(range(100, 1000))
    final_calls: list[dict[str, object]] = []

    def fake_open(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is None or path != "target":
            return next(next_fd)
        call = {
            "path": path,
            "flags": flags,
            "mode": mode,
            "dir_fd": dir_fd,
        }
        final_calls.append(call)
        response = responses.pop(0)
        if callable(response):
            response = response(flags, mode, dir_fd)
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr(strict_module.os, "open", fake_open)
    monkeypatch.setattr(strict_module.os, "close", lambda _fd: None)
    return final_calls


def _assert_supplied_parent(final_calls: list[dict[str, object]]) -> None:
    parent_fds = {call["dir_fd"] for call in final_calls}
    assert len(parent_calls := parent_fds) == 1
    assert next(iter(parent_calls)) is not None


def test_darwin_existing_file_uses_one_non_creating_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_posix(monkeypatch)
    flags = os.O_RDWR | os.O_CREAT
    calls = _fake_final_opens(monkeypatch, [501])

    assert strict_module.open_no_follow("/fixture/parent/target", flags) == 501

    assert len(calls) == 1
    assert calls[0]["flags"] == (
        flags & ~(os.O_CREAT | os.O_EXCL)
    ) | SECURITY_FLAGS
    _assert_supplied_parent(calls)


def test_darwin_missing_file_then_creates_exclusively(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_posix(monkeypatch)
    flags = os.O_RDWR | os.O_CREAT
    missing = FileNotFoundError(errno.ENOENT, "missing")
    calls = _fake_final_opens(monkeypatch, [missing, 502])

    assert strict_module.open_no_follow("/fixture/parent/target", flags) == 502

    assert [call["flags"] for call in calls] == [
        (flags & ~(os.O_CREAT | os.O_EXCL)) | SECURITY_FLAGS,
        flags | os.O_EXCL | SECURITY_FLAGS,
    ]
    _assert_supplied_parent(calls)


def test_darwin_concurrent_creation_retries_non_creating_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_posix(monkeypatch)
    flags = os.O_WRONLY | os.O_CREAT
    responses = [
        FileNotFoundError(errno.ENOENT, "missing"),
        FileExistsError(errno.EEXIST, "created concurrently"),
        503,
    ]
    calls = _fake_final_opens(monkeypatch, responses)

    assert strict_module.open_no_follow("/fixture/parent/target", flags) == 503

    assert len(calls) == 3
    assert calls[1]["flags"] & (os.O_CREAT | os.O_EXCL) == (
        os.O_CREAT | os.O_EXCL
    )
    assert calls[2]["flags"] & (os.O_CREAT | os.O_EXCL) == 0
    _assert_supplied_parent(calls)


def test_darwin_never_issues_old_create_without_exclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_posix(monkeypatch)
    flags = os.O_RDWR | os.O_CREAT

    def old_failure(trial_flags, _mode, _dir_fd):
        if trial_flags & os.O_CREAT and not trial_flags & os.O_EXCL:
            raise OSError(errno.EINVAL, "old Darwin create form")
        if trial_flags & os.O_EXCL:
            return 504
        raise FileNotFoundError(errno.ENOENT, "missing")

    calls = _fake_final_opens(monkeypatch, [old_failure, old_failure])

    assert strict_module.open_no_follow("/fixture/parent/target", flags) == 504

    assert len(calls) == 2
    _assert_supplied_parent(calls)


def test_darwin_final_symlink_stays_eloop_and_victim_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _simulate_posix(monkeypatch)
    victim = tmp_path / "victim"
    victim.write_bytes(b"unchanged")
    calls = _fake_final_opens(
        monkeypatch,
        [OSError(errno.ELOOP, "symbolic link")],
    )

    with pytest.raises(OSError) as caught:
        strict_module.open_no_follow(
            "/fixture/parent/target",
            os.O_WRONLY | os.O_CREAT,
        )

    assert caught.value.errno == errno.ELOOP
    assert len(calls) == 1
    assert victim.read_bytes() == b"unchanged"
    _assert_supplied_parent(calls)


def test_darwin_caller_requested_exclusive_remains_direct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_posix(monkeypatch)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    calls = _fake_final_opens(
        monkeypatch,
        [FileExistsError(errno.EEXIST, "already exists")],
    )

    with pytest.raises(FileExistsError):
        strict_module.open_no_follow("/fixture/parent/target", flags)

    assert len(calls) == 1
    assert calls[0]["flags"] == flags | SECURITY_FLAGS
    _assert_supplied_parent(calls)


def test_non_darwin_create_remains_one_unchanged_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_posix(monkeypatch, platform="linux")
    flags = os.O_RDWR | os.O_CREAT
    calls = _fake_final_opens(monkeypatch, [505])

    assert strict_module.open_no_follow("/fixture/parent/target", flags) == 505

    assert len(calls) == 1
    assert calls[0]["flags"] == flags | SECURITY_FLAGS
    _assert_supplied_parent(calls)


@pytest.mark.parametrize(
    "flags",
    [
        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
        os.O_RDWR | os.O_TRUNC | os.O_CREAT,
    ],
)
def test_darwin_preserves_flags_access_mode_and_permissions(
    monkeypatch: pytest.MonkeyPatch, flags: int
) -> None:
    _simulate_posix(monkeypatch)
    calls = _fake_final_opens(
        monkeypatch,
        [FileNotFoundError(errno.ENOENT, "missing"), 506],
    )

    assert (
        strict_module.open_no_follow(
            "/fixture/parent/target",
            flags,
            mode=0o640,
        )
        == 506
    )

    assert calls[0]["flags"] == (
        flags & ~(os.O_CREAT | os.O_EXCL)
    ) | SECURITY_FLAGS
    assert calls[1]["flags"] == flags | os.O_EXCL | SECURITY_FLAGS
    assert [call["mode"] for call in calls] == [0o640, 0o640]
    _assert_supplied_parent(calls)


@pytest.mark.parametrize("error_number", [errno.EACCES, errno.ELOOP, errno.ENOTDIR])
def test_darwin_create_errors_propagate_without_fallback(
    monkeypatch: pytest.MonkeyPatch, error_number: int
) -> None:
    _simulate_posix(monkeypatch)
    calls = _fake_final_opens(
        monkeypatch,
        [
            FileNotFoundError(errno.ENOENT, "missing"),
            OSError(error_number, "create failed"),
        ],
    )

    with pytest.raises(OSError) as caught:
        strict_module.open_no_follow(
            "/fixture/parent/target",
            os.O_WRONLY | os.O_CREAT,
        )

    assert caught.value.errno == error_number
    assert len(calls) == 2
    _assert_supplied_parent(calls)
