from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import full_inspection_repair.package as package_module
import full_inspection_repair.strict as strict_module
from full_inspection_repair.package import (
    InstallBlocked,
    build_package_manifest,
    install_package,
)


@pytest.mark.parametrize("failure", ("fsync", "replace"))
def test_durable_json_preserves_old_file_on_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    path = tmp_path / "evidence.json"
    path.write_bytes(b'{"old":true}\n')

    def fail(*_args, **_kwargs) -> None:
        raise OSError(f"injected {failure} failure")

    if failure == "fsync":
        monkeypatch.setattr(strict_module, "fsync_fd", fail)
    else:
        monkeypatch.setattr(strict_module.os, "replace", fail)
    with pytest.raises(OSError, match=f"injected {failure} failure"):
        strict_module.write_json(path, {"new": True})

    assert path.read_bytes() == b'{"old":true}\n'
    assert not list(tmp_path.glob(".evidence.json.*.tmp"))


def test_durable_json_syncs_file_before_replacing_and_syncs_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "evidence.json"
    events: list[object] = []
    real_write_all = strict_module.write_all
    real_replace = strict_module.os.replace

    monkeypatch.setattr(
        strict_module,
        "write_all",
        lambda fd, data: (
            events.append(("write", bytes(data))),
            real_write_all(fd, data),
        ),
    )
    monkeypatch.setattr(strict_module, "fsync_fd", lambda _fd: events.append("file"))
    monkeypatch.setattr(
        strict_module,
        "fsync_directory",
        lambda parent: events.append(("parent", parent)),
    )
    monkeypatch.setattr(
        strict_module.os,
        "replace",
        lambda source, destination: (
            events.append(("replace", Path(source), Path(destination))),
            real_replace(source, destination),
        ),
    )

    strict_module.write_json(path, {"new": True})

    assert [event[0] if isinstance(event, tuple) else event for event in events] == [
        "write",
        "file",
        "replace",
        "parent",
    ]
    assert events[-1] == ("parent", tmp_path)
    assert path.read_bytes() == b'{"new":true}\n'


def test_fsync_tree_syncs_files_before_directories_bottom_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged = tmp_path / "staged"
    nested = staged / "nested"
    nested.mkdir(parents=True)
    (staged / "root.txt").write_text("root", encoding="utf-8")
    (nested / "child.txt").write_text("child", encoding="utf-8")
    helper = getattr(package_module, "_fsync_tree", None)
    if helper is None:
        pytest.fail("durable staged-tree fsync helper is missing")

    events: list[tuple[str, Path]] = []
    fd_paths: dict[int, Path] = {}
    real_open = package_module.open_no_follow
    real_fsync = package_module.fsync_fd

    def open_no_follow(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        fd_paths[fd] = Path(path)
        return fd

    def fsync_file(fd):
        events.append(("file", fd_paths[fd]))
        real_fsync(fd)

    monkeypatch.setattr(package_module, "open_no_follow", open_no_follow)
    monkeypatch.setattr(package_module, "fsync_fd", fsync_file)
    monkeypatch.setattr(
        package_module,
        "fsync_directory",
        lambda path: events.append(("directory", Path(path))),
    )

    helper(staged)

    file_paths = {path for kind, path in events if kind == "file"}
    directory_paths = [path for kind, path in events if kind == "directory"]
    assert file_paths == {staged / "root.txt", nested / "child.txt"}
    assert directory_paths == [nested, staged]
    assert max(index for index, event in enumerate(events) if event[0] == "file") < min(
        index for index, event in enumerate(events) if event[0] == "directory"
    )


def test_durable_directory_replace_syncs_tree_and_both_parents_in_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source-parent" / "source"
    source.mkdir(parents=True)
    destination = tmp_path / "target-parent" / "target"
    destination.parent.mkdir()
    helper = getattr(package_module, "_durable_directory_replace", None)
    if helper is None:
        pytest.fail("durable directory replacement helper is missing")

    events: list[object] = []
    real_replace = package_module.os.replace
    monkeypatch.setattr(
        package_module,
        "_fsync_tree",
        lambda path: events.append(("tree", Path(path))),
    )
    monkeypatch.setattr(
        package_module,
        "fsync_directory",
        lambda path: events.append(("parent", Path(path))),
    )
    monkeypatch.setattr(
        package_module.os,
        "replace",
        lambda src, dst: (
            events.append(("replace", Path(src), Path(dst))),
            real_replace(src, dst),
        ),
    )

    helper(source, destination)

    assert events == [
        ("tree", source),
        ("parent", source.parent),
        ("parent", destination.parent),
        ("replace", source, destination),
        ("parent", source.parent),
        ("parent", destination.parent),
    ]
    assert destination.is_dir()


def test_durable_directory_replace_fails_closed_before_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "destination"
    helper = getattr(package_module, "_durable_directory_replace", None)
    if helper is None:
        pytest.fail("durable directory replacement helper is missing")

    replace_calls: list[tuple[object, object]] = []
    monkeypatch.setattr(package_module, "_fsync_tree", lambda _path: None)

    def fail_parent(_path: Path) -> None:
        raise OSError("injected parent fsync failure")

    monkeypatch.setattr(package_module, "fsync_directory", fail_parent)
    monkeypatch.setattr(
        package_module.os,
        "replace",
        lambda src, dst: replace_calls.append((src, dst)),
    )

    with pytest.raises(OSError, match="injected parent fsync failure"):
        helper(source, destination)

    assert replace_calls == []
    assert source.is_dir()
    assert not destination.exists()


def test_installation_uses_durable_replace_for_all_directory_transitions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# New\n", encoding="utf-8")
    target = tmp_path / "installed"
    target.mkdir()
    (target / "SKILL.md").write_text("# Old\n", encoding="utf-8")
    rollback = tmp_path / "rollback"
    helper = getattr(package_module, "_durable_directory_replace", None)
    if helper is None:
        pytest.fail("durable directory replacement helper is missing")

    calls: list[tuple[str, str]] = []

    def observe(source_path, destination_path) -> None:
        calls.append((Path(source_path).name, Path(destination_path).name))
        helper(source_path, destination_path)

    def fail_commit(_binding: dict[str, object]) -> None:
        raise OSError("injected commit failure")

    monkeypatch.setattr(package_module, "_durable_directory_replace", observe)
    monkeypatch.setattr(
        package_module,
        "validate_claim_for_install",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(InstallBlocked, match="old install was restored"):
        install_package(
            source,
            target,
            build_package_manifest(source),
            claim={"claim_digest": "a" * 64},
            review={"review_digest": "b" * 64},
            verification_method="sigstore-keyless",
            attestation_bytes=b"{}",
            rollback_root=rollback,
            commit_callback=fail_commit,
        )

    assert calls == [
        ("installed", "rollback"),
        ("installed", "installed"),
        ("installed", "failed-target"),
        ("rollback", "installed"),
    ]
