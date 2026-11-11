from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import math
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

if os.name == "nt":
    import msvcrt
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_READ_ATTRIBUTES = 0x80
    _SYNCHRONIZE = 0x100000
    _FILE_SHARE_READ = 0x1
    _FILE_SHARE_WRITE = 0x2
    _FILE_SHARE_DELETE = 0x4
    _FILE_DIRECTORY_FILE = 0x1
    _FILE_NON_DIRECTORY_FILE = 0x40
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x20
    _FILE_OPEN_REPARSE_POINT = 0x00200000
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_OPEN = 1
    _FILE_CREATE = 2
    _FILE_OPEN_IF = 3
    _OBJ_CASE_INSENSITIVE = 0x40
    _FILE_ATTRIBUTE_DIRECTORY = 0x10
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    _STATUS_OBJECT_NAME_COLLISION = 0xC0000035
    _STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    _STATUS_NOT_A_DIRECTORY = 0xC0000103
    _STATUS_ACCESS_DENIED = 0xC0000022
    _STATUS_REPARSE_POINT_ENCOUNTERED = 0xC000050B

    class _UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class _OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class _IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [
            ("Status", ctypes.c_ssize_t),
            ("Information", ctypes.c_size_t),
        ]

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _kernel32.FlushFileBuffers.restype = wintypes.BOOL
    _kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _ntdll.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_OBJECT_ATTRIBUTES),
        ctypes.POINTER(_IO_STATUS_BLOCK),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    ]
    _ntdll.NtCreateFile.restype = ctypes.c_ssize_t


class StrictJSONError(ValueError):
    """Raised when input cannot be interpreted unambiguously."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise StrictJSONError(f"non-finite JSON constant: {value}")


def _depth(value: Any, current: int = 0, limit: int = 128) -> None:
    if current > limit:
        raise StrictJSONError("JSON nesting exceeds policy")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, current + 1, limit)
    elif isinstance(value, list):
        for item in value:
            _depth(item, current + 1, limit)


DEFAULT_JSONL_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_JSONL_MAX_RECORD_BYTES = 8 * 1024 * 1024
DEFAULT_JSONL_MAX_RECORDS = 100_000


def _absolute_no_resolve(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _assert_no_alternate_data_stream(path: Path) -> None:
    if os.name != "nt":
        return
    absolute = _absolute_no_resolve(path)
    anchor = Path(absolute.anchor)
    for part in absolute.relative_to(anchor).parts:
        if ":" in part:
            raise OSError(errno.EINVAL, "alternate data stream path forbidden")


def _windows_status_error(status: int, message: str) -> OSError:
    mapping = {
        _STATUS_OBJECT_NAME_COLLISION: errno.EEXIST,
        _STATUS_OBJECT_NAME_NOT_FOUND: errno.ENOENT,
        _STATUS_NOT_A_DIRECTORY: errno.ENOTDIR,
        _STATUS_ACCESS_DENIED: errno.EACCES,
        _STATUS_REPARSE_POINT_ENCOUNTERED: errno.ELOOP,
    }
    return OSError(mapping.get(status, errno.EIO), f"{message}: ntstatus={status:#x}")


def _windows_info(handle: int, info_class: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    if not _kernel32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle), info_class, buffer, size
    ):
        error = ctypes.get_last_error()
        raise OSError(error, f"GetFileInformationByHandleEx failed: winerror={error}")
    return buffer.raw


def _windows_assert_not_reparse(handle: int, label: str) -> None:
    data = _windows_info(handle, 9, 8)
    attributes = int.from_bytes(data[0:4], "little")
    reparse_tag = int.from_bytes(data[4:8], "little")
    if attributes & _FILE_ATTRIBUTE_REPARSE_POINT or reparse_tag:
        raise OSError(errno.ELOOP, f"link or reparse point forbidden: {label}")


def _windows_is_directory(handle: int) -> bool:
    data = _windows_info(handle, 1, 24)
    return bool(data[21])


def _windows_close(handle: int) -> None:
    if handle and handle != _INVALID_HANDLE_VALUE:
        _kernel32.CloseHandle(wintypes.HANDLE(handle))


def _windows_open_relative(
    parent: int,
    name: str,
    *,
    directory: bool,
    disposition: int,
    desired_access: int,
    share_access: int,
) -> int:
    buffer = ctypes.create_unicode_buffer(name)
    unicode_name = _UNICODE_STRING(
        Length=len(name.encode("utf-16-le")),
        MaximumLength=(len(name) + 1) * 2,
        Buffer=ctypes.cast(buffer, wintypes.LPWSTR),
    )
    attributes = _OBJECT_ATTRIBUTES(
        Length=ctypes.sizeof(_OBJECT_ATTRIBUTES),
        RootDirectory=wintypes.HANDLE(parent),
        ObjectName=ctypes.pointer(unicode_name),
        Attributes=_OBJ_CASE_INSENSITIVE,
        SecurityDescriptor=None,
        SecurityQualityOfService=None,
    )
    status_block = _IO_STATUS_BLOCK()
    handle = wintypes.HANDLE()
    options = (
        _FILE_OPEN_REPARSE_POINT
        | _FILE_SYNCHRONOUS_IO_NONALERT
        | (_FILE_DIRECTORY_FILE if directory else _FILE_NON_DIRECTORY_FILE)
    )
    status = _ntdll.NtCreateFile(
        ctypes.byref(handle),
        desired_access,
        ctypes.byref(attributes),
        ctypes.byref(status_block),
        None,
        0,
        share_access,
        disposition,
        options,
        None,
        0,
    )
    status_value = status & 0xFFFFFFFF
    if status_value >= 0x80000000:
        raise _windows_status_error(status_value, f"cannot open relative object {name}")
    return int(handle.value)


def _windows_open_directory_handle(path: Path, *, write_access: bool = False) -> int:
    absolute = _absolute_no_resolve(path)
    _assert_no_alternate_data_stream(absolute)
    anchor = Path(absolute.anchor)
    handle = _kernel32.CreateFileW(
        str(anchor),
        (_GENERIC_READ | (_GENERIC_WRITE if write_access else 0))
        | _FILE_READ_ATTRIBUTES
        | _SYNCHRONIZE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        3,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise OSError(error, f"cannot open volume root {anchor}: winerror={error}")
    handle = int(handle)
    try:
        _windows_assert_not_reparse(handle, str(anchor))
        if not _windows_is_directory(handle):
            raise OSError(errno.ENOTDIR, f"not a directory: {anchor}")
        for name in absolute.relative_to(anchor).parts:
            child = _windows_open_relative(
                handle,
                name,
                directory=True,
                disposition=_FILE_OPEN,
                desired_access=(
                    (_GENERIC_READ | (_GENERIC_WRITE if write_access else 0))
                    | _FILE_READ_ATTRIBUTES
                    | _SYNCHRONIZE
                ),
                share_access=(
                    _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
                ),
            )
            _windows_close(handle)
            handle = child
            _windows_assert_not_reparse(handle, name)
            if not _windows_is_directory(handle):
                raise OSError(errno.ENOTDIR, f"not a directory: {name}")
        return handle
    except Exception:
        _windows_close(handle)
        raise


def _flush_windows_directory(path: Path) -> None:
    handle = _windows_open_directory_handle(path, write_access=True)
    try:
        if not _kernel32.FlushFileBuffers(wintypes.HANDLE(handle)):
            error = ctypes.get_last_error()
            raise OSError(error, f"directory FlushFileBuffers failed: winerror={error}")
    finally:
        _windows_close(handle)


def _open_windows_no_follow(
    path: Path,
    flags: int,
    mode: int,
    *,
    create_parents: bool,
) -> int:
    absolute = _absolute_no_resolve(path)
    _assert_no_alternate_data_stream(absolute)
    anchor = Path(absolute.anchor)
    root = _kernel32.CreateFileW(
        str(anchor),
        _GENERIC_READ | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        3,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_OPEN_REPARSE_POINT,
        None,
    )
    if root == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise OSError(error, f"cannot open volume root {anchor}: winerror={error}")
    handle = int(root)
    fd_handle: int | None = None
    try:
        _windows_assert_not_reparse(handle, str(anchor))
        parts = absolute.relative_to(anchor).parts
        if not parts:
            raise OSError(errno.EISDIR, f"path is a directory: {absolute}")
        for name in parts[:-1]:
            try:
                child = _windows_open_relative(
                    handle,
                    name,
                    directory=True,
                    disposition=_FILE_OPEN,
                    desired_access=(
                        _GENERIC_READ | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
                    ),
                    share_access=(
                        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
                    ),
                )
            except OSError as exc:
                if exc.errno != errno.ENOENT or not create_parents:
                    raise
                child = _windows_open_relative(
                    handle,
                    name,
                    directory=True,
                    disposition=_FILE_CREATE,
                    desired_access=(
                        _GENERIC_READ | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
                    ),
                    share_access=(
                        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
                    ),
                )
            _windows_close(handle)
            handle = child
            _windows_assert_not_reparse(handle, name)
            if not _windows_is_directory(handle):
                raise OSError(errno.ENOTDIR, f"not a directory: {name}")

        if flags & os.O_CREAT:
            disposition = _FILE_CREATE if flags & os.O_EXCL else _FILE_OPEN_IF
        else:
            disposition = _FILE_OPEN
        if flags & os.O_RDWR:
            access = _GENERIC_READ | _GENERIC_WRITE
            fd_flags = os.O_RDWR
        elif flags & os.O_WRONLY:
            access = _GENERIC_WRITE
            fd_flags = os.O_WRONLY
        else:
            access = _GENERIC_READ
            fd_flags = os.O_RDONLY
        fd_handle = _windows_open_relative(
            handle,
            parts[-1],
            directory=False,
            disposition=disposition,
            desired_access=access | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            share_access=(_FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE),
        )
        _windows_assert_not_reparse(fd_handle, parts[-1])
        if _windows_is_directory(fd_handle):
            raise OSError(errno.EISDIR, f"path is a directory: {absolute}")
    except Exception:
        if fd_handle is not None:
            _windows_close(fd_handle)
        _windows_close(handle)
        raise
    finally:
        _windows_close(handle)
    fd_flags |= getattr(os, "O_BINARY", 0)
    if flags & os.O_APPEND:
        fd_flags |= os.O_APPEND
    try:
        return msvcrt.open_osfhandle(fd_handle, fd_flags)
    except Exception:
        _windows_close(fd_handle)
        raise


def open_no_follow(
    path: str | Path,
    flags: int,
    mode: int = 0o600,
    *,
    create_parents: bool = False,
) -> int:
    """Open a file without following links or reparse points in any component."""

    absolute = _absolute_no_resolve(path)
    _assert_no_alternate_data_stream(absolute)
    if os.name == "nt":
        return _open_windows_no_follow(
            absolute,
            flags,
            mode,
            create_parents=create_parents,
        )

    anchor = Path(absolute.anchor or "/")
    parent_fd = os.open(
        anchor,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        parts = absolute.relative_to(anchor).parts
        if not parts:
            raise OSError(errno.EISDIR, f"path is a directory: {absolute}")
        for name in parts[:-1]:
            try:
                child_fd = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                if not create_parents:
                    raise
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
                child_fd = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    try:
                        info = os.stat(
                            name,
                            dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        raise exc
                    if stat.S_ISLNK(info.st_mode):
                        raise OSError(
                            errno.ELOOP,
                            f"link or reparse point forbidden: {name}",
                        ) from exc
                raise
            os.close(parent_fd)
            parent_fd = child_fd
        return os.open(
            parts[-1],
            flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            mode,
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)


def assert_no_link_chain(path: str | Path, *, allow_missing: bool = True) -> Path:
    """Return a lexical absolute path after rejecting linked existing components."""

    absolute = _absolute_no_resolve(path)
    _assert_no_alternate_data_stream(absolute)
    anchor = Path(absolute.anchor)
    current = anchor
    parts = absolute.relative_to(anchor).parts
    for index, name in enumerate(parts):
        current = current / name
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if allow_missing:
                return absolute
            raise
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise OSError(errno.ELOOP, f"link or reparse point forbidden: {current}")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise OSError(errno.ENOTDIR, f"not a directory: {current}")
    return absolute


def strict_loads(data: bytes | str, *, max_bytes: int = 64 * 1024 * 1024) -> Any:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > max_bytes:
        raise StrictJSONError("JSON exceeds size policy")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise StrictJSONError("UTF-8 BOM is not permitted")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise StrictJSONError("invalid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except StrictJSONError:
        raise
    except json.JSONDecodeError as exc:
        raise StrictJSONError(f"invalid JSON: {exc}") from exc
    _depth(value)
    return value


def read_json(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> Any:
    fd = open_no_follow(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        return read_json_fd(fd, max_bytes=max_bytes)
    finally:
        os.close(fd)


def read_json_fd(fd: int, *, max_bytes: int = 64 * 1024 * 1024) -> Any:
    size = os.fstat(fd).st_size
    if size > max_bytes:
        raise StrictJSONError("JSON exceeds size policy")
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), "rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes or size != len(data):
        raise StrictJSONError("JSON exceeds size policy or changed during read")
    return strict_loads(data, max_bytes=max_bytes)


def read_jsonl(
    path: Path,
    *,
    max_line_bytes: int = DEFAULT_JSONL_MAX_RECORD_BYTES,
    max_bytes: int = DEFAULT_JSONL_MAX_BYTES,
    max_records: int = DEFAULT_JSONL_MAX_RECORDS,
) -> list[Any]:
    fd = open_no_follow(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        return read_jsonl_fd(
            fd,
            max_line_bytes=max_line_bytes,
            max_bytes=max_bytes,
            max_records=max_records,
        )
    finally:
        os.close(fd)


def read_jsonl_fd(
    fd: int,
    *,
    max_line_bytes: int = DEFAULT_JSONL_MAX_RECORD_BYTES,
    max_bytes: int = DEFAULT_JSONL_MAX_BYTES,
    max_records: int = DEFAULT_JSONL_MAX_RECORDS,
    reject_blank: bool = False,
    require_final_newline: bool = False,
) -> list[Any]:
    size = os.fstat(fd).st_size
    if size > max_bytes:
        raise StrictJSONError("JSONL exceeds size policy")
    os.lseek(fd, 0, os.SEEK_SET)
    result: list[Any] = []
    total = 0
    number = 0
    last_had_newline = True
    with os.fdopen(os.dup(fd), "rb") as handle:
        while True:
            limit = min(max_line_bytes, max_bytes - total) + 1
            line = handle.readline(limit)
            if not line:
                break
            number += 1
            total += len(line)
            if number > max_records:
                raise StrictJSONError("JSONL record count exceeds policy")
            if total > max_bytes:
                raise StrictJSONError("JSONL exceeds size policy")
            last_had_newline = line.endswith(b"\n")
            line = line.rstrip(b"\r\n")
            if not line.strip() and not reject_blank:
                continue
            if len(line) > max_line_bytes:
                raise StrictJSONError(f"JSONL line exceeds size policy: {number}")
            result.append(strict_loads(line))
    if size and require_final_newline and not last_had_newline:
        raise StrictJSONError("JSONL is truncated")
    if total != size:
        raise StrictJSONError("JSONL size changed during read")
    return result


def canonical_bytes(value: Any) -> bytes:
    for item in _walk(value):
        if isinstance(item, float) and not math.isfinite(item):
            raise StrictJSONError("non-finite number")
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _walk(value: Any):
    yield value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk(key)
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("write returned without progress")
        view = view[written:]


def fsync_fd(fd: int) -> None:
    while True:
        try:
            os.fsync(fd)
            return
        except InterruptedError:
            continue


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        _flush_windows_directory(path)
        return
    fd = open_no_follow(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        fsync_fd(fd)
    finally:
        os.close(fd)


def typed_digest(value: Any, object_type: str, schema_version: str) -> str:
    if not object_type or not schema_version:
        raise StrictJSONError("typed digest identity is required")
    prefix = (
        "full-inspection-repair\0" + object_type + "\0" + schema_version + "\0"
    ).encode("utf-8")
    return sha256_bytes(prefix + canonical_bytes(value))


def digest_without(
    value: dict[str, Any],
    field: str,
    object_type: str,
    schema_version: str,
) -> str:
    return typed_digest(
        {key: item for key, item in value.items() if key != field},
        object_type,
        schema_version,
    )


def _durable_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        try:
            write_all(fd, data)
            fsync_fd(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path: Path, value: Any) -> None:
    _durable_write_bytes(path, canonical_bytes(value) + b"\n")
