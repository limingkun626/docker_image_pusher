from __future__ import annotations

import ctypes
import errno
import os
import stat
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .strict import sha256_bytes, typed_digest

if os.name == "nt":
    import msvcrt
else:
    msvcrt = None


class ProtectedObjectError(RuntimeError):
    """Raised when an object cannot be read under the protected contract."""


MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    FILE_SHARE_READ = 0x1
    GENERIC_READ = 0x80000000
    FILE_READ_ATTRIBUTES = 0x80
    READ_CONTROL = 0x20000
    SYNCHRONIZE = 0x100000
    FILE_OPEN = 1
    FILE_DIRECTORY_FILE = 0x1
    FILE_NON_DIRECTORY_FILE = 0x40
    FILE_SYNCHRONOUS_IO_NONALERT = 0x20
    FILE_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    OPEN_EXISTING = 3
    OBJ_CASE_INSENSITIVE = 0x40
    FILE_ATTRIBUTE_NORMAL = 0x80
    FILE_ATTRIBUTE_DIRECTORY = 0x10
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    OWNER_SECURITY_INFORMATION = 0x1
    DACL_SECURITY_INFORMATION = 0x4
    SE_FILE_OBJECT = 1
    SDDL_REVISION_1 = 1
    FILE_BEGIN = 0
    ERROR_NO_MORE_FILES = 18
    ERROR_MORE_DATA = 234

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [
            ("Status", ctypes.c_ssize_t),
            ("Information", ctypes.c_size_t),
        ]

    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel32.SetFilePointerEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    ]
    kernel32.SetFilePointerEx.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    ntdll.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(OBJECT_ATTRIBUTES),
        ctypes.POINTER(IO_STATUS_BLOCK),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    ]
    ntdll.NtCreateFile.restype = ctypes.c_ssize_t
    ntdll.NtReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(IO_STATUS_BLOCK),
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.PULONG,
    ]
    ntdll.NtReadFile.restype = ctypes.c_ssize_t


def _raise_win(message: str) -> None:
    error = ctypes.get_last_error()
    raise ProtectedObjectError(f"{message}: winerror={error}")


def _open_root(path: Path) -> int:
    handle = kernel32.CreateFileW(
        str(path),
        GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        _raise_win(f"cannot open root {path}")
    return int(handle)


def _open_windows_root(path: Path) -> int:
    anchor = Path(path.anchor)
    handle = _open_root(anchor)
    try:
        anchor_standard = _standard(handle)
        anchor_tag = _attribute_tag(handle)
        if not anchor_standard["directory"]:
            raise ProtectedObjectError("volume root is not a directory")
        if anchor_tag["attributes"] & FILE_ATTRIBUTE_REPARSE_POINT or anchor_tag[
            "reparse_tag"
        ]:
            raise ProtectedObjectError("reparse point volume root forbidden")
        for name in path.relative_to(anchor).parts:
            child = _open_relative(handle, name, directory=True)
            _close(handle)
            handle = child
            standard = _standard(handle)
            tag = _attribute_tag(handle)
            if tag["attributes"] & FILE_ATTRIBUTE_REPARSE_POINT or tag["reparse_tag"]:
                raise ProtectedObjectError(
                    f"reparse point forbidden in source root path: {name}"
                )
            if not standard["directory"]:
                raise ProtectedObjectError(
                    f"source root component is not a directory: {name}"
                )
        return handle
    except Exception:
        _close(handle)
        raise


def _open_relative(parent: int, name: str, *, directory: bool) -> int:
    encoded = name
    buffer = ctypes.create_unicode_buffer(encoded)
    unicode_name = UNICODE_STRING(
        Length=len(encoded.encode("utf-16-le")),
        MaximumLength=(len(encoded) + 1) * 2,
        Buffer=ctypes.cast(buffer, wintypes.LPWSTR),
    )
    attributes = OBJECT_ATTRIBUTES(
        Length=ctypes.sizeof(OBJECT_ATTRIBUTES),
        RootDirectory=wintypes.HANDLE(parent),
        ObjectName=ctypes.pointer(unicode_name),
        Attributes=OBJ_CASE_INSENSITIVE,
        SecurityDescriptor=None,
        SecurityQualityOfService=None,
    )
    status_block = IO_STATUS_BLOCK()
    handle = wintypes.HANDLE()
    options = (
        FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | (FILE_DIRECTORY_FILE if directory else FILE_NON_DIRECTORY_FILE)
    )
    status = ntdll.NtCreateFile(
        ctypes.byref(handle),
        GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        ctypes.byref(attributes),
        ctypes.byref(status_block),
        None,
        0,
        FILE_SHARE_READ,
        FILE_OPEN,
        options,
        None,
        0,
    )
    if status < 0:
        raise ProtectedObjectError(
            f"cannot open relative object {name}: ntstatus={status:#x}"
        )
    return int(handle.value)


def _close(handle: int) -> None:
    if not kernel32.CloseHandle(wintypes.HANDLE(handle)):
        _raise_win("CloseHandle failed")


def _info(handle: int, info_class: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    ok = kernel32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle), info_class, buffer, size
    )
    if not ok:
        error = ctypes.get_last_error()
        if error == ERROR_NO_MORE_FILES:
            return b""
        raise ProtectedObjectError(
            f"GetFileInformationByHandleEx({info_class}) failed: winerror={error}"
        )
    return buffer.raw


def _file_id(handle: int) -> dict[str, Any]:
    data = _info(handle, 18, 24)
    volume = int.from_bytes(data[0:8], "little")
    object_id = data[8:24].hex()
    return {"volume_id": f"{volume:016x}", "file_id": object_id}


def _standard(handle: int) -> dict[str, Any]:
    data = _info(handle, 1, 24)
    return {
        "allocation_size": int.from_bytes(data[0:8], "little", signed=True),
        "size": int.from_bytes(data[8:16], "little", signed=True),
        "link_count": int.from_bytes(data[16:20], "little"),
        "delete_pending": bool(data[20]),
        "directory": bool(data[21]),
    }


def _attribute_tag(handle: int) -> dict[str, Any]:
    data = _info(handle, 9, 8)
    return {
        "attributes": int.from_bytes(data[0:4], "little"),
        "reparse_tag": int.from_bytes(data[4:8], "little"),
    }


def _basic(handle: int) -> dict[str, Any]:
    data = _info(handle, 0, 40)
    return {
        "creation_time": int.from_bytes(data[0:8], "little", signed=True),
        "last_access_time": int.from_bytes(data[8:16], "little", signed=True),
        "last_write_time": int.from_bytes(data[16:24], "little", signed=True),
        "change_time": int.from_bytes(data[24:32], "little", signed=True),
        "file_attributes": int.from_bytes(data[32:36], "little"),
    }


def _streams(handle: int) -> list[dict[str, Any]]:
    data = _info(handle, 7, 1024 * 1024)
    if not data:
        return []
    result = []
    offset = 0
    while True:
        next_offset = int.from_bytes(data[offset : offset + 4], "little")
        name_length = int.from_bytes(data[offset + 4 : offset + 8], "little")
        stream_size = int.from_bytes(
            data[offset + 8 : offset + 16], "little", signed=True
        )
        name = data[offset + 24 : offset + 24 + name_length].decode("utf-16-le")
        result.append({"name": name, "size": stream_size})
        if next_offset == 0:
            break
        offset += next_offset
        if offset >= len(data):
            raise ProtectedObjectError("malformed FileStreamInfo")
    return result


def _security(handle: int) -> str:
    owner = wintypes.LPVOID()
    group = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    sacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    error = advapi32.GetSecurityInfo(
        wintypes.HANDLE(handle),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        ctypes.byref(group),
        ctypes.byref(dacl),
        ctypes.byref(sacl),
        ctypes.byref(descriptor),
    )
    if error:
        raise ProtectedObjectError(f"GetSecurityInfo failed: winerror={error}")
    text = wintypes.LPWSTR()
    length = wintypes.DWORD()
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ctypes.byref(text),
            ctypes.byref(length),
        ):
            _raise_win("ConvertSecurityDescriptorToStringSecurityDescriptorW failed")
        return text.value or ""
    finally:
        if descriptor.value:
            kernel32.LocalFree(descriptor)


if os.name == "nt":
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL


def _read_all(fd: int, expected_size: int) -> bytes:
    if expected_size < 0:
        raise ProtectedObjectError("negative file size")
    if expected_size > MAX_FILE_BYTES:
        raise ProtectedObjectError("file exceeds size policy")
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    remaining = expected_size
    while remaining:
        try:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
        except InterruptedError:
            continue
        except OSError as exc:
            raise ProtectedObjectError(f"read failed: {exc}") from exc
        if not chunk:
            raise ProtectedObjectError("unexpected EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _account_size(size: int, total: list[int]) -> None:
    if size < 0 or size > MAX_FILE_BYTES:
        raise ProtectedObjectError("file exceeds size policy")
    if total[0] > MAX_TOTAL_BYTES - size:
        raise ProtectedObjectError("source tree exceeds total size policy")
    total[0] += size


def _directory_entries(handle: int) -> list[tuple[str, int, int]]:
    data = _info(handle, 10, 1024 * 1024)
    if not data:
        return []
    result = []
    offset = 0
    while True:
        next_offset = int.from_bytes(data[offset : offset + 4], "little")
        attributes = int.from_bytes(data[offset + 56 : offset + 60], "little")
        name_length = int.from_bytes(data[offset + 60 : offset + 64], "little")
        name = data[offset + 104 : offset + 104 + name_length].decode("utf-16-le")
        if name not in {".", ".."}:
            result.append((name, attributes, offset))
        if next_offset == 0:
            break
        offset += next_offset
        if offset >= len(data):
            raise ProtectedObjectError("malformed directory enumeration")
    return result


def _snapshot_file(handle: int, total: list[int]) -> dict[str, Any]:
    if msvcrt is None:
        raise ProtectedObjectError("Windows file snapshot used on POSIX")
    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    try:
        standard = _standard(handle)
        tag = _attribute_tag(handle)
        if tag["attributes"] & FILE_ATTRIBUTE_REPARSE_POINT or tag["reparse_tag"]:
            raise ProtectedObjectError("reparse point forbidden")
        if standard["directory"]:
            raise ProtectedObjectError("expected file, observed directory")
        if standard["link_count"] != 1:
            raise ProtectedObjectError("hardlink forbidden")
        _account_size(standard["size"], total)
        first = _read_all(fd, standard["size"])
        second = _read_all(fd, standard["size"])
        if first != second:
            raise ProtectedObjectError("two reads from same handle differ")
        streams = _streams(handle)
        named = [
            item["name"]
            for item in streams
            if item["name"] not in {"::$DATA", ":$DATA"}
        ]
        if named:
            raise ProtectedObjectError(
                "alternate data stream forbidden: " + ", ".join(sorted(named))
            )
        identity = _file_id(handle)
        security = _security(handle)
        basic = _basic(handle)
        return {
            "file_id": identity["file_id"],
            "volume_id": identity["volume_id"],
            "size": standard["size"],
            "link_count": standard["link_count"],
            "owner": security.split("D:", 1)[0],
            "security_sddl": security,
            "security_digest": sha256_bytes(security.encode("utf-8")),
            "timestamps": {
                key: value
                for key, value in basic.items()
                if key not in {"file_attributes", "last_access_time"}
            },
            "file_attributes": basic["file_attributes"],
            "streams": streams,
            "named_streams": named,
            "same_handle": True,
            "two_reads_equal": first == second,
            "content_sha256": sha256_bytes(first),
            "content": first,
        }
    finally:
        os.close(fd)


def _walk_windows(root: Path) -> dict[str, Any]:
    root_handle = _open_windows_root(root)
    total = [0]
    try:
        root_standard = _standard(root_handle)
        root_tag = _attribute_tag(root_handle)
        if not root_standard["directory"]:
            raise ProtectedObjectError("source root is not a directory")
        if root_tag["attributes"] & FILE_ATTRIBUTE_REPARSE_POINT or root_tag["reparse_tag"]:
            raise ProtectedObjectError("reparse point source root forbidden")
        root_id = _file_id(root_handle)
        root_basic = _basic(root_handle)
        root_generation = typed_digest(
            {
                "volume_id": root_id["volume_id"],
                "file_id": root_id["file_id"],
                "creation_time": root_basic["creation_time"],
            },
            "source-root-generation",
            "1",
        )
        sources = []
        directories = [
            {
                "relative_path": ".",
                **root_id,
                "generation": root_generation,
            }
        ]

        def visit(parent_handle: int, prefix: str) -> None:
            for name, attributes, _ in _directory_entries(parent_handle):
                if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ProtectedObjectError(
                        f"reparse point forbidden: {prefix}{name}"
                    )
                directory = bool(attributes & FILE_ATTRIBUTE_DIRECTORY)
                handle = _open_relative(parent_handle, name, directory=directory)
                relative = f"{prefix}{name}"
                try:
                    if directory:
                        identity = _file_id(handle)
                        directories.append(
                            {
                                "relative_path": relative + "/",
                                **identity,
                            }
                        )
                        visit(handle, relative + "/")
                    else:
                        record = _snapshot_file(handle, total)
                        record["relative_path"] = relative
                        record["root_generation"] = root_generation
                        sources.append(record)
                finally:
                    if directory:
                        _close(handle)

        visit(root_handle, "")
        return {
            "root_generation": root_generation,
            "directories": sorted(directories, key=lambda item: item["relative_path"]),
            "sources": sorted(sources, key=lambda item: item["relative_path"]),
        }
    finally:
        _close(root_handle)


def _walk_posix(root: Path) -> dict[str, Any]:
    anchor = Path(root.anchor)
    root_fd = os.open(
        anchor,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for name in root.relative_to(anchor).parts:
            child_fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=root_fd,
            )
            os.close(root_fd)
            root_fd = child_fd
            if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
                raise ProtectedObjectError(
                    f"source root component is not a directory: {name}"
                )
    except Exception:
        os.close(root_fd)
        raise
    sources = []
    directories = []
    total = [0]
    try:
        root_stat = os.fstat(root_fd)
        generation = typed_digest(
            {
                "device": root_stat.st_dev,
                "inode": root_stat.st_ino,
                "ctime_ns": root_stat.st_ctime_ns,
            },
            "source-root-generation",
            "1",
        )
        directories.append(
            {
                "relative_path": ".",
                "file_id": str(root_stat.st_ino),
                "volume_id": str(root_stat.st_dev),
                "generation": generation,
            }
        )

        def visit(directory_fd: int, prefix: str) -> None:
            with os.scandir(directory_fd) as entries:
                for entry in sorted(entries, key=lambda item: item.name):
                    relative = prefix + entry.name
                    try:
                        observed = os.stat(
                            entry.name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                    except OSError as exc:
                        raise ProtectedObjectError(
                            f"cannot inspect {relative}: {exc}"
                        ) from exc
                    if stat.S_ISLNK(observed.st_mode):
                        raise ProtectedObjectError(f"symlink forbidden: {relative}")
                    if not (
                        stat.S_ISDIR(observed.st_mode)
                        or stat.S_ISREG(observed.st_mode)
                    ):
                        raise ProtectedObjectError(f"special file forbidden: {relative}")
                    flags = (
                        os.O_RDONLY
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NONBLOCK", 0)
                    )
                    try:
                        fd = os.open(entry.name, flags, dir_fd=directory_fd)
                    except OSError as exc:
                        raise ProtectedObjectError(
                            f"cannot open {relative}: {exc}"
                        ) from exc
                    try:
                        info = os.fstat(fd)
                        if stat.S_ISDIR(info.st_mode):
                            directories.append(
                                {
                                    "relative_path": relative + "/",
                                    "file_id": str(info.st_ino),
                                    "volume_id": str(info.st_dev),
                                }
                            )
                            child_fd = os.open(
                                ".",
                                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                                dir_fd=fd,
                            )
                            try:
                                visit(child_fd, relative + "/")
                            finally:
                                os.close(child_fd)
                        elif stat.S_ISREG(info.st_mode):
                            if info.st_nlink != 1:
                                raise ProtectedObjectError(
                                    f"hardlink forbidden: {relative}"
                                )
                            _account_size(info.st_size, total)
                            first = _read_all(fd, info.st_size)
                            second = _read_all(fd, info.st_size)
                            after = os.fstat(fd)
                            if (
                                after.st_dev != info.st_dev
                                or after.st_ino != info.st_ino
                                or after.st_size != info.st_size
                                or after.st_mtime_ns != info.st_mtime_ns
                                or after.st_ctime_ns != info.st_ctime_ns
                            ):
                                raise ProtectedObjectError(
                                    f"file changed during read: {relative}"
                                )
                            sources.append(
                                {
                                    "relative_path": relative,
                                    "file_id": str(info.st_ino),
                                    "volume_id": str(info.st_dev),
                                    "size": info.st_size,
                                    "link_count": info.st_nlink,
                                    "owner": str(info.st_uid),
                                    "security_sddl": f"posix-mode:{info.st_mode:o}",
                                    "security_digest": sha256_bytes(
                                        f"{info.st_mode:o}".encode("ascii")
                                    ),
                                    "timestamps": {
                                        "ctime_ns": info.st_ctime_ns,
                                        "mtime_ns": info.st_mtime_ns,
                                    },
                                    "streams": [],
                                    "named_streams": [],
                                    "same_handle": True,
                                    "two_reads_equal": first == second,
                                    "content_sha256": sha256_bytes(first),
                                    "content": first,
                                    "root_generation": generation,
                                }
                            )
                        else:
                            raise ProtectedObjectError(
                                f"special file forbidden: {relative}"
                            )
                    finally:
                        os.close(fd)

        visit(root_fd, "")
        return {
            "root_generation": generation,
            "directories": sorted(directories, key=lambda item: item["relative_path"]),
            "sources": sorted(sources, key=lambda item: item["relative_path"]),
        }
    finally:
        os.close(root_fd)


def snapshot_tree(root: Path) -> dict[str, Any]:
    root = Path(os.path.abspath(os.fspath(root)))
    try:
        if os.name != "nt":
            info = os.lstat(root)
            if stat.S_ISLNK(info.st_mode):
                raise ProtectedObjectError(f"source root is a symlink: {root}")
            if not stat.S_ISDIR(info.st_mode):
                raise ProtectedObjectError(f"source root is not a directory: {root}")
        walked = _walk_windows(root) if os.name == "nt" else _walk_posix(root)
    except ProtectedObjectError:
        raise
    except OSError as exc:
        code = errno.errorcode.get(exc.errno, str(exc.errno))
        raise ProtectedObjectError(
            f"protected read failed for {root}: {code}: {exc}"
        ) from exc
    public_sources = []
    for record in walked["sources"]:
        public = {key: value for key, value in record.items() if key != "content"}
        public_sources.append(public)
    value = {
        "schema_version": 2,
        "root": str(root),
        "root_generation": walked["root_generation"],
        "source_count": len(public_sources),
        "directory_count": len(walked["directories"]),
        "sources": public_sources,
        "directories": walked["directories"],
    }
    value["snapshot_digest"] = typed_digest(value, "protected-snapshot", "2")
    value["_content_by_path"] = {
        item["relative_path"]: item["content"] for item in walked["sources"]
    }
    return value


def public_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in snapshot.items() if not key.startswith("_")}
