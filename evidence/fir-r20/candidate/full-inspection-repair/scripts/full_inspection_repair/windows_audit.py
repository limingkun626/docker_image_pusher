from __future__ import annotations

import ctypes
import os
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contracts import canonical_digest

FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL = 0x000900BB
USN_JOURNAL_DATA_SIZE = 56
USN_READ_BUFFER_SIZE = 64 * 1024
ERROR_HANDLE_EOF = 38
ERROR_MORE_DATA = 234
FILE_ATTRIBUTE_DIRECTORY = 0x10


class WindowsAuditUnavailable(RuntimeError):
    """Raised when a Windows filesystem audit capability cannot be trusted."""


if os.name == "nt":
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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
    _kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.DeviceIoControl.restype = wintypes.BOOL
    _kernel32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    _kernel32.GetVolumeInformationW.restype = wintypes.BOOL


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _volume_anchor(path: str | Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if os.name != "nt" or not absolute.anchor:
        raise WindowsAuditUnavailable("Windows volume path is required")
    return Path(absolute.anchor)


def _volume_device(path: Path) -> str:
    anchor = _volume_anchor(path)
    drive = anchor.drive.rstrip(":\\")
    if len(drive) != 1:
        raise WindowsAuditUnavailable(f"unsupported volume anchor: {anchor}")
    return f"\\\\.\\{drive}:"


def _volume_identity(anchor: Path) -> dict[str, object]:
    serial = wintypes.DWORD()
    max_component = wintypes.DWORD()
    flags = wintypes.DWORD()
    name = ctypes.create_unicode_buffer(261)
    filesystem = ctypes.create_unicode_buffer(261)
    ok = _kernel32.GetVolumeInformationW(
        str(anchor),
        name,
        len(name),
        ctypes.byref(serial),
        ctypes.byref(max_component),
        ctypes.byref(flags),
        filesystem,
        len(filesystem),
    )
    if not ok:
        error = ctypes.get_last_error()
        raise WindowsAuditUnavailable(
            f"GetVolumeInformationW failed for {anchor}: winerror={error}"
        )
    filesystem_name = filesystem.value.upper()
    if filesystem_name != "NTFS":
        raise WindowsAuditUnavailable(f"USN journal requires NTFS: {filesystem_name}")
    return {
        "volume": str(anchor),
        "volume_device": _volume_device(anchor),
        "volume_name": name.value,
        "volume_serial": f"{serial.value:08x}",
        "filesystem": filesystem_name,
    }


def _open_volume(anchor: Path) -> int:
    handle = _kernel32.CreateFileW(
        _volume_device(anchor),
        0x80000000,
        0x1 | 0x2 | 0x4,
        None,
        3,
        0,
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        error = ctypes.get_last_error()
        raise WindowsAuditUnavailable(
            f"cannot open USN volume {anchor}: winerror={error}"
        )
    return int(handle)


def _device_io_control(
    handle: int,
    code: int,
    input_bytes: bytes,
    output_size: int,
) -> bytes:
    input_buffer = (
        ctypes.create_string_buffer(input_bytes, len(input_bytes))
        if input_bytes
        else None
    )
    output_buffer = ctypes.create_string_buffer(output_size)
    returned = wintypes.DWORD()
    ok = _kernel32.DeviceIoControl(
        wintypes.HANDLE(handle),
        code,
        input_buffer,
        len(input_bytes),
        output_buffer,
        output_size,
        ctypes.byref(returned),
        None,
    )
    error = ctypes.get_last_error()
    if not ok and error not in {ERROR_MORE_DATA, ERROR_HANDLE_EOF}:
        raise WindowsAuditUnavailable(
            f"DeviceIoControl {code:#x} failed: winerror={error}"
        )
    return output_buffer.raw[: returned.value]


def _query_journal(path: str | Path) -> dict[str, object]:
    anchor = _volume_anchor(path)
    identity = _volume_identity(anchor)
    handle = _open_volume(anchor)
    try:
        raw = _device_io_control(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            b"",
            USN_JOURNAL_DATA_SIZE,
        )
    finally:
        _kernel32.CloseHandle(wintypes.HANDLE(handle))
    if len(raw) < USN_JOURNAL_DATA_SIZE:
        raise WindowsAuditUnavailable("USN journal query returned a short buffer")
    (
        journal_id,
        first_usn,
        next_usn,
        lowest_valid_usn,
        maximum_usn,
        maximum_size,
        allocation_delta,
    ) = struct.unpack("<QqqqqQQ", raw[:USN_JOURNAL_DATA_SIZE])
    return {
        **identity,
        "journal_id": journal_id,
        "first_usn": first_usn,
        "next_usn": next_usn,
        "lowest_valid_usn": lowest_valid_usn,
        "maximum_usn": maximum_usn,
        "maximum_size": maximum_size,
        "allocation_delta": allocation_delta,
    }


def audit_capability(path: str | Path) -> dict[str, object]:
    """Return a fail-closed, structured USN journal availability result."""

    base: dict[str, object] = {
        "schema_version": 1,
        "checked_at": _now(),
        "path": str(Path(os.path.abspath(os.fspath(path)))),
        "available": False,
        "status": "UNAVAILABLE",
        "reason": None,
    }
    try:
        base.update(_query_journal(path))
    except WindowsAuditUnavailable as exc:
        base["reason"] = str(exc)
    else:
        base["available"] = True
        base["status"] = "AVAILABLE"
    base["capability_digest"] = canonical_digest(base)
    return base


def start_filesystem_audit(path: str | Path) -> dict[str, object]:
    journal = _query_journal(path)
    result: dict[str, object] = {
        "schema_version": 1,
        "status": "STARTED",
        "started_at": _now(),
        "path": str(Path(os.path.abspath(os.fspath(path)))),
        **journal,
        "start_usn": journal["next_usn"],
    }
    result["start_digest"] = canonical_digest(result)
    return result


def _decode_record(raw: bytes) -> dict[str, object]:
    if len(raw) < 8:
        raise WindowsAuditUnavailable("USN record header is truncated")
    record_length = struct.unpack_from("<I", raw)[0]
    major = struct.unpack_from("<H", raw, 4)[0]
    if record_length < 8 or record_length > len(raw):
        raise WindowsAuditUnavailable("USN record length is invalid")
    if major == 2:
        if record_length < 60:
            raise WindowsAuditUnavailable("USN_RECORD_V2 is truncated")
        file_reference = struct.unpack_from("<Q", raw, 8)[0]
        parent_reference = struct.unpack_from("<Q", raw, 16)[0]
        usn = struct.unpack_from("<q", raw, 24)[0]
        timestamp = struct.unpack_from("<q", raw, 32)[0]
        reason = struct.unpack_from("<I", raw, 40)[0]
        source_info = struct.unpack_from("<I", raw, 44)[0]
        security_id = struct.unpack_from("<I", raw, 48)[0]
        attributes = struct.unpack_from("<I", raw, 52)[0]
        name_length = struct.unpack_from("<H", raw, 56)[0]
        name_offset = struct.unpack_from("<H", raw, 58)[0]
    elif major == 3:
        if record_length < 76:
            raise WindowsAuditUnavailable("USN_RECORD_V3 is truncated")
        file_reference = raw[8:24].hex()
        parent_reference = raw[24:40].hex()
        usn = struct.unpack_from("<q", raw, 40)[0]
        timestamp = struct.unpack_from("<q", raw, 48)[0]
        reason = struct.unpack_from("<I", raw, 56)[0]
        source_info = struct.unpack_from("<I", raw, 60)[0]
        security_id = struct.unpack_from("<I", raw, 64)[0]
        attributes = struct.unpack_from("<I", raw, 68)[0]
        name_length = struct.unpack_from("<H", raw, 72)[0]
        name_offset = struct.unpack_from("<H", raw, 74)[0]
    else:
        raise WindowsAuditUnavailable(f"unsupported USN record version: {major}")
    if name_offset + name_length > record_length:
        raise WindowsAuditUnavailable("USN record filename exceeds record length")
    return {
        "record_length": record_length,
        "major_version": major,
        "file_reference_number": file_reference,
        "parent_file_reference_number": parent_reference,
        "usn": usn,
        "timestamp": timestamp,
        "reason": reason,
        "source_info": source_info,
        "security_id": security_id,
        "file_attributes": attributes,
        "is_directory": bool(attributes & FILE_ATTRIBUTE_DIRECTORY),
        "file_name": raw[name_offset : name_offset + name_length].decode(
            "utf-16-le", errors="strict"
        ),
    }


def _event_usn(event: dict[str, object]) -> int:
    try:
        return int(event["usn"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WindowsAuditUnavailable("USN event has an invalid identity") from exc


def _read_journal(
    journal: dict[str, object],
    *,
    start_usn: int,
    end_usn: int,
    max_records: int,
) -> list[dict[str, object]]:
    if max_records <= 0:
        raise ValueError("max_records must be positive")
    anchor = Path(str(journal["volume"]))
    handle = _open_volume(anchor)
    events: list[dict[str, object]] = []
    next_usn = start_usn
    try:
        while next_usn < end_usn:
            input_data = struct.pack(
                "<qIIQQQ",
                next_usn,
                0xFFFFFFFF,
                0,
                0,
                0,
                int(journal["journal_id"]),
            )
            raw = _device_io_control(
                handle,
                FSCTL_READ_USN_JOURNAL,
                input_data,
                USN_READ_BUFFER_SIZE,
            )
            if len(raw) < 8:
                raise WindowsAuditUnavailable("USN read returned a short buffer")
            following_usn = struct.unpack_from("<q", raw)[0]
            position = 8
            while position + 8 <= len(raw):
                record_length = struct.unpack_from("<I", raw, position)[0]
                if record_length == 0 or position + record_length > len(raw):
                    raise WindowsAuditUnavailable("USN buffer contains a torn record")
                event = _decode_record(raw[position : position + record_length])
                event_usn = _event_usn(event)
                if event_usn < start_usn:
                    raise WindowsAuditUnavailable("USN event precedes the audit start")
                if event_usn >= end_usn:
                    position += record_length
                    continue
                events.append(event)
                if len(events) > max_records:
                    raise WindowsAuditUnavailable("USN event limit exceeded")
                position += record_length
            if following_usn <= next_usn:
                break
            next_usn = min(following_usn, end_usn)
    finally:
        _kernel32.CloseHandle(wintypes.HANDLE(handle))
    return events


def finish_filesystem_audit(
    start: dict[str, Any],
    *,
    max_records: int = 100_000,
) -> dict[str, object]:
    if start.get("schema_version") != 1 or start.get("status") != "STARTED":
        raise WindowsAuditUnavailable("filesystem audit start receipt is invalid")
    if canonical_digest(
        {key: value for key, value in start.items() if key != "start_digest"}
    ) != start.get("start_digest"):
        raise WindowsAuditUnavailable("filesystem audit start digest mismatch")
    journal = _query_journal(str(start["path"]))
    if journal["journal_id"] != start.get("journal_id"):
        raise WindowsAuditUnavailable("USN journal identity changed during audit")
    start_usn = int(start["start_usn"])
    if start_usn < int(journal["lowest_valid_usn"]):
        raise WindowsAuditUnavailable("USN start position is no longer retained")
    end_usn = int(journal["next_usn"])
    events = _read_journal(
        journal,
        start_usn=start_usn,
        end_usn=end_usn,
        max_records=max_records,
    )
    if any(_event_usn(event) < start_usn for event in events):
        raise WindowsAuditUnavailable("USN event precedes the audit start")
    events = [event for event in events if _event_usn(event) < end_usn]
    result: dict[str, object] = {
        "schema_version": 1,
        "status": "COMPLETE",
        "completed_at": _now(),
        "path": start["path"],
        "journal_id": journal["journal_id"],
        "start_usn": start_usn,
        "end_usn": end_usn,
        "start_identity_digest": start["start_digest"],
        "end_identity_digest": canonical_digest(journal),
        "event_count": len(events),
        "events": events,
    }
    result["events_digest"] = canonical_digest(events)
    result["audit_digest"] = canonical_digest(result)
    return result
