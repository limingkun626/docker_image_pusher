from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any


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
    if path.stat().st_size > max_bytes:
        raise StrictJSONError("JSON exceeds size policy")
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise StrictJSONError("JSON exceeds size policy")
    return strict_loads(data, max_bytes=max_bytes)


def read_jsonl(
    path: Path,
    *,
    max_line_bytes: int = 8 * 1024 * 1024,
    max_bytes: int = 64 * 1024 * 1024,
) -> list[Any]:
    if path.stat().st_size > max_bytes:
        raise StrictJSONError("JSONL exceeds size policy")
    result = []
    total = 0
    number = 0
    with path.open("rb") as handle:
        while True:
            limit = min(max_line_bytes, max_bytes - total) + 1
            line = handle.readline(limit)
            if not line:
                break
            number += 1
            total += len(line)
            if total > max_bytes:
                raise StrictJSONError("JSONL exceeds size policy")
            line = line.rstrip(b"\r\n")
            if not line.strip():
                continue
            if len(line) > max_line_bytes:
                raise StrictJSONError(f"JSONL line exceeds size policy: {number}")
            result.append(strict_loads(line))
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
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        fsync_fd(fd)
    finally:
        os.close(fd)


def typed_digest(value: Any, object_type: str, schema_version: str) -> str:
    if not object_type or not schema_version:
        raise StrictJSONError("typed digest identity is required")
    prefix = (
        "full-inspection-repair\0"
        + object_type
        + "\0"
        + schema_version
        + "\0"
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


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")

