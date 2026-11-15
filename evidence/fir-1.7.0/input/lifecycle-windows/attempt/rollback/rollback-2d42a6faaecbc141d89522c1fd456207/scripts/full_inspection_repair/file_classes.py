from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

TEXT_SOURCE = "TEXT_SOURCE"
TEXT_DATA = "TEXT_DATA"
DOCUMENTATION = "DOCUMENTATION"
TEST_SOURCE = "TEST_SOURCE"
CONFIGURATION = "CONFIGURATION"
BINARY_OPAQUE = "BINARY_OPAQUE"
CACHE_ARTIFACT = "CACHE_ARTIFACT"

FILE_CLASSES = (
    TEXT_SOURCE,
    TEXT_DATA,
    DOCUMENTATION,
    TEST_SOURCE,
    CONFIGURATION,
    BINARY_OPAQUE,
    CACHE_ARTIFACT,
)

_CACHE_NAMES = frozenset(
    {
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".hypothesis",
        ".coverage",
    }
)
_DOCUMENT_SUFFIXES = frozenset({".md", ".markdown", ".rst"})
_DATA_SUFFIXES = frozenset(
    {".json", ".jsonl", ".yaml", ".yml", ".toml", ".xml", ".csv", ".tsv"}
)
_CONFIG_SUFFIXES = frozenset(
    {".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties"}
)
_CONFIG_NAMES = frozenset(
    {
        ".importlinter",
        ".editorconfig",
        "pytest.ini",
        "tox.ini",
        "setup.cfg",
        "requirements.txt",
        "pyproject.toml",
    }
)
_SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".ps1",
        ".psm1",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".html",
        ".htm",
        ".css",
        ".scss",
        ".sql",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
    }
)
_BINARY_SUFFIXES = frozenset(
    {
        ".pyc",
        ".pyo",
        ".class",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".zip",
        ".whl",
        ".gz",
        ".tar",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".pdf",
        ".woff",
        ".woff2",
    }
)

SCANNER_BINDINGS = {
    ".py": ("scanner.python.ast",),
    ".pyi": ("scanner.python.ast",),
    ".md": ("scanner.markdown.links",),
    ".markdown": ("scanner.markdown.links",),
    ".ps1": ("scanner.powershell.commands",),
    ".psm1": ("scanner.powershell.commands",),
    ".sh": ("scanner.shell.commands",),
    ".bash": ("scanner.shell.commands",),
    ".zsh": ("scanner.shell.commands",),
    ".fish": ("scanner.shell.commands",),
    ".js": ("scanner.javascript.references",),
    ".jsx": ("scanner.javascript.references",),
    ".ts": ("scanner.javascript.references",),
    ".tsx": ("scanner.javascript.references",),
    ".mjs": ("scanner.javascript.references",),
    ".cjs": ("scanner.javascript.references",),
    ".html": ("scanner.markup.references",),
    ".htm": ("scanner.markup.references",),
    ".css": ("scanner.stylesheet.references",),
    ".scss": ("scanner.stylesheet.references",),
    ".json": ("scanner.structured-config.paths",),
    ".jsonl": ("scanner.structured-config.paths",),
    ".yaml": ("scanner.structured-config.paths",),
    ".yml": ("scanner.structured-config.paths",),
    ".toml": ("scanner.structured-config.paths",),
    ".xml": ("scanner.structured-config.paths",),
    ".ini": ("scanner.structured-config.paths",),
    ".cfg": ("scanner.structured-config.paths",),
    ".conf": ("scanner.structured-config.paths",),
    ".properties": ("scanner.structured-config.paths",),
}


def _path(value: str | PurePosixPath) -> PurePosixPath:
    return PurePosixPath(str(value).replace("\\", "/"))


def is_cache_path(locator: str | PurePosixPath) -> bool:
    path = _path(locator)
    return any(part.casefold() in _CACHE_NAMES for part in path.parts)


def is_test_path(locator: str | PurePosixPath) -> bool:
    path = _path(locator)
    name = path.name.casefold()
    return "tests" in {part.casefold() for part in path.parts[:-1]} or (
        name.startswith("test_") or name.endswith("_test.py")
    )


def is_binary_content(content: bytes | None, locator: str | PurePosixPath = "") -> bool:
    path = _path(locator)
    if path.suffix.casefold() in _BINARY_SUFFIXES:
        return True
    if content is None:
        return False
    if b"\x00" in content:
        return True
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def classify_file(
    locator: str | PurePosixPath,
    content: bytes | None = None,
    *,
    is_directory: bool = False,
) -> dict[str, Any]:
    path = _path(locator)
    suffix = path.suffix.casefold()
    name = path.name.casefold()

    if is_cache_path(path):
        file_class = CACHE_ARTIFACT
    elif is_directory:
        file_class = TEXT_DATA
    elif is_test_path(path) and suffix in _SOURCE_SUFFIXES:
        file_class = TEST_SOURCE
    elif suffix in _DOCUMENT_SUFFIXES:
        file_class = DOCUMENTATION
    elif name in _CONFIG_NAMES or suffix in _CONFIG_SUFFIXES:
        file_class = CONFIGURATION
    elif is_binary_content(content, path):
        file_class = BINARY_OPAQUE
    elif suffix in _SOURCE_SUFFIXES:
        file_class = TEXT_SOURCE
    elif suffix in _DATA_SUFFIXES:
        file_class = TEXT_DATA
    elif name in {"skill.md", "requirements.txt"}:
        file_class = DOCUMENTATION if name == "skill.md" else CONFIGURATION
    else:
        file_class = TEXT_DATA

    scanner_ids = list(scanner_ids_for(path, file_class, is_directory=is_directory))
    if file_class in {BINARY_OPAQUE, CACHE_ARTIFACT} or is_directory:
        coverage_status = "OPAQUE_RAW_ONLY"
        unscanned_reason = (
            "RUNTIME_CACHE_RAW_ONLY"
            if file_class == CACHE_ARTIFACT
            else "BINARY_RAW_ONLY"
            if file_class == BINARY_OPAQUE
            else "DIRECTORY_RESOURCE_ONLY"
        )
    elif scanner_ids:
        coverage_status = "SCANNED"
        unscanned_reason = None
    else:
        coverage_status = "UNSUPPORTED"
        unscanned_reason = "UNSUPPORTED_FILE_CLASS"

    return {
        "locator": path.as_posix(),
        "file_class": file_class,
        "text_or_opaque": (
            "OPAQUE" if file_class in {BINARY_OPAQUE, CACHE_ARTIFACT} else "TEXT"
        ),
        "scanner_ids": scanner_ids,
        "coverage_status": coverage_status,
        "unscanned_reason": unscanned_reason,
        "is_test": file_class == TEST_SOURCE,
        "is_configuration": file_class == CONFIGURATION,
        "is_cache": file_class == CACHE_ARTIFACT,
        "is_binary": file_class == BINARY_OPAQUE,
    }


def scanner_ids_for(
    locator: str | PurePosixPath,
    file_class: str | None = None,
    *,
    is_directory: bool = False,
) -> tuple[str, ...]:
    path = _path(locator)
    if is_directory or file_class in {BINARY_OPAQUE, CACHE_ARTIFACT}:
        return ()
    scanners = list(SCANNER_BINDINGS.get(path.suffix.casefold(), ()))
    if file_class == TEST_SOURCE and path.suffix.casefold() == ".py":
        scanners.append("scanner.test.references")
    return tuple(dict.fromkeys(scanners))


def classify_locator(locator: str | PurePosixPath) -> dict[str, Any]:
    return classify_file(locator, None)


def scanner_bindings() -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "scanner_id": scanner_id,
            "extensions": sorted(
                extension
                for extension, scanner_ids in SCANNER_BINDINGS.items()
                if scanner_id in scanner_ids
            ),
        }
        for scanner_id in sorted({item for ids in SCANNER_BINDINGS.values() for item in ids})
    )
