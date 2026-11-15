from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.file_classes import (
    BINARY_OPAQUE,
    CACHE_ARTIFACT,
    CONFIGURATION,
    TEST_SOURCE,
    TEXT_SOURCE,
    classify_file,
)


def test_t_file_01_powershell_is_text_source_with_scanner() -> None:
    result = classify_file("scripts/check.ps1", b"Write-Output 'ok'\n")

    assert result["file_class"] == TEXT_SOURCE
    assert result["coverage_status"] == "SCANNED"
    assert result["scanner_ids"] == ["scanner.powershell.commands"]


def test_t_file_02_json_and_yaml_are_configuration_with_path_scanner() -> None:
    for locator in ("workflow.json", "workflow.yaml"):
        result = classify_file(locator, b"path: scripts/check.ps1\n")
        assert result["file_class"] == CONFIGURATION
        assert result["scanner_ids"] == ["scanner.structured-config.paths"]


def test_cache_binary_test_and_unknown_are_never_silent() -> None:
    assert classify_file("__pycache__/x.pyc", b"\x00")["file_class"] == CACHE_ARTIFACT
    assert classify_file("artifact.bin", b"\x00")["file_class"] == BINARY_OPAQUE
    assert classify_file("tests/test_x.py", b"")["file_class"] == TEST_SOURCE
    unknown = classify_file("asset.unknown", b"text")
    assert unknown["coverage_status"] == "UNSUPPORTED"
    assert unknown["unscanned_reason"] == "UNSUPPORTED_FILE_CLASS"
