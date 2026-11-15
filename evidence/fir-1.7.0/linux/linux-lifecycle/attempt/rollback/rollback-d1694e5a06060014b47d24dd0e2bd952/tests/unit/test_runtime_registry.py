from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.runtime_registry import RegistryError, load_registry


def _write_registry(tmp_path: Path, value: dict[str, object]) -> Path:
    value = copy.deepcopy(value)
    value.pop("registry_digest", None)
    value["registry_digest"] = canonical_digest(value)
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _raw_registry() -> dict[str, object]:
    return json.loads((ROOT / "policies" / "runtime-registry-v3.json").read_text())


def test_t_reg_01_registry_is_complete_frozen_and_immutable() -> None:
    snapshot = load_registry()

    assert snapshot.registry_id == "FIR-RUNTIME-REGISTRY"
    assert len(snapshot.required_cells("SKILL")) == 72
    assert snapshot["release_authority"] is False
    with pytest.raises(TypeError):
        snapshot["cell_bindings"][0]["cell_id"] = "changed"


def test_t_reg_02_missing_implementation_blocks(tmp_path: Path) -> None:
    value = _raw_registry()
    value["target_adapters"][0]["implementation"]["module"] = (
        "full_inspection_repair.module_that_does_not_exist"
    )

    with pytest.raises(RegistryError, match="EXACT_ADAPTER_MODULE_MISSING"):
        load_registry(_write_registry(tmp_path, value))


def test_t_reg_03_absolute_host_path_blocks(tmp_path: Path) -> None:
    value = _raw_registry()
    value["target_adapters"][0]["path"] = r"C:\host\tool.exe"

    with pytest.raises(RegistryError, match="package-relative"):
        load_registry(_write_registry(tmp_path, value))


def test_t_reg_04_duplicate_primary_mechanism_blocks(tmp_path: Path) -> None:
    value = _raw_registry()
    native = [
        row
        for row in value["cell_bindings"]
        if row["terminal_state"] == "COVERED_BY_NATIVE_DETECTOR"
    ]
    native[0]["detector_binding"]["mechanism_id"] = native[1]["detector_binding"][
        "mechanism_id"
    ]

    with pytest.raises(RegistryError, match="CELL_BINDING_DUPLICATE"):
        load_registry(_write_registry(tmp_path, value))


def test_t_reg_05_merge_alias_uses_one_primary() -> None:
    snapshot = load_registry()
    merged = snapshot.cell_binding("SKILL:LATENT_DEFECT:STATIC")
    primary = snapshot.cell_binding(merged["primary_cell_id"])

    assert merged["terminal_state"] == "MERGED_WITH_PRIMARY_CELL"
    assert merged["detector_binding"] is None
    assert merged["oracle_binding"] is None
    assert primary["terminal_state"] == "COVERED_BY_INDEPENDENT_ORACLE"
