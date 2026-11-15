from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.controlplane import (
    ControlPlaneBlocked,
    assert_phase_status,
    resolve_layout,
)


def test_t_path_01_output_equal_to_target_is_blocked(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(ControlPlaneBlocked, match="disjoint"):
        resolve_layout("check", target=target, output=target)


@pytest.mark.parametrize(
    "output",
    (
        lambda target: target / "output",
        lambda target: target.parent,
    ),
)
def test_t_path_02_output_inside_target_is_blocked(tmp_path: Path, output) -> None:
    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(ControlPlaneBlocked, match="disjoint"):
        resolve_layout("check", target=target, output=output(target))


def test_t_path_03_repair_requires_pairwise_disjoint_paths(tmp_path: Path) -> None:
    target = tmp_path / "source"
    target.mkdir()
    output = tmp_path / "run"
    with pytest.raises(ControlPlaneBlocked, match="candidate"):
        resolve_layout(
            "repair",
            target=target,
            output=output,
            candidate=target / "candidate",
        )


def test_existing_output_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "source"
    target.mkdir()
    output = tmp_path / "run"
    output.mkdir()
    with pytest.raises(ControlPlaneBlocked, match="already exists"):
        resolve_layout("check", target=target, output=output)


def test_t_life_02_inspection_cannot_claim_installed() -> None:
    with pytest.raises(ControlPlaneBlocked, match="inspection"):
        assert_phase_status("inspection", "INSTALLED")


def test_install_lifecycle_owns_installed_status() -> None:
    assert_phase_status("inspection", "CLOSED_FOR_DECLARED_UNIVERSE")
    assert_phase_status("release", "RELEASE_READY")
    assert_phase_status("install", "INSTALLED")
