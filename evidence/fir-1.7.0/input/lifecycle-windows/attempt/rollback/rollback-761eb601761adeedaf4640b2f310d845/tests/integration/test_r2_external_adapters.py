from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.r2_engine import (
    external_adapter_registry,
    run_bounded_process,
    run_external_adapter,
)


def test_external_adapters_fail_closed_without_release_authority() -> None:
    registry = external_adapter_registry()
    assert len(registry) == 11
    for cell_id, row in registry.items():
        assert row["release_authority"] is False
        result = run_external_adapter(cell_id)
        assert result["status"] == "BLOCKED_ADAPTER"
        assert result["release_authority"] is False


def test_offline_and_output_limits_do_not_become_pass() -> None:
    denied = run_bounded_process(
        [sys.executable, "-c", "print('offline')"],
        env={"NO_PROXY": "*", "HTTP_PROXY": "", "HTTPS_PROXY": ""},
    )
    assert denied["status"] == "PASS"

    offline = run_bounded_process(
        [sys.executable, "-c", "print('must not run')"],
        network_required=True,
        network_policy="DENY",
    )
    assert offline["status"] == "BLOCKED"
    assert offline["failure_code"] == "OFFLINE"

    overflow = run_bounded_process(
        [sys.executable, "-c", "print('x' * 4096)"],
        max_output_bytes=64,
    )
    assert overflow["status"] == "OUTPUT_OVERFLOW"
