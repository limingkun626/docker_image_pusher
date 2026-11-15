from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from . import capabilities
from .contracts import canonical_digest
from .runtime_registry import _freeze


def resolve_tool_runtime_fixture(
    manifest: Mapping[str, Any],
    command: Sequence[str],
    fixture: Mapping[str, Any],
    mode: str,
) -> Mapping[str, Any]:
    """Build one immutable identity receipt from the capability implementation."""
    resolved_command = capabilities._resolve_logical_command(command)
    archive = capabilities._fixture_archive_identity()
    tool = capabilities._tool_identity(manifest, resolved_command)
    fixture_case = capabilities.fixture_case_identity(fixture, mode)
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "archive_identity": {
            "archive_path": archive["archive"],
            "archive_sha256": archive["archive_sha256"],
            "archive_size": archive["archive_size"],
        },
        "member_identity": {
            "member_manifest_digest": archive["member_table_digest"],
            "tree_digest": archive["tree_digest"],
            "selected_member": fixture_case["selected_member"],
            "selected_member_digest": fixture_case["selected_member_digest"],
            "selected_tree_digest": fixture_case["extracted_tree_digest"],
        },
        "tool_identity": tool,
        "version_identity": {
            "expected_version": tool["expected_version"],
            "observed_version": tool["observed_version"],
            "version_source": tool["version_source"],
            "version_matches": tool["version_matches"],
        },
        "runtime_closure": tool["closure"],
        "runtime_closure_digest": tool["closure_digest"],
        "argv": resolved_command,
        "argv_digest": canonical_digest(resolved_command),
        "fixture_identity": fixture_case,
    }
    receipt["identity_digest"] = canonical_digest(receipt)
    return _freeze(receipt)
