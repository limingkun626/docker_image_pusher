from __future__ import annotations

import copy
import json
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import capabilities
from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.fixture_identity import resolve_tool_runtime_fixture
from full_inspection_repair.runtime_registry import _thaw

DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
STARTED_AT = "2026-11-16T00:00:00Z"
FINISHED_AT = "2026-11-16T00:01:00Z"


def _schema(name: str) -> dict:
    return json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))


def _signature_receipt() -> dict:
    return {
        "receipt_id": "signature-1",
        "signer_id": "reviewer-1",
        "issuer": "external-review",
        "verification_method": "trusted-runner",
        "receipt_digest": DIGEST,
    }


def _impact_graph() -> dict:
    return {
        "schema_version": 3,
        "subject_digest": DIGEST,
        "candidate_digest": None,
        "source_closure_digest": None,
        "impact_scanner_registry_digest": DIGEST,
        "scanner_coverage_digest": DIGEST,
        "scanner_coverage": [
            {
                "locator": "SKILL.md",
                "scanner_id": "scanner.markdown",
                "scanner_version": "1.0.0",
                "scanner_digest": DIGEST,
                "coverage_status": "SCANNED",
                "observed_ranges": [{"start_byte": 0, "end_byte": 10}],
                "edge_kinds": ["REFERENCES"],
                "failure_reason": None,
            }
        ],
        "opaque_sources": [],
        "unsupported_sources": [],
        "nodes": [{"id": "file:SKILL.md", "kind": "FILE", "locator": "SKILL.md"}],
        "edges": [],
        "imports": [],
        "consumer_evidence": {},
        "no_consumer_proofs": {},
        "finding_closure": {},
        "consumer_receipts": {},
        "graph_digest": DIGEST,
    }


def _domain_receipt() -> dict:
    return {
        "schema_version": 1,
        "kind": "domain-receipt",
        "domain_id": "lifecycle.windows.install",
        "status": "VERIFIED",
        "runner_id": "runner-1",
        "runner_version": "1.0.0",
        "runner_digest": DIGEST,
        "signer_id": "reviewer-1",
        "issuer": "external-review",
        "signature_receipt": _signature_receipt(),
        "scope_id": "scope-1",
        "candidate_digest": DIGEST,
        "installer_digest": DIGEST,
        "environment_digest": DIGEST,
        "command": ["python", "install.py"],
        "command_digest": canonical_digest(["python", "install.py"]),
        "raw_evidence": {"exit_code": 0, "readback_digest": DIGEST},
        "evidence_sha256": DIGEST,
        "started_at": STARTED_AT,
        "finished_at": FINISHED_AT,
        "fresh_until": "2026-11-16T01:01:00Z",
        "receipt_digest": DIGEST,
    }


def _knowledge_replay_receipt() -> dict:
    return {
        "schema_version": 1,
        "kind": "MUTATION",
        "runner_id": "runner-1",
        "runner_version": "1.0.0",
        "runner_digest": DIGEST,
        "signer_id": "reviewer-1",
        "issuer": "external-review",
        "signature_receipt": _signature_receipt(),
        "corpus_digest": DIGEST,
        "candidate_digest": DIGEST,
        "environment_digest": DIGEST,
        "tool_closure_digest": DIGEST,
        "pack_identity_digest": DIGEST,
        "requested_case_ids": ["case-1"],
        "raw_results": [
            {
                "case_id": "case-1",
                "outcome": "PASS",
                "raw_payload": {"assertion": "mutation killed"},
                "raw_result_digest": DIGEST,
            }
        ],
        "computed_counters": {
            "case_count": 1,
            "pass": 1,
            "fail": 0,
            "timeout": 0,
            "infra_error": 0,
            "unscored": 0,
            "missing": 0,
        },
        "redaction_receipt": {
            "policy_digest": DIGEST,
            "output_digest": DIGEST,
        },
        "started_at": STARTED_AT,
        "finished_at": FINISHED_AT,
        "receipt_digest": DIGEST,
    }


def _method_result(method_id: str) -> dict:
    return {
        "method_id": method_id,
        "method_version": "1.0.0",
        "result_digest": DIGEST,
        "facts": [
            {
                "semantic_key": "invariant:path:value",
                "semantic_fact_digest": DIGEST,
                "witness_refs": ["witness:1"],
            }
        ],
        "raw_status": "FINDING",
        "error": None,
    }


def _semantic_cell_result() -> dict:
    return {
        "schema_version": 1,
        "cell_id": "SKILL:FUNCTIONAL_FAULT:STATIC",
        "target_kind": "SKILL",
        "category_id": "FUNCTIONAL_FAULT",
        "evidence_plane": "STATIC",
        "terminal_state": "COVERED_BY_NATIVE_DETECTOR",
        "binding_id": "detector.functional",
        "binding_digest": DIGEST,
        "subject_digest": DIGEST,
        "scope_id": "scope-1",
        "fixture_ids": ["case-1"],
        "detector_result": _method_result("detector.functional"),
        "oracle_result": _method_result("oracle.functional"),
        "comparison": "AGREE",
        "semantic_fact_set_digest": DIGEST,
        "status": "FINDING",
        "failure_code": None,
        "resource_receipt": {"receipt_digest": DIGEST},
        "process_tree_receipt": {"receipt_digest": DIGEST},
        "network_guard_receipt": {"receipt_digest": DIGEST},
        "recorded_at": STARTED_AT,
        "receipt_digest": DIGEST,
    }


def _capability_matrix() -> dict:
    return {
        "schema_version": 2,
        "pack_digest": DIGEST,
        "runtime_registry_digest": DIGEST,
        "execution_schema_digest": DIGEST,
        "adapter_schema_digest": DIGEST,
        "fixture_archive_sha256": DIGEST,
        "fixture_member_manifest_digest": DIGEST,
        "fixture_definition_digest": DIGEST,
        "tool_identity_digests": [DIGEST],
        "runtime_closure_digests": [DIGEST],
        "environment_digest": DIGEST,
        "evaluator_digest": DIGEST,
        "certification_row_digest": DIGEST,
        "rows": [
            {
                "capability_slice_id": "SLICE-0123456789abcdef",
                "test_class": "positive",
                "status": "PASS",
                "fixture_member_id": "fixture/case",
                "fixture_tree_digest": DIGEST,
                "tool_identity_digest": DIGEST,
                "runtime_closure_digest": DIGEST,
                "command_digest": DIGEST,
                "semantic_assertion_digest": DIGEST,
                "raw_receipt": {"receipt_digest": DIGEST},
                "row_digest": DIGEST,
            }
        ],
        "row_count": 1,
        "failures": [],
        "status": "PASS",
        "matrix_digest": DIGEST,
    }


PAYLOADS = {
    "impact-graph.schema.json": _impact_graph,
    "domain-receipt.schema.json": _domain_receipt,
    "knowledge-replay-receipt.schema.json": _knowledge_replay_receipt,
    "semantic-cell-result.schema.json": _semantic_cell_result,
    "capability-matrix.schema.json": _capability_matrix,
}


@pytest.mark.parametrize("schema_name", sorted(PAYLOADS))
def test_controlplane_schemas_compile_and_accept_complete_receipts(
    schema_name: str,
) -> None:
    schema = _schema(schema_name)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    assert not list(validator.iter_errors(PAYLOADS[schema_name]()))


@pytest.mark.parametrize("schema_name", sorted(PAYLOADS))
def test_every_required_controlplane_field_is_enforced(schema_name: str) -> None:
    schema = _schema(schema_name)
    validator = Draft202012Validator(schema)
    payload = PAYLOADS[schema_name]()

    for field in schema["required"]:
        incomplete = copy.deepcopy(payload)
        incomplete.pop(field)
        assert list(validator.iter_errors(incomplete)), field


def test_domain_status_without_execution_evidence_is_rejected() -> None:
    validator = Draft202012Validator(_schema("domain-receipt.schema.json"))
    assert list(
        validator.iter_errors(
            {"schema_version": 1, "kind": "domain-receipt", "status": "VERIFIED"}
        )
    )


@pytest.mark.parametrize(
    "raw_results",
    [
        [],
        [
            {
                "case_id": "case-1",
                "outcome": "PASS",
                "raw_result_digest": DIGEST,
            }
        ],
    ],
)
def test_knowledge_replay_rejects_boolean_or_hash_only_evidence(
    raw_results: list[dict],
) -> None:
    validator = Draft202012Validator(
        _schema("knowledge-replay-receipt.schema.json")
    )
    receipt = _knowledge_replay_receipt()
    receipt["raw_results"] = raw_results
    assert list(validator.iter_errors(receipt))

    boolean_only = _knowledge_replay_receipt()
    boolean_only.pop("raw_results")
    boolean_only.pop("requested_case_ids")
    boolean_only["success"] = True
    assert list(validator.iter_errors(boolean_only))


def test_semantic_cell_cannot_use_boolean_coverage() -> None:
    validator = Draft202012Validator(
        _schema("semantic-cell-result.schema.json")
    )
    assert list(
        validator.iter_errors(
            {
                "schema_version": 1,
                "cell_id": "SKILL:FUNCTIONAL_FAULT:STATIC",
                "target_kind": "SKILL",
                "category_id": "FUNCTIONAL_FAULT",
                "evidence_plane": "STATIC",
                "coverage": True,
            }
        )
    )
    receipt = _semantic_cell_result()
    receipt["coverage"] = True
    assert list(validator.iter_errors(receipt))


@pytest.mark.parametrize(
    "field",
    [
        "scanner_coverage_digest",
        "scanner_coverage",
        "opaque_sources",
        "unsupported_sources",
        "graph_digest",
    ],
)
def test_impact_graph_requires_scanner_coverage_and_boundaries(field: str) -> None:
    validator = Draft202012Validator(_schema("impact-graph.schema.json"))
    graph = _impact_graph()
    graph.pop(field)
    assert list(validator.iter_errors(graph))


@pytest.mark.parametrize(
    "field",
    [
        "pack_digest",
        "runtime_registry_digest",
        "fixture_archive_sha256",
        "fixture_member_manifest_digest",
        "fixture_definition_digest",
        "tool_identity_digests",
        "runtime_closure_digests",
        "environment_digest",
        "evaluator_digest",
        "certification_row_digest",
        "rows",
        "failures",
        "status",
        "matrix_digest",
    ],
)
def test_capability_matrix_requires_complete_identity_and_rows(field: str) -> None:
    validator = Draft202012Validator(_schema("capability-matrix.schema.json"))
    matrix = _capability_matrix()
    matrix.pop(field)
    assert list(validator.iter_errors(matrix))


def test_fixture_identity_reuses_real_capabilities_and_is_immutable() -> None:
    slice_id = "SLICE-322b9b55b7d0b8fa"
    pack = capabilities.load_pack(slice_ids=[slice_id])
    manifest = pack["slices"][0]
    fixture = capabilities.load_fixtures()["slices"][slice_id]

    receipt = resolve_tool_runtime_fixture(
        manifest,
        manifest["command_template"],
        fixture,
        "positive",
    )

    assert isinstance(receipt, Mapping)
    assert receipt["version_identity"]["version_matches"] is True
    assert receipt["archive_identity"]["archive_sha256"]
    assert receipt["member_identity"]["tree_digest"]
    assert receipt["runtime_closure"]
    assert receipt["fixture_identity"]["selected_member"]
    with pytest.raises(TypeError):
        receipt["identity_digest"] = OTHER_DIGEST

    thawed = _thaw(receipt)
    material = dict(thawed)
    declared = material.pop("identity_digest")
    assert canonical_digest(material) == declared


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("archive_identity", "archive_sha256"), OTHER_DIGEST),
        (("member_identity", "selected_member"), "fixture/tampered"),
        (("tool_identity", "observed_version"), "0.0.0"),
        (("runtime_closure", 0, "sha256"), OTHER_DIGEST),
        (("argv",), ["tampered"]),
        (("fixture_identity", "selected_member_digest"), OTHER_DIGEST),
    ],
)
def test_fixture_identity_digest_changes_for_each_identity_class(
    path: tuple,
    value,
) -> None:
    slice_id = "SLICE-322b9b55b7d0b8fa"
    manifest = capabilities.load_pack(slice_ids=[slice_id])["slices"][0]
    fixture = capabilities.load_fixtures()["slices"][slice_id]
    receipt = _thaw(
        resolve_tool_runtime_fixture(
            manifest,
            manifest["command_template"],
            fixture,
            "positive",
        )
    )
    original = receipt["identity_digest"]
    target = receipt
    for part in path[:-1]:
        target = target[part]
    if len(path) == 1:
        receipt[path[0]] = value
    else:
        target[path[-1]] = value
    material = dict(receipt)
    material.pop("identity_digest")
    assert canonical_digest(material) != original
