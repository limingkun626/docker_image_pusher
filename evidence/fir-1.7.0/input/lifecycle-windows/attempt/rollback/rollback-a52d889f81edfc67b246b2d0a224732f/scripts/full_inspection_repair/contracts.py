from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

from .strict import StrictJSONError, strict_loads

REQUIRED_TAXONOMY_CATEGORIES = frozenset(
    {
        "FUNCTIONAL_FAULT",
        "RISK_EXPOSURE",
        "LATENT_DEFECT",
        "VULNERABILITY",
        "OMISSION",
        "INCONSISTENCY",
        "BOUNDARY",
        "EXCEPTION_PATH",
        "OTHER_DECLARED",
    }
)
CLOSED_FINDING_STATUSES = frozenset(
    {
        "FIXED",
        "FALSE_POSITIVE_WITH_PROOF",
        "PREVENTED_BY_VERIFIED_GUARD",
        "SUPERSEDED_BY_VERIFIED_CHANGE",
    }
)
SCHEMA_DIR = Path(__file__).resolve().parents[2] / "contracts"


class ContractError(ValueError):
    """Raised when a contract or closure invariant is not satisfied."""

    def __init__(self, message: str, code: str = "BLOCKED_EVIDENCE") -> None:
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def material_digest(payload: Mapping[str, Any], digest_field: str) -> str:
    material = dict(payload)
    material.pop(digest_field, None)
    return canonical_digest(material)


def dir_hash1(root: str | Path) -> str:
    """Return the in-toto dirHash1 value for a directory tree."""

    root_path = Path(root)
    if not root_path.is_dir():
        raise ContractError(f"directory tree does not exist: {root_path}")
    rows: list[str] = []
    for current, directories, files in os.walk(root_path, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in directories:
            if (current_path / name).is_symlink():
                raise ContractError(
                    f"directory tree contains a link: {(current_path / name).relative_to(root_path)}"
                )
        for name in files:
            path = current_path / name
            if path.is_symlink():
                raise ContractError(
                    f"directory tree contains a link: {path.relative_to(root_path)}"
                )
            relative = path.relative_to(root_path).as_posix()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            rows.append(f"{digest}  {relative}\n")
    payload = "".join(sorted(rows, key=lambda row: row[66:])).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def in_toto_statement(
    *,
    name: str,
    digest: str,
    predicate_type: str,
    predicate: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not name:
        raise ContractError("in-toto subject name is required")
    if not re_full_sha256(digest):
        raise ContractError("in-toto subject digest is invalid")
    if not predicate_type.startswith("https://"):
        raise ContractError("in-toto predicateType must be an HTTPS URI")
    statement: dict[str, Any] = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": name, "digest": {"sha256": digest}}],
        "predicateType": predicate_type,
    }
    if predicate is not None:
        statement["predicate"] = dict(predicate)
    return statement


def re_full_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _validate_material_digest(
    name: str,
    payload: dict[str, Any],
    field: str,
    *,
    code: str = "BLOCKED_EVIDENCE",
) -> None:
    if payload.get(field) != material_digest(payload, field):
        raise ContractError(f"{name}: {field} mismatch", code=code)


def _load_schema(name: str) -> dict[str, Any]:
    path = SCHEMA_DIR / f"{name}.schema.json"
    try:
        return strict_loads(path.read_bytes())
    except (OSError, StrictJSONError) as exc:
        raise ContractError(f"cannot load schema {name}: {exc}") from exc


def schema_digest(name: str) -> str:
    path = SCHEMA_DIR / f"{name}.schema.json"
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ContractError(f"cannot read schema {name}: {exc}") from exc


def _validator(name: str) -> Draft202012Validator:
    schema = _load_schema(name)
    registry = Registry()
    if "$id" in schema:
        registry = registry.with_resource(
            schema["$id"], Resource.from_contents(schema)
        )
    if name in {"risk-ledger", "risk-ledger-v2"}:
        finding = _load_schema("finding")
        registry = registry.with_resource(
            finding["$id"], Resource.from_contents(finding)
        )
    return Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FormatChecker(),
    )


def validate_contract(name: str, payload: dict[str, Any]) -> None:
    try:
        _validator(name).validate(payload)
    except ValidationError as exc:
        raise ContractError(f"{name}: {exc.message}") from exc

    date_fields = {
        "finding": ("closed_at",),
        "issue-observation": ("recorded_at",),
    }.get(name, ())
    for field in date_fields:
        value = payload.get(field)
        if value is None:
            continue
        try:
            text = str(value)
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ContractError(
                f"{name}: {field} is not an RFC3339 date-time: {exc}"
            ) from exc
        if parsed.tzinfo is None:
            raise ContractError(f"{name}: {field} must include a timezone")

    if name == "defect-taxonomy":
        missing = sorted(REQUIRED_TAXONOMY_CATEGORIES - set(payload["categories"]))
        if missing:
            raise ContractError(f"missing taxonomy categories: {', '.join(missing)}")


def _assert_binding(
    label: str,
    actual: object,
    expected: object,
    *,
    code: str = "BLOCKED_EVIDENCE",
) -> None:
    if expected is not None and actual != expected:
        raise ContractError(f"{label} mismatch: expected {expected}, found {actual}", code)


def _expected_value(expected: Any, key: str) -> Any:
    if expected is None:
        return None
    if isinstance(expected, Mapping):
        return expected.get(key)
    return getattr(expected, key, None)


def validate_run_manifest(
    manifest: dict[str, Any],
    *,
    expected: Any = None,
) -> None:
    validate_contract("run-manifest-v2", manifest)
    _validate_material_digest(
        "run-manifest-v2",
        manifest,
        "manifest_digest",
        code="BLOCKED_STALE_INPUT",
    )
    bindings = manifest["bindings"]
    for field in (
        "registry_digest",
        "taxonomy_policy_digest",
        "trust_policy_digest",
        "knowledge_pack_digest",
        "tool_closure_digest",
        "environment_digest",
        "config_digest",
    ):
        _assert_binding(
            f"run binding {field}",
            bindings[field],
            _expected_value(expected, field),
            code="BLOCKED_STALE_INPUT",
        )
    subject = manifest["subject"]
    _assert_binding(
        "run subject tree",
        subject["tree_digest"],
        _expected_value(expected, "subject_tree_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "run scope",
        manifest["scope_digest"],
        _expected_value(expected, "scope_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    candidate = _expected_value(expected, "candidate_digest")
    if candidate is not None:
        _assert_binding("run candidate", manifest["candidate_digest"], candidate)
    if (
        manifest["scope_digest"] == subject["tree_digest"]
        or (
            manifest["candidate_digest"] is not None
            and manifest["candidate_digest"] in {
                manifest["scope_digest"],
                subject["tree_digest"],
            }
        )
    ):
        raise ContractError(
            "run scope, source subject and candidate identities must be distinct"
        )


def validate_tool_closure(
    closure: dict[str, Any],
    *,
    expected_artifact_sha256: str | None = None,
) -> None:
    required = {
        "schema_version",
        "tool_id",
        "logical_name",
        "version",
        "platform",
        "artifact_sha256",
        "version_output_sha256",
        "argv_template",
        "rule_set_digest",
        "fixture_archive_digest",
        "license_digest",
        "closure_digest",
    }
    if not required.issubset(closure):
        raise ContractError("tool closure is incomplete", code="BLOCKED_ADAPTER")
    if closure["schema_version"] != 1:
        raise ContractError("unsupported tool closure version", code="BLOCKED_ADAPTER")
    for field in (
        "artifact_sha256",
        "version_output_sha256",
        "rule_set_digest",
        "fixture_archive_digest",
        "license_digest",
    ):
        if not re_full_sha256(closure.get(field)):
            raise ContractError(
                f"tool closure {field} is invalid", code="BLOCKED_ADAPTER"
            )
    argv = closure.get("argv_template")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) for item in argv)
    ):
        raise ContractError("tool closure argv_template is invalid", code="BLOCKED_ADAPTER")
    if expected_artifact_sha256 is not None:
        _assert_binding(
            "tool artifact",
            closure["artifact_sha256"],
            expected_artifact_sha256,
            code="BLOCKED_ADAPTER",
        )
    _validate_material_digest(
        "tool-closure",
        closure,
        "closure_digest",
        code="BLOCKED_ADAPTER",
    )


def validate_execution_receipt(
    receipt: dict[str, Any],
    *,
    expected: Any = None,
    tool_closures: Mapping[str, dict[str, Any]] | None = None,
) -> None:
    validate_contract("execution-receipt-v3", receipt)
    _validate_material_digest(
        "execution-receipt-v3", receipt, "receipt_digest"
    )
    execution = receipt["execution"]
    if execution["parse_status"] == "MALFORMED":
        raise ContractError("execution receipt is malformed", code="BLOCKED_DETECTOR")
    network = receipt["network"]
    if network["enforced"] and not (
        network["backend"] not in {"none", ""}
        and network["namespace_or_job_identity"]
        and re_full_sha256(network["canary_receipt_digest"])
    ):
        raise ContractError(
            "network enforcement lacks backend, identity or canary evidence",
            code="BLOCKED_ADAPTER",
        )
    if receipt["process_tree"]["descendants_remaining"]:
        raise ContractError(
            "execution receipt has live descendants", code="BLOCKED_EVIDENCE"
        )
    if not receipt["process_tree"]["empty_verified"]:
        raise ContractError(
            "execution receipt does not prove process cleanup",
            code="BLOCKED_EVIDENCE",
        )
    if not network["cleanup_verified"]:
        raise ContractError(
            "execution receipt does not prove network cleanup",
            code="BLOCKED_EVIDENCE",
        )
    tool = receipt["tool"]
    closure_digest = tool["closure_digest"]
    if tool_closures is not None:
        closure = tool_closures.get(receipt["binding_id"])
        if closure is None:
            raise ContractError("tool closure is missing", code="BLOCKED_ADAPTER")
        if closure.get("closure_digest") != closure_digest:
            raise ContractError(
                "execution receipt tool closure was substituted",
                code="BLOCKED_ADAPTER",
            )
    _assert_binding(
        "receipt run",
        receipt["run_id"],
        _expected_value(expected, "run_id"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "receipt candidate",
        receipt["subject"]["candidate_digest"],
        _expected_value(expected, "candidate_digest"),
    )
    _assert_binding(
        "receipt subject",
        receipt["subject"]["tree_digest"],
        _expected_value(expected, "subject_tree_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "receipt environment",
        execution["environment_digest"],
        _expected_value(expected, "environment_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "receipt rule set",
        execution["rule_set_digest"],
        _expected_value(expected, "rule_set_digest"),
        code="BLOCKED_STALE_INPUT",
    )


def validate_evidence_fact(
    fact: dict[str, Any],
    *,
    expected: Any = None,
) -> None:
    validate_contract("evidence-fact-v2", fact)
    _validate_material_digest("evidence-fact-v2", fact, "fact_digest")
    locator = fact["locator"]
    if locator["start_byte"] > locator["end_byte"]:
        raise ContractError("evidence fact byte span is reversed")
    _assert_binding(
        "evidence run", fact["run_id"], _expected_value(expected, "run_id"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "evidence candidate",
        fact["candidate_digest"],
        _expected_value(expected, "candidate_digest"),
    )
    _assert_binding(
        "evidence subject",
        fact["subject_digest"],
        _expected_value(expected, "subject_tree_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "evidence registry",
        fact["registry_digest"],
        _expected_value(expected, "registry_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "evidence policy",
        fact["policy_digest"],
        _expected_value(expected, "policy_digest"),
        code="BLOCKED_STALE_INPUT",
    )


def build_run_manifest(
    *,
    run_id: str,
    scope_id: str,
    scope_digest: str,
    platform: str,
    subject_manifest_digest: str,
    subject_tree_digest: str,
    subject_dir_hash1: str,
    logical_identity: str,
    bindings: Mapping[str, str],
    repair_plan_digest: str | None = None,
    candidate_digest: str | None = None,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": 2,
        "run_id": run_id,
        "scope_id": scope_id,
        "scope_digest": scope_digest,
        "platform": platform,
        "subject": {
            "manifest_digest": subject_manifest_digest,
            "tree_digest": subject_tree_digest,
            "dir_hash1": subject_dir_hash1,
            "logical_identity": logical_identity,
        },
        "bindings": dict(bindings),
        "repair_plan_digest": repair_plan_digest,
        "candidate_digest": candidate_digest,
    }
    manifest["manifest_digest"] = material_digest(manifest, "manifest_digest")
    validate_run_manifest(manifest)
    return manifest


def build_evidence_fact(
    *,
    run_id: str,
    cell_id: str,
    invariant_id: str,
    defect_class_id: str,
    subject_digest: str,
    candidate_digest: str | None,
    policy_digest: str,
    registry_digest: str,
    locator: Mapping[str, Any],
    predicate: str,
    value: Any,
    witness_refs: Iterable[str],
    method_id: str,
    method_version: str,
    producer_receipt_digest: str,
    terminal_observation: str,
) -> dict[str, Any]:
    fact: dict[str, Any] = {
        "schema_version": 2,
        "run_id": run_id,
        "cell_id": cell_id,
        "invariant_id": invariant_id,
        "defect_class_id": defect_class_id,
        "subject_digest": subject_digest,
        "candidate_digest": candidate_digest,
        "policy_digest": policy_digest,
        "registry_digest": registry_digest,
        "locator": dict(locator),
        "predicate": predicate,
        "value": value,
        "witness_refs": list(witness_refs),
        "method_id": method_id,
        "method_version": method_version,
        "producer_receipt_digest": producer_receipt_digest,
        "terminal_observation": terminal_observation,
    }
    fact["fact_id"] = semantic_digest(fact)
    fact["fact_digest"] = material_digest(fact, "fact_digest")
    validate_evidence_fact(fact)
    return fact


def build_execution_receipt(
    *,
    run_id: str,
    receipt_kind: str,
    cell_id: str,
    binding_id: str,
    tool_closure_digest: str,
    subject_tree_digest: str,
    candidate_digest: str | None,
    snapshot_digest: str,
    execution: Mapping[str, Any],
    resources: Mapping[str, Any],
    process_tree: Mapping[str, Any],
    network: Mapping[str, Any],
    facts: Iterable[Mapping[str, Any]] = (),
    terminal_status: str,
    failure_code: str | None = None,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "schema_version": 3,
        "run_id": run_id,
        "receipt_kind": receipt_kind,
        "cell_id": cell_id,
        "binding_id": binding_id,
        "tool": {"closure_digest": tool_closure_digest},
        "subject": {
            "tree_digest": subject_tree_digest,
            "candidate_digest": candidate_digest,
            "snapshot_digest": snapshot_digest,
        },
        "execution": dict(execution),
        "resources": dict(resources),
        "process_tree": dict(process_tree),
        "network": dict(network),
        "facts": [
            {
                "fact_id": item["fact_id"],
                "fact_digest": item["fact_digest"],
            }
            for item in facts
        ],
        "terminal_status": terminal_status,
        "failure_code": failure_code,
    }
    receipt["receipt_id"] = canonical_digest(receipt)
    receipt["receipt_digest"] = material_digest(receipt, "receipt_digest")
    validate_execution_receipt(receipt)
    return receipt


def semantic_witness(
    *,
    cell_id: str,
    defect_class_id: str,
    invariant_id: str,
    primary_locator: Mapping[str, Any],
    normalized_evidence: Mapping[str, Any],
    supporting_locators: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    witness: dict[str, Any] = {
        "schema_version": 1,
        "cell_id": cell_id,
        "defect_class_id": defect_class_id,
        "invariant_id": invariant_id,
        "primary_locator": dict(primary_locator),
        "normalized_evidence": dict(normalized_evidence),
        "supporting_locators": [dict(item) for item in supporting_locators],
    }
    witness["semantic_digest"] = semantic_digest(witness)
    return witness


def semantic_digest(witness: Mapping[str, Any]) -> str:
    return canonical_digest(
        {
            "cell_id": witness.get("cell_id"),
            "defect_class_id": witness.get("defect_class_id"),
            "invariant_id": witness.get("invariant_id"),
            "primary_locator": witness.get("primary_locator"),
            "normalized_evidence": witness.get("normalized_evidence"),
        }
    )


def validate_candidate_binding(
    payload: Mapping[str, Any],
    *,
    candidate_digest: str,
    subject_digest: str | None = None,
    scope_digest: str | None = None,
) -> None:
    _assert_binding("candidate binding", payload.get("candidate_digest"), candidate_digest)
    _assert_binding(
        "subject binding",
        payload.get("subject_digest"),
        subject_digest,
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "scope binding",
        payload.get("scope_digest"),
        scope_digest,
        code="BLOCKED_STALE_INPUT",
    )


def validate_policy_binding(
    payload: Mapping[str, Any],
    *,
    policy_digest: str,
    field: str = "policy_digest",
) -> None:
    _assert_binding(
        "policy binding",
        payload.get(field),
        policy_digest,
        code="BLOCKED_STALE_INPUT",
    )


dirhash1 = dir_hash1
build_in_toto_statement = in_toto_statement


def validate_candidate_manifest(
    manifest: dict[str, Any],
    *,
    expected: Any = None,
) -> None:
    validate_contract("candidate-manifest-v2", manifest)
    _validate_material_digest(
        "candidate-manifest-v2",
        manifest,
        "candidate_manifest_digest",
    )
    _assert_binding(
        "candidate base subject",
        manifest["base_subject_digest"],
        _expected_value(expected, "subject_tree_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "candidate binding",
        manifest["candidate_digest"],
        _expected_value(expected, "candidate_digest"),
    )
    _assert_binding(
        "candidate repair plan",
        manifest["repair_plan_digest"],
        _expected_value(expected, "repair_plan_digest"),
        code="BLOCKED_REPAIR_PLAN",
    )


def validate_source_inventory(
    inventory: dict[str, Any],
    *,
    expected: Any = None,
) -> None:
    required = {
        "schema_version",
        "run_id",
        "scope_digest",
        "subject_digest",
        "candidate_digest",
        "policy_digest",
        "sources",
        "inventory_digest",
    }
    if set(inventory) != required:
        raise ContractError("source inventory is incomplete")
    if inventory["schema_version"] != 2:
        raise ContractError("unsupported source inventory version")
    _validate_material_digest("source-inventory-v2", inventory, "inventory_digest")
    _assert_binding(
        "source inventory scope",
        inventory["scope_digest"],
        _expected_value(expected, "scope_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "source inventory subject",
        inventory["subject_digest"],
        _expected_value(expected, "subject_tree_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "source inventory candidate",
        inventory["candidate_digest"],
        _expected_value(expected, "candidate_digest"),
    )
    _assert_binding(
        "source inventory policy",
        inventory["policy_digest"],
        _expected_value(expected, "policy_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    seen: set[str] = set()
    for source in inventory["sources"]:
        source_id = source.get("source_id")
        if not source_id or source_id in seen:
            raise ContractError("source inventory has missing or duplicate source_id")
        seen.add(source_id)
        applicability = source.get("applicability")
        if applicability == "NOT_APPLICABLE_WITH_PROOF":
            if not source.get("proof_ref") or not source.get("policy_digest"):
                raise ContractError("source N/A lacks a policy-bound proof")
        elif applicability not in {"APPLICABLE", "REQUIRED_MISSING"}:
            raise ContractError("source inventory has an unknown applicability")


def validate_risk_ledger_consistency(ledger: dict[str, Any]) -> None:
    validate_contract("risk-ledger", ledger)
    items = ledger["items"]
    derived_open = sum(item["status"] == "OPEN" for item in items)
    derived_closed = sum(item["status"] in CLOSED_FINDING_STATUSES for item in items)
    if ledger["open_count"] != derived_open:
        raise ContractError(
            f"open_count mismatch: declared={ledger['open_count']} actual={derived_open}"
        )
    if ledger["closed_count"] != derived_closed:
        raise ContractError(
            f"closed_count mismatch: declared={ledger['closed_count']} actual={derived_closed}"
        )
    required = list(ledger["required_sources"])
    observed = list(ledger["observed_sources"])
    required_set = set(required)
    observed_set = set(observed)
    if ledger["required_sources_digest"] != canonical_digest(sorted(required_set)):
        raise ContractError("required_sources_digest mismatch")
    if ledger["finding_schema_digest"] != schema_digest("finding"):
        raise ContractError("finding_schema_digest mismatch")
    if ledger["risk_ledger_schema_digest"] != schema_digest("risk-ledger"):
        raise ContractError("risk_ledger_schema_digest mismatch")
    missing = sorted(required_set - observed_set)
    unexpected = sorted(observed_set - required_set)
    if ledger["missing_sources"] != missing:
        raise ContractError("missing_sources mismatch")
    if ledger["unexpected_sources"] != unexpected:
        raise ContractError("unexpected_sources mismatch")
    finding_sources = {str(item["source_id"]) for item in items}
    if not finding_sources.issubset(required_set):
        raise ContractError("finding source is not in the required source set")
    declared_digest = ledger["ledger_digest"]
    material = dict(ledger)
    material.pop("ledger_digest")
    if declared_digest != canonical_digest(material):
        raise ContractError("ledger_digest mismatch")


def validate_risk_ledger_v2(
    ledger: dict[str, Any],
    *,
    expected: Any = None,
) -> None:
    validate_contract("risk-ledger-v2", ledger)
    material = dict(ledger)
    material.pop("ledger_digest", None)
    if ledger["ledger_digest"] != canonical_digest(material):
        raise ContractError("v2 ledger_digest mismatch")
    _assert_binding(
        "ledger run",
        ledger["run_id"],
        _expected_value(expected, "run_id"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "ledger scope",
        ledger["scope_digest"],
        _expected_value(expected, "scope_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "ledger subject",
        ledger["subject_digest"],
        _expected_value(expected, "subject_tree_digest"),
        code="BLOCKED_STALE_INPUT",
    )
    _assert_binding(
        "ledger candidate",
        ledger["candidate_digest"],
        _expected_value(expected, "candidate_digest"),
    )
    if len({
        ledger["scope_digest"],
        ledger["subject_digest"],
        ledger["candidate_digest"],
    }) != 3:
        raise ContractError("ledger identity fields must be distinct")
    items = ledger["items"]
    derived_open = sum(item["status"] == "OPEN" for item in items)
    derived_closed = sum(item["status"] in CLOSED_FINDING_STATUSES for item in items)
    if ledger["open_count"] != derived_open:
        raise ContractError("v2 ledger open_count mismatch")
    if ledger["closed_count"] != derived_closed:
        raise ContractError("v2 ledger closed_count mismatch")
    required = set(ledger["required_sources"])
    observed = set(ledger["observed_sources"])
    if ledger["required_sources_digest"] != canonical_digest(sorted(required)):
        raise ContractError("v2 ledger required_sources_digest mismatch")
    if ledger["missing_sources"] != sorted(required - observed):
        raise ContractError("v2 ledger missing_sources mismatch")
    if ledger["unexpected_sources"] != sorted(observed - required):
        raise ContractError("v2 ledger unexpected_sources mismatch")
    open_ids = sorted(
        str(item["risk_id"]) for item in items if item["status"] == "OPEN"
    )
    expected_unresolved = sorted(
        open_ids
        + [f"source:{source_id}" for source_id in ledger["missing_sources"]]
    )
    if sorted(str(item) for item in ledger["unresolved_ids"]) != expected_unresolved:
        raise ContractError("v2 unresolved_ids are not derived from open findings")
    residual = sorted(
        str(item["risk_id"])
        for item in items
        if item.get("residual_risk") is not None
    )
    if sorted(str(item) for item in ledger["residual_risks"]) != residual:
        raise ContractError("v2 residual_risks are not derived from findings")


def assert_zero_open_risk(
    ledger: dict[str, Any],
    *,
    expected_candidate_digest: str | None = None,
) -> None:
    if ledger.get("schema_version") == 2:
        validate_risk_ledger_v2(
            ledger,
            expected={"candidate_digest": expected_candidate_digest}
            if expected_candidate_digest is not None
            else None,
        )
    else:
        validate_risk_ledger_consistency(ledger)
    open_items = [item["risk_id"] for item in ledger["items"] if item["status"] == "OPEN"]
    if open_items:
        raise ContractError(f"open findings: {', '.join(open_items)}")
    for field in ("missing_sources", "unexpected_sources", "residual_risks", "unresolved_ids"):
        if ledger[field]:
            raise ContractError(f"zero-open-risk violation: {field} must be empty")
    for item in ledger["items"]:
        if item["status"] not in CLOSED_FINDING_STATUSES:
            raise ContractError(f"finding is not terminally closed: {item['risk_id']}")
        for field in ("evidence_refs", "closed_by", "closed_at", "verification_check"):
            if not item[field]:
                raise ContractError(
                    f"finding {item['risk_id']} lacks closure field {field}"
                )
        if item["residual_risk"] is not None:
            raise ContractError(f"finding {item['risk_id']} retains residual risk")
        verification_check = str(item["verification_check"]).lower()
        if any(
            marker in verification_check
            for marker in ("not-run", "not_run", "pending", "unknown")
        ):
            raise ContractError(
                f"finding {item['risk_id']} closure has no executed verification"
            )
        if item["evidence_sha256"] != item["closed_by"]:
            raise ContractError(
                f"finding {item['risk_id']} evidence digest is not closure-bound"
            )
        if not any(
            reference.startswith(("candidate:", "evidence:", "receipt:"))
            for reference in item["evidence_refs"]
        ):
            raise ContractError(
                f"finding {item['risk_id']} lacks closure evidence"
            )
        if (
            expected_candidate_digest is not None
            and item["closed_by"] != expected_candidate_digest
        ):
            raise ContractError(
                f"finding {item['risk_id']} closure is bound to a different candidate"
            )
        candidate_refs = {
            reference.removeprefix("candidate:")
            for reference in item["evidence_refs"]
            if reference.startswith("candidate:")
        }
        if candidate_refs and candidate_refs != {item["closed_by"]}:
            raise ContractError(
                f"finding {item['risk_id']} evidence candidate does not match closure"
            )


def gate_finding_projection(ledger: dict[str, Any]) -> list[dict[str, Any]]:
    """Project ledger rows into the gate's explicit ID vocabulary."""

    validate_risk_ledger_consistency(ledger)
    projected: list[dict[str, Any]] = []
    for item in ledger["items"]:
        finding_id = str(item["risk_id"])
        if not finding_id or finding_id == "UNKNOWN":
            raise ContractError("finding identity is empty or UNKNOWN")
        row = dict(item)
        row["finding_id"] = finding_id
        projected.append(row)
    finding_ids = [row["finding_id"] for row in projected]
    if len(finding_ids) != len(set(finding_ids)):
        raise ContractError("duplicate finding identity projection")
    return projected


def gate_receipt_digest(gate: dict[str, Any]) -> str:
    material = dict(gate)
    material.pop("gate_digest", None)
    return canonical_digest(material)


def validate_gate_receipt(gate: dict[str, Any]) -> None:
    if gate.get("status") != "PASS" or gate.get("release_ready") is not True:
        raise ContractError("gate is not a PASS receipt")
    if gate.get("gate_digest") != gate_receipt_digest(gate):
        raise ContractError("gate_digest mismatch")
