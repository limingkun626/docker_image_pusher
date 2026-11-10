from __future__ import annotations

import hashlib
import json
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
    if name == "risk-ledger":
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
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
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


def assert_zero_open_risk(
    ledger: dict[str, Any],
    *,
    expected_candidate_digest: str | None = None,
) -> None:
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
