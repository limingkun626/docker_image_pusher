from __future__ import annotations

from collections.abc import Iterable

from .contracts import (
    CLOSED_FINDING_STATUSES,
    ContractError,
    canonical_digest,
    schema_digest,
    validate_contract,
    validate_risk_ledger_consistency,
)


def build_risk_ledger(
    *,
    scope_digest: str,
    required_sources: Iterable[str],
    findings: Iterable[dict[str, object]],
    observed_sources: Iterable[str] | None = None,
    present_sources: Iterable[str] | None = None,
    source_inventory: Iterable[dict[str, object]] | None = None,
) -> dict[str, object]:
    required = set(required_sources)
    inventory = list(source_inventory or ())
    if inventory:
        inventory_required: set[str] = set()
        inventory_observed: set[str] = set()
        for record in inventory:
            if set(record) != {"source_id", "locator", "sha256", "present"}:
                raise ContractError("source inventory record is incomplete")
            source_id = record["source_id"]
            locator = record["locator"]
            digest = record["sha256"]
            present = record["present"]
            if (
                not isinstance(source_id, str)
                or not source_id
                or not isinstance(locator, str)
                or not locator
                or not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                or not isinstance(present, bool)
            ):
                raise ContractError("source inventory record is invalid")
            if source_id in inventory_required:
                raise ContractError("source inventory contains duplicate source_id")
            inventory_required.add(source_id)
            if present:
                inventory_observed.add(source_id)
        if required != inventory_required:
            raise ContractError("required sources disagree with source inventory")
        if observed_sources is not None and set(observed_sources) != inventory_observed:
            raise ContractError("observed sources disagree with source inventory")
        if present_sources is not None and set(present_sources) != inventory_observed:
            raise ContractError("present sources disagree with source inventory")
        observed_sources = sorted(inventory_observed)
    sources = sorted(required)
    source_set = set(sources)
    if observed_sources is None and present_sources is None:
        raise ContractError("observed_sources is required")
    if (
        observed_sources is not None
        and present_sources is not None
        and set(observed_sources) != set(present_sources)
    ):
        raise ContractError("observed_sources and present_sources disagree")
    observed = sorted(
        set(observed_sources if observed_sources is not None else present_sources or ())
    )
    observed_set = set(observed)
    items = []
    for finding in findings:
        item = {"schema_version": 1, **finding}
        validate_contract("finding", item)
        items.append(item)
    risk_ids = [item["risk_id"] for item in items]
    if len(risk_ids) != len(set(risk_ids)):
        raise ContractError("duplicate risk_id in finding set")
    finding_sources = {str(item["source_id"]) for item in items}
    unsupported_finding_sources = sorted(finding_sources - source_set)
    if unsupported_finding_sources:
        raise ContractError(
            "unexpected finding source: " + ", ".join(unsupported_finding_sources)
        )

    # shortcut: CLI source-inventory wiring is outside this write set; zero-open blocks unbound ledgers.
    unbound_inventory = not inventory
    ledger: dict[str, object] = {
        "schema_version": 1,
        "scope_digest": scope_digest,
        "finding_schema_digest": schema_digest("finding"),
        "risk_ledger_schema_digest": schema_digest("risk-ledger"),
        "required_sources": sources,
        "required_sources_digest": canonical_digest(sources),
        "observed_sources": observed,
        "items": items,
        "open_count": sum(item["status"] == "OPEN" for item in items),
        "closed_count": sum(item["status"] in CLOSED_FINDING_STATUSES for item in items),
        "missing_sources": sorted(source_set - observed_set),
        "unexpected_sources": sorted(observed_set - source_set),
        "residual_risks": (
            ["UNBOUND_SOURCE_INVENTORY"] if unbound_inventory else []
        ),
        "unresolved_ids": (
            ["source-inventory:missing"] if unbound_inventory else []
        ),
    }
    ledger["ledger_digest"] = canonical_digest(ledger)
    validate_risk_ledger_consistency(ledger)
    return ledger
