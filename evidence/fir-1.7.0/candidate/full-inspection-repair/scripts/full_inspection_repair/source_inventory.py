from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from .adapters import AdapterError, Subject
from .contracts import ContractError, canonical_digest, canonical_json
from .file_classes import classify_file
from .taxonomy import EVIDENCE_PLANES

SOURCE_TYPES = (
    "RESOURCE",
    "CLAIM",
    "INVARIANT",
    "PLANE",
    "BEHAVIOR",
    "RUNTIME",
    "LIFECYCLE",
    "EXTERNAL",
)
TERMINAL_STATUSES = frozenset(
    {
        "SATISFIED",
        "NOT_APPLICABLE_WITH_PROOF",
        "UNSUPPORTED",
        "UNCOVERED",
        "BLOCKED",
    }
)
SATISFYING_TERMINAL_STATUSES = frozenset(
    {"SATISFIED", "NOT_APPLICABLE_WITH_PROOF"}
)

_INVARIANTS = (
    "INV-SCOPE-FROZEN",
    "INV-CENSUS-COMPLETE",
    "INV-MATRIX-COMPLETE",
    "INV-NO-AUTO-REENTRY",
    "INV-JOURNAL-DURABLE",
    "INV-RELEASE-AUTHORITY-BOUNDARY",
    "INV-IMPACT-CLOSED",
    "INV-CANDIDATE-BOUND",
)
_BEHAVIORS = (
    "check",
    "repair",
    "capabilities.validate",
    "capabilities.run",
    "capabilities.matrix",
    "package",
    "review",
    "claim",
    "install",
    "build-taxonomy",
)
_RUNTIME = (
    "python>=3.12",
    "supported-operating-systems",
    "runtime-dependencies",
    "sandbox-backend",
)
_LIFECYCLE = (
    "fresh-install",
    "upgrade",
    "repeat-install",
    "interrupted-install-recovery",
    "rollback",
    "post-install-readback",
)
_EXTERNAL = (
    "python-interpreter",
    "jsonschema",
    "pyyaml",
    "pytest",
    "cryptography",
    "sigstore-verifier",
)


class SourceInventoryError(AdapterError, ContractError):
    """Raised when the frozen source denominator or its closure is invalid."""


def _locator_digest(locator: str) -> str:
    return hashlib.sha256(locator.encode("utf-8")).hexdigest()


def _observed_ranges(content: bytes | None) -> list[dict[str, int]]:
    if content is None:
        return []
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return []
    return [{"start_byte": 0, "end_byte": len(content)}]


def _raw_projection(item: Any) -> dict[str, Any] | None:
    if item.content.decode("utf-8", errors="ignore").encode("utf-8") == item.content:
        return None
    return {
        "size": item.size,
        "sha256": item.sha256,
        "projection": "raw-byte-hash-no-text-interpretation",
    }


def _row(
    *,
    source_type: str,
    suffix: str,
    locator: str,
    producer_id: str,
    producer_version: str,
    producer_digest: str,
    subject_digest: str,
    applicability: str = "APPLICABLE",
    proof_ref: str | None = None,
    observed_ranges: list[dict[str, int]] | None = None,
    raw_projection: dict[str, Any] | None = None,
    discovery_method: str = "adapter-skill",
    origin: str = "target",
    **typed: Any,
) -> dict[str, Any]:
    if source_type not in SOURCE_TYPES:
        raise SourceInventoryError(f"unknown source type: {source_type}")
    material: dict[str, Any] = {
        "schema_version": 2,
        "source_id": (
            f"source:{suffix}"
            if source_type == "RESOURCE"
            else f"{source_type.casefold()}:{suffix}"
        ),
        "source_type": source_type,
        "locator": locator,
        "locator_sha256": _locator_digest(locator),
        "discovery_method": discovery_method,
        "origin": origin,
        "observed_ranges": observed_ranges or [],
        "raw_projection": raw_projection,
        "applicability": applicability,
        "proof_ref": proof_ref,
        "producer": {
            "id": producer_id,
            "version": producer_version,
            "digest": producer_digest,
        },
        "subject_digest": subject_digest,
    }
    material.update(typed)
    material["obligation_digest"] = canonical_digest(material)
    return material


def _frontmatter_claims(text: str) -> list[tuple[str, str]]:
    if not text.startswith("---"):
        return []
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return []
    claims: list[tuple[str, str]] = []
    for line in lines[1:]:
        if line.strip() == "---":
            break
        match = re.match(r"^([A-Za-z][A-Za-z0-9_-]*):\s*(.*?)\s*$", line)
        if match:
            claims.append((match.group(1), match.group(2).strip()))
    return claims


def _skill_claims(subject: Subject) -> list[tuple[str, str, bytes]]:
    skill = next((item for item in subject.files if item.locator == "SKILL.md"), None)
    if skill is None:
        return []
    text = skill.content.decode("utf-8", errors="replace")
    claims = [
        (f"frontmatter.{key}", value, skill.content)
        for key, value in _frontmatter_claims(text)
    ]
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip(" -*\t")
        if re.search(r"\b(must|required|requires|only|supports?|not claimed)\b", stripped, re.I):
            claims.append((f"normative.line-{number}", stripped, skill.content))
    return claims


def build_source_inventory(
    subject: Subject,
    *,
    candidate_digest: str | None = None,
    registry_snapshot: Any | None = None,
) -> dict[str, Any]:
    if subject.subject_kind != "SKILL":
        raise SourceInventoryError(
            f"no source inventory producer for {subject.subject_kind}"
        )
    producer_id = "skill-source-adapter"
    producer_version = "2.0.0"
    producer_digest = canonical_digest(
        {
            "producer": producer_id,
            "version": producer_version,
            "subject_kind": "SKILL",
        }
    )
    rows: list[dict[str, Any]] = []
    for item in subject.files:
        classification = classify_file(item.locator, item.content)
        rows.append(
            _row(
                source_type="RESOURCE",
                suffix=item.locator,
                locator=item.locator,
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
                observed_ranges=_observed_ranges(item.content),
                raw_projection=_raw_projection(item),
                file_class=classification["file_class"],
                scanner_ids=classification["scanner_ids"],
                coverage_status=classification["coverage_status"],
                sha256=item.sha256,
                size=item.size,
            )
        )
    present = {item.locator for item in subject.files}
    if "SKILL.md" not in present:
        rows.append(
            _row(
                source_type="RESOURCE",
                suffix="SKILL.md",
                locator="SKILL.md",
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
                applicability="REQUIRED_MISSING",
            )
        )
    for directory in subject.directories:
        locator = str(
            directory.get("relative_path")
            or directory.get("locator")
            or directory.get("path")
            or ""
        ).replace("\\", "/")
        if not locator or locator == ".":
            continue
        classification = classify_file(locator, is_directory=True)
        rows.append(
            _row(
                source_type="RESOURCE",
                suffix=locator,
                locator=locator,
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
                discovered_kind="DIRECTORY",
                file_class=classification["file_class"],
                coverage_status=classification["coverage_status"],
            )
        )

    for key, text, content in _skill_claims(subject):
        locator = f"SKILL.md#{key}"
        rows.append(
            _row(
                source_type="CLAIM",
                suffix=locator,
                locator=locator,
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
                observed_ranges=_observed_ranges(content),
                claim_text_digest=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                normalization_version="1.0.0",
            )
        )
    if not any(row["source_type"] == "CLAIM" for row in rows):
        proof = canonical_digest(
            {
                "target_kind": "SKILL",
                "missing": "declared-claims",
                "source_inventory_producer": producer_digest,
                "subject_digest": subject.tree_digest,
            }
        )
        rows.append(
            _row(
                source_type="CLAIM",
                suffix="not-present",
                locator="SKILL.md#claims",
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
                applicability="NOT_APPLICABLE_WITH_PROOF",
                proof_ref=proof,
                missing_condition="NO_DECLARED_CLAIMS",
            )
        )

    for invariant_id in _INVARIANTS:
        rows.append(
            _row(
                source_type="INVARIANT",
                suffix=invariant_id,
                locator=f"registry:invariant:{invariant_id}",
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
                origin="runtime-registry",
            )
        )
    for plane in EVIDENCE_PLANES:
        rows.append(
            _row(
                source_type="PLANE",
                suffix=plane,
                locator=f"registry:plane:SKILL:{plane}",
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
                evidence_plane=plane,
            )
        )
    for behavior in _BEHAVIORS:
        rows.append(
            _row(
                source_type="BEHAVIOR",
                suffix=behavior,
                locator=f"behavior:{behavior}",
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
            )
        )
    for runtime in _RUNTIME:
        rows.append(
            _row(
                source_type="RUNTIME",
                suffix=runtime,
                locator=f"runtime:{runtime}",
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
            )
        )
    for lifecycle in _LIFECYCLE:
        rows.append(
            _row(
                source_type="LIFECYCLE",
                suffix=lifecycle,
                locator=f"lifecycle:{lifecycle}",
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
            )
        )
    for external in _EXTERNAL:
        rows.append(
            _row(
                source_type="EXTERNAL",
                suffix=external,
                locator=f"external:{external}",
                producer_id=producer_id,
                producer_version=producer_version,
                producer_digest=producer_digest,
                subject_digest=subject.tree_digest,
                origin="runtime-registry",
            )
        )

    rows.sort(key=lambda item: (SOURCE_TYPES.index(item["source_type"]), item["source_id"]))
    ids = [item["source_id"] for item in rows]
    if len(ids) != len(set(ids)):
        raise SourceInventoryError("source inventory contains duplicate source IDs")
    present_types = {item["source_type"] for item in rows}
    missing_types = sorted(set(SOURCE_TYPES) - present_types)
    if missing_types:
        raise SourceInventoryError(
            "source inventory misses required types: " + ", ".join(missing_types)
        )
    inventory: dict[str, Any] = {
        "schema_version": 2,
        "subject_digest": subject.tree_digest,
        "candidate_digest": candidate_digest,
        "producer_id": producer_id,
        "producer_version": producer_version,
        "producer_digest": producer_digest,
        "runtime_registry_digest": (
            registry_snapshot.registry_digest
            if registry_snapshot is not None
            else None
        ),
        "sources": rows,
    }
    inventory["source_denominator_digest"] = canonical_digest(rows)
    inventory["source_inventory_digest"] = canonical_digest(inventory)
    return inventory


def build_required_sources_v2(
    subject: Subject,
    *,
    candidate_digest: str | None = None,
    registry_snapshot: Any | None = None,
) -> dict[str, Any]:
    return build_source_inventory(
        subject,
        candidate_digest=candidate_digest,
        registry_snapshot=registry_snapshot,
    )


def build_source_closure(
    inventory: Mapping[str, Any],
    *,
    scope_id: str = "scope:current",
    evidence: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    declared = inventory.get("source_inventory_digest")
    material = {key: value for key, value in inventory.items() if key != "source_inventory_digest"}
    if declared != canonical_digest(material):
        raise SourceInventoryError("source inventory digest mismatch")
    sources = inventory.get("sources")
    if not isinstance(sources, list) or not sources:
        raise SourceInventoryError("source inventory must be non-empty")
    evidence = evidence or {}
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source in sources:
        if source.get("source_type") not in SOURCE_TYPES:
            raise SourceInventoryError(
                f"unknown source type: {source.get('source_type')}"
            )
        source_id = str(source["source_id"])
        if source_id in seen:
            raise SourceInventoryError(f"duplicate source closure row: {source_id}")
        seen.add(source_id)
        supplied = evidence.get(source_id, {})
        if source.get("applicability") == "REQUIRED_MISSING":
            status = "BLOCKED"
            refs = [str(source["obligation_digest"])]
            reason = "REQUIRED_SOURCE_MISSING"
        elif source.get("applicability") == "NOT_APPLICABLE_WITH_PROOF":
            status = "NOT_APPLICABLE_WITH_PROOF"
            refs = [str(source.get("proof_ref") or "")]
            reason = None
        else:
            status = str(supplied.get("terminal_status", "UNCOVERED"))
            refs = list(supplied.get("evidence_refs", []))
            reason = supplied.get(
                "unsupported_reason",
                None if supplied else "EVIDENCE_NOT_SUPPLIED",
            )
        receipts = {
            str(item.get("evidence_ref")): item
            for item in supplied.get("receipts", [])
            if isinstance(item, Mapping)
        }
        if status in SATISFYING_TERMINAL_STATUSES and source.get(
            "applicability"
        ) == "APPLICABLE":
            unresolved = [
                str(ref)
                for ref in refs
                if str(ref) not in receipts
                or receipts[str(ref)].get("receipt_digest")
                != canonical_digest(
                    {
                        key: value
                        for key, value in receipts[str(ref)].items()
                        if key != "receipt_digest"
                    }
                )
                or receipts[str(ref)].get("source_id") != source_id
                or receipts[str(ref)].get("scope_id") != scope_id
                or receipts[str(ref)].get("subject_digest")
                != inventory["subject_digest"]
                or receipts[str(ref)].get("candidate_digest")
                != inventory.get("candidate_digest")
                or receipts[str(ref)].get("runtime_registry_digest")
                != inventory.get("runtime_registry_digest")
            ]
            if unresolved:
                status = "BLOCKED"
                reason = "EVIDENCE_UNRESOLVED"
        if status not in TERMINAL_STATUSES:
            raise SourceInventoryError(f"invalid source terminal status: {status}")
        if status in SATISFYING_TERMINAL_STATUSES and not all(refs):
            raise SourceInventoryError(f"source closure lacks proof: {source_id}")
        records.append(
            {
                "source_id": source_id,
                "source_type": source["source_type"],
                "locator": source["locator"],
                "applicability": source["applicability"],
                "terminal_status": status,
                "evidence_refs": refs,
                "evidence_sha256": canonical_digest(
                    {"source": source, "supplied": supplied, "status": status}
                ),
                "evidence_method_id": str(
                    supplied.get("evidence_method_id", "source-scanner")
                ),
                "evidence_method_version": str(
                    supplied.get("evidence_method_version", "1.0.0")
                ),
                "evidence_receipts": [
                    receipts[ref] for ref in refs if ref in receipts
                ],
                "unsupported_reason": reason,
                "proof_ref": source.get("proof_ref"),
            }
        )
    closure: dict[str, Any] = {
        "schema_version": 1,
        "scope_id": scope_id,
        "subject_digest": inventory["subject_digest"],
        "candidate_digest": inventory.get("candidate_digest"),
        "runtime_registry_digest": inventory.get("runtime_registry_digest"),
        "source_denominator_digest": inventory["source_denominator_digest"],
        "source_count": len(records),
        "terminal_count": sum(
            item["terminal_status"] in SATISFYING_TERMINAL_STATUSES for item in records
        ),
        "records": records,
        "coverage_boundary_digest": canonical_digest(
            [
                {
                    "source_id": item["source_id"],
                    "status": item["terminal_status"],
                    "unsupported_reason": item["unsupported_reason"],
                }
                for item in records
            ]
        ),
    }
    closure["closure_digest"] = canonical_digest(closure)
    return closure


def build_source_closure_evidence(
    inventory: Mapping[str, Any],
    *,
    scope_id: str,
    semantic_report: Mapping[str, Any],
    environment_digest: str,
) -> dict[str, dict[str, Any]]:
    report_digest = str(semantic_report["report_digest"])
    registry_digest = inventory.get("runtime_registry_digest")
    cells = [item for item in semantic_report["cells"] if isinstance(item, Mapping)]
    receipt_digests = sorted(
        str(item["receipt_digest"]) for item in cells if item.get("receipt_digest")
    )
    proof_set = canonical_digest(receipt_digests)
    by_plane: dict[str, list[str]] = {}
    for cell in cells:
        plane = str(cell.get("evidence_plane", ""))
        receipt = cell.get("receipt_digest")
        if receipt:
            by_plane.setdefault(plane, []).append(str(receipt))
    evidence: dict[str, dict[str, Any]] = {}
    for source in inventory["sources"]:
        if source.get("applicability") != "APPLICABLE":
            continue
        source_type = str(source["source_type"])
        source_id = str(source["source_id"])
        if source_type == "RESOURCE":
            refs = [
                f"resource-snapshot:{source['sha256']}",
                f"semantic-matrix:{report_digest}",
            ]
            method = "protected-reader+semantic-matrix"
        elif source_type == "CLAIM":
            refs = [
                f"claim-observation:{source['locator_sha256']}",
                f"semantic-matrix:{report_digest}",
            ]
            method = "claim-extractor+semantic-matrix"
        elif source_type == "INVARIANT":
            refs = [f"semantic-proof-set:{proof_set}"]
            method = "semantic-proof-set"
        elif source_type == "PLANE":
            refs = [
                f"semantic-plane:{source['evidence_plane']}:{canonical_digest(sorted(by_plane.get(str(source['evidence_plane']), [])))}"
            ]
            method = "semantic-plane-receipts"
        elif source_type == "BEHAVIOR":
            refs = [
                f"behavior-receipts:{canonical_digest(sorted(by_plane.get('BEHAVIOR', [])))}",
                f"semantic-matrix:{report_digest}",
            ]
            method = "behavior-evidence"
        elif source_type == "RUNTIME":
            refs = [
                f"environment:{environment_digest}",
                f"runtime-registry:{registry_digest}",
            ]
            method = "runtime-identity"
        elif source_type == "LIFECYCLE":
            refs = [
                f"lifecycle-receipts:{canonical_digest(sorted(by_plane.get('LIFECYCLE', [])))}"
            ]
            method = "lifecycle-receipts"
        elif source_type == "EXTERNAL":
            refs = [f"tool-closure:{registry_digest}"]
            method = "tool-closure-registry"
        else:
            raise SourceInventoryError(
                f"no evidence projection for source type: {source_type}"
            )
        receipts = []
        for ref in refs:
            receipt: dict[str, Any] = {
                "schema_version": 1,
                "kind": "source-evidence-receipt",
                "source_id": source_id,
                "source_type": source_type,
                "scope_id": scope_id,
                "subject_digest": str(inventory["subject_digest"]),
                "candidate_digest": inventory.get("candidate_digest"),
                "runtime_registry_digest": registry_digest,
                "evidence_ref": ref,
                "evidence_sha256": ref.rsplit(":", 1)[-1],
                "method_id": method,
                "method_version": "1.0.0",
            }
            receipt["receipt_digest"] = canonical_digest(receipt)
            receipts.append(receipt)
        evidence[source_id] = {
            "terminal_status": "SATISFIED",
            "evidence_refs": refs,
            "evidence_method_id": method,
            "evidence_method_version": "1.0.0",
            "receipts": receipts,
        }
    return evidence


def assert_source_closure_complete(closure: Mapping[str, Any]) -> None:
    declared = closure.get("closure_digest")
    material = {key: value for key, value in closure.items() if key != "closure_digest"}
    if declared != canonical_digest(material):
        raise SourceInventoryError("source closure digest mismatch")
    records = closure.get("records")
    if not isinstance(records, list) or not records:
        raise SourceInventoryError("source closure must be non-empty")
    ids = [str(item["source_id"]) for item in records]
    if len(ids) != len(set(ids)):
        raise SourceInventoryError("source closure contains duplicate source IDs")
    blocking = sorted(
        str(item["source_id"])
        for item in records
        if item.get("terminal_status") not in SATISFYING_TERMINAL_STATUSES
    )
    if blocking:
        raise SourceInventoryError(
            "source closure has nonterminal sources: " + ", ".join(blocking)
        )
    unresolved: list[str] = []
    for item in records:
        if item.get("terminal_status") != "SATISFIED":
            continue
        receipts = {
            str(receipt.get("evidence_ref")): receipt
            for receipt in item.get("evidence_receipts", [])
            if isinstance(receipt, Mapping)
        }
        for ref in item.get("evidence_refs", []):
            receipt = receipts.get(str(ref))
            if (
                receipt is None
                or receipt.get("receipt_digest")
                != canonical_digest(
                    {
                        key: value
                        for key, value in receipt.items()
                        if key != "receipt_digest"
                    }
                )
                or receipt.get("source_id") != item["source_id"]
                or receipt.get("scope_id") != closure.get("scope_id")
                or receipt.get("subject_digest") != closure.get("subject_digest")
                or receipt.get("candidate_digest") != closure.get("candidate_digest")
                or receipt.get("runtime_registry_digest")
                != closure.get("runtime_registry_digest")
            ):
                unresolved.append(str(item["source_id"]))
                break
    if unresolved:
        raise SourceInventoryError(
            "source closure has unresolved evidence: " + ", ".join(unresolved)
        )
    if closure.get("source_count") != len(records):
        raise SourceInventoryError("source closure source_count mismatch")
    if closure.get("terminal_count") != len(records):
        raise SourceInventoryError("source closure terminal_count mismatch")


def assert_source_inventory_current(
    inventory: Mapping[str, Any],
    *,
    subject_digest: str,
    candidate_digest: str | None = None,
) -> None:
    declared = inventory.get("source_inventory_digest")
    material = {key: value for key, value in inventory.items() if key != "source_inventory_digest"}
    if declared != canonical_digest(material):
        raise SourceInventoryError("source inventory digest mismatch")
    if inventory.get("subject_digest") != subject_digest:
        raise SourceInventoryError("source inventory subject binding mismatch")
    if inventory.get("candidate_digest") != candidate_digest:
        raise SourceInventoryError("source inventory candidate binding mismatch")


def bind_source_inventory(
    inventory: Mapping[str, Any],
    *,
    candidate_digest: str | None,
) -> dict[str, Any]:
    bound = {
        key: value
        for key, value in inventory.items()
        if key != "source_inventory_digest"
    }
    bound["candidate_digest"] = candidate_digest
    bound["source_inventory_digest"] = canonical_digest(bound)
    return bound


def source_inventory_json(inventory: Mapping[str, Any]) -> str:
    return canonical_json(inventory)


def parse_inventory(value: str | bytes | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise SourceInventoryError("source inventory must be a JSON object")
    return parsed
