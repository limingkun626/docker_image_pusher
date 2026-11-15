from __future__ import annotations

import re
import multiprocessing
import os
import shutil
import tempfile
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

from .contracts import canonical_digest

TERMINAL_STATES = frozenset(
    {
        "CLEAN",
        "CLEAN_WITH_PROOF",
        "FINDING",
        "BLOCKED",
        "UNSUPPORTED",
        "UNCOVERED",
        "EMPTY_RESULT",
    }
)
_IGNORED_KEYS = frozenset(
    {
        "message",
        "reason",
        "label",
        "witness",
        "witness_id",
        "confidence",
        "line",
        "lines",
        "column",
        "start_line",
        "end_line",
        "one_based_line",
        "zero_based_line",
        "method_id",
        "method_version",
        "passed",
        "raw_status",
    }
)
_EVIDENCE_WRAPPERS = frozenset(
    {"evidence", "normalized_evidence", "observations", "value", "details", "payload"}
)
_KEY_ALIASES = {
    "cell": "cell_id",
    "cellid": "cell_id",
    "defectclass": "defect_class_id",
    "defectclassid": "defect_class_id",
    "classid": "defect_class_id",
    "invariant": "invariant_id",
    "invariantid": "invariant_id",
    "locator": "primary_locator",
    "primarylocator": "primary_locator",
    "evidence": "normalized_evidence",
    "normalizedevidence": "normalized_evidence",
    "normalizedevidence": "normalized_evidence",
}


def _key(value: object) -> str:
    raw = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value))
    compact = re.sub(r"[^a-z0-9]", "", raw.casefold())
    return _KEY_ALIASES.get(compact, raw.casefold())


def _normalized_path(value: str | PurePosixPath) -> str:
    path = PurePosixPath(str(value).replace("\\", "/"))
    parts: list[str] = []
    for part in path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def _normalize(value: Any, *, root: bool = False) -> Any:
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = _key(raw_key)
            if key in _IGNORED_KEYS:
                continue
            if key in _EVIDENCE_WRAPPERS:
                wrapped = _normalize(item)
                if isinstance(wrapped, dict):
                    normalized.update(wrapped)
                else:
                    normalized["payload"] = wrapped
                continue
            normalized[key] = _normalize(item)
        return normalized
    if isinstance(value, (list, tuple)):
        normalized_items = [_normalize(item) for item in value]
        return sorted(
            normalized_items,
            key=lambda item: canonical_digest(item),
        )
    if isinstance(value, str):
        return value.replace("\\", "/").strip()
    return value


def _facts(value: Any) -> tuple[list[dict[str, Any]], str]:
    if value is None:
        return [], "MISSING"
    if isinstance(value, Mapping):
        raw_status = str(value.get("status") or value.get("terminal_observation") or value.get("raw_status") or "")
        facts = value.get("facts") or value.get("findings") or value.get("witnesses") or []
        if isinstance(facts, Mapping):
            facts = list(facts.values())
        if not facts and value.get("finding"):
            facts = [value["finding"]]
        return [dict(item) for item in facts if isinstance(item, Mapping)], raw_status
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        items = [dict(item) for item in value if isinstance(item, Mapping)]
        facts = [
            item
            for item in items
            if any(
                key in item
                for key in (
                    "primary_locator",
                    "locator",
                    "path",
                    "finding",
                    "witness",
                    "semantic_digest",
                )
            )
        ]
        statuses = [
            str(item.get("status") or item.get("raw_status") or "").upper()
            for item in items
            if item.get("status") or item.get("raw_status")
        ]
        if not facts:
            if items and all(status in {"CLEAN", "PASS"} for status in statuses):
                return [], "CLEAN"
            if items and any(
                status in {"BLOCKED", "MALFORMED", "MISSING", "UNSUPPORTED", "UNCOVERED", "EMPTY_RESULT"}
                for status in statuses
            ):
                return [], "BLOCKED"
        return facts, "FINDING" if facts else "CLEAN"
    return [], "MALFORMED"


def normalize_semantic_witness(witness: Mapping[str, Any]) -> dict[str, Any]:
    witness = {_key(key): value for key, value in witness.items()}
    locator = (
        witness.get("primary_locator")
        or witness.get("locator")
        or witness.get("path")
    )
    if isinstance(locator, Mapping):
        raw_path = locator.get("path") or locator.get("locator") or locator.get("file") or ""
        symbol = locator.get("symbol") or witness.get("symbol")
    else:
        raw_path = locator or ""
        symbol = witness.get("symbol")
    normalized = {
        "schema_version": 1,
        "cell_id": str(witness.get("cell_id") or ""),
        "defect_class_id": str(witness.get("defect_class_id") or ""),
        "invariant_id": str(witness.get("invariant_id") or ""),
        "primary_locator": {
            "path": _normalized_path(raw_path),
            "symbol": str(symbol) if symbol is not None else None,
        },
        "normalized_evidence": _normalize(
            witness.get("normalized_evidence")
            or witness.get("evidence")
            or {
                key: value
                for key, value in witness.items()
                if key
                not in {
                    "schema_version",
                    "cell_id",
                    "defect_class_id",
                    "invariant_id",
                    "primary_locator",
                    "locator",
                    "path",
                    "symbol",
                    "supporting_locators",
                    "semantic_digest",
                }
            },
            root=True,
        ),
    }
    normalized["semantic_digest"] = canonical_digest(normalized)
    return normalized


def semantic_key(witness: Mapping[str, Any]) -> tuple[Any, ...]:
    normalized = normalize_semantic_witness(witness)
    locator = normalized["primary_locator"]
    return (
        normalized["cell_id"],
        normalized["defect_class_id"],
        normalized["invariant_id"],
        locator["path"],
        locator["symbol"],
        normalized["semantic_digest"],
    )


def compare_semantic_witnesses(
    detector: Any,
    oracle: Any,
) -> dict[str, Any]:
    detector_facts, detector_status = _facts(detector)
    oracle_facts, oracle_status = _facts(oracle)
    blocked_statuses = {"MISSING", "MALFORMED", "BLOCKED", "UNSUPPORTED", "UNCOVERED", "EMPTY_RESULT"}
    if detector_status in blocked_statuses or oracle_status in blocked_statuses:
        return {"comparison": "BLOCKED", "failure_code": "ONE_SIDED_OR_PARTIAL"}
    if not detector_facts and not oracle_facts:
        if detector_status in {"", "CLEAN", "PASS"} and oracle_status in {"", "CLEAN", "PASS"}:
            return {"comparison": "AGREE_CLEAN", "failure_code": None, "facts": []}
        return {"comparison": "BLOCKED", "failure_code": "ONE_SIDED_OR_PARTIAL"}
    if not detector_facts or not oracle_facts:
        return {
            "comparison": "BLOCKED",
            "failure_code": "ONE_SIDED_ORACLE_EVIDENCE",
        }
    detector_keys = {semantic_key(item) for item in detector_facts}
    oracle_keys = {semantic_key(item) for item in oracle_facts}
    if detector_keys == oracle_keys:
        merged = sorted(
            (
                normalize_semantic_witness(item)
                for item in detector_facts
            ),
            key=lambda item: item["semantic_digest"],
        )
        return {
            "comparison": "AGREE",
            "failure_code": None,
            "facts": merged,
            "semantic_fact_set_digest": canonical_digest(merged),
        }
    return {
        "comparison": "DISAGREE",
        "failure_code": "ORACLE_DISAGREEMENT",
        "detector_only": sorted(detector_keys - oracle_keys),
        "oracle_only": sorted(oracle_keys - detector_keys),
    }


def _snapshot(subject: Any) -> dict[str, Any]:
    return {
        "subject_digest": getattr(subject, "tree_digest", None),
        "target_root": str(subject.root),
        "files": {
            item.locator: item.content.decode("utf-8", errors="replace")
            for item in getattr(subject, "files", ())
        },
    }


def _exact_adapter_worker(connection: Any, cell_id: str, snapshot: Mapping[str, Any]) -> None:
    try:
        if cell_id.endswith(":LIFECYCLE"):
            from .lifecycle_adapters import run_for_snapshot
        else:
            from .external_adapters import run_for_snapshot
        result = run_for_snapshot(cell_id, snapshot)
    except BaseException as exc:
        result = {
            "status": "BLOCKED_ADAPTER",
            "failure_code": type(exc).__name__,
            "facts": [],
            "error": str(exc),
        }
    try:
        connection.send(result)
    finally:
        connection.close()


def _run_exact_adapter(cell_id: str, snapshot: Mapping[str, Any], timeout: float = 120.0) -> dict[str, Any]:
    context = multiprocessing.get_context("spawn" if os.name == "nt" else "forkserver")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(
        target=_exact_adapter_worker,
        args=(send, cell_id, dict(snapshot)),
        daemon=True,
    )
    try:
        process.start()
    except Exception as exc:
        receive.close()
        send.close()
        return {
            "status": "BLOCKED_ADAPTER",
            "failure_code": "EXACT_ADAPTER_PROCESS_START_FAILED",
            "facts": [],
            "error": str(exc),
        }
    send.close()
    result = None
    try:
        if receive.poll(timeout):
            candidate = receive.recv()
            if isinstance(candidate, Mapping):
                result = dict(candidate)
    except (EOFError, OSError):
        result = None
    finally:
        receive.close()
    process.join(0.2)
    if result is not None:
        return result
    if process.is_alive():
        try:
            import psutil

            descendants = psutil.Process(process.pid).children(recursive=True)
            for child in reversed(descendants):
                try:
                    child.kill()
                except psutil.Error:
                    pass
        except Exception:
            pass
        process.terminate()
        process.join(1.0)
    if process.is_alive():
        process.kill()
        process.join(1.0)
    return {
        "status": "BLOCKED_ADAPTER",
        "failure_code": "EXACT_ADAPTER_TIMEOUT",
        "facts": [],
        "error": f"exact adapter exceeded {timeout:.1f}s",
    }


def _exact_adapter_timeout(
    registry: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> float:
    policies = registry.get("resource_policies", {})
    declared = float(binding.get("timeout_seconds", 0) or 0)
    external = float(
        (policies.get("external_adapter") or {}).get("timeout_seconds", 0)
        if isinstance(policies, Mapping)
        else 0
    )
    lifecycle = float(
        (policies.get("lifecycle_adapter") or {}).get("timeout_seconds", 0)
        if isinstance(policies, Mapping)
        else 0
    )
    return max(declared, external, lifecycle, 0.1)


def _cell_applicability(
    binding: Mapping[str, Any],
    subject: Any,
    source_inventory: Mapping[str, Any],
    registry: Any,
    taxonomy: Mapping[str, Any],
) -> dict[str, Any]:
    category = str(binding["category_id"])
    plane = str(binding["evidence_plane"])
    terminal = str(binding["terminal_state"])
    resources = [
        row
        for row in source_inventory["sources"]
        if row["source_type"] == "RESOURCE"
        and row["applicability"] != "REQUIRED_MISSING"
    ]
    observed_classes = sorted(
        {str(row.get("file_class")) for row in resources if row.get("file_class")}
    )

    if terminal == "COVERED_BY_EXACT_ADAPTER":
        if plane == "LIFECYCLE":
            required = {
                "BINARY_OPAQUE",
                "CONFIGURATION",
                "TEST_SOURCE",
            }
            condition = "NO_LIFECYCLE_FIXTURE_OR_CONFIGURATION_SOURCE"
        else:
            required = {"TEST_SOURCE"}
            condition = "NO_EXECUTABLE_BEHAVIOR_TEST_SOURCE"
    elif plane in {"CONTRACT", "RUNTIME"}:
        required = {"CONFIGURATION", "TEXT_SOURCE", "TEST_SOURCE"}
        condition = f"NO_{plane}_SOURCE"
    elif plane == "PERFORMANCE":
        required = {"BINARY_OPAQUE", "CONFIGURATION", "TEXT_SOURCE", "TEST_SOURCE"}
        condition = "NO_PERFORMANCE_SENSITIVE_SOURCE"
    elif plane == "SEMANTIC":
        required = {"CONFIGURATION", "TEXT_SOURCE", "TEST_SOURCE"}
        condition = "NO_SEMANTIC_EXECUTABLE_OR_CONFIGURATION_SOURCE"
    elif plane == "STATIC" and category in {
        "EXCEPTION_PATH",
        "RISK_EXPOSURE",
        "VULNERABILITY",
    }:
        required = {
            "BINARY_OPAQUE",
            "CONFIGURATION",
            "TEXT_SOURCE",
            "TEST_SOURCE",
        }
        condition = "NO_STATIC_RISK_OR_VULNERABILITY_SOURCE"
    elif plane == "SECURITY" and category == "RISK_EXPOSURE":
        required = {
            "BINARY_OPAQUE",
            "CONFIGURATION",
            "TEXT_SOURCE",
            "TEST_SOURCE",
        }
        condition = "NO_SECURITY_EXPOSURE_SOURCE"
    else:
        required = {
            "BINARY_OPAQUE",
            "CONFIGURATION",
            "DOCUMENTATION",
            "TEXT_DATA",
            "TEXT_SOURCE",
            "TEST_SOURCE",
        }
        condition = "NO_APPLICABLE_SOURCE"

    matched = sorted(set(required) & set(observed_classes))
    matched_sources = sorted(
        str(row["source_id"])
        for row in resources
        if row.get("file_class") in matched
    )
    applicable = bool(matched_sources)
    classifier_material = [
        {
            "locator": row["locator"],
            "file_class": row.get("file_class"),
            "scanner_ids": row.get("scanner_ids", []),
        }
        for row in resources
    ]
    classifier_digest = canonical_digest(
        {"version": "1.0.0", "classifications": classifier_material}
    )
    proof_material: dict[str, Any] = {
        "schema_version": 1,
        "kind": "NOT_APPLICABLE_WITH_PROOF",
        "cell_id": str(binding["cell_id"]),
        "target_kind": str(binding["target_kind"]),
        "category_id": category,
        "evidence_plane": plane,
        "binding_id": str(binding["binding_id"]),
        "binding_digest": str(binding["binding_digest"]),
        "runtime_registry_id": registry.registry_id,
        "runtime_registry_version": registry.registry_version,
        "runtime_registry_digest": registry.registry_digest,
        "taxonomy_digest": str(taxonomy["coverage_digest"]),
        "source_inventory_digest": str(source_inventory["source_inventory_digest"]),
        "file_classifier_digest": classifier_digest,
        "required_file_classes": sorted(required),
        "observed_file_classes": observed_classes,
        "matched_sources": matched_sources,
        "missing_conditions": [] if applicable else [condition],
        "evidence_refs": [
            f"file-classifier:{classifier_digest}",
            f"source-inventory:{source_inventory['source_inventory_digest']}",
            f"runtime-registry:{registry.registry_digest}",
            f"taxonomy:{taxonomy['coverage_digest']}",
        ],
    }
    proof = dict(proof_material)
    proof["proof_digest"] = canonical_digest(proof_material)
    return {
        "applicable": applicable,
        "required_file_classes": sorted(required),
        "observed_file_classes": observed_classes,
        "matched_sources": matched_sources,
        "missing_conditions": proof["missing_conditions"],
        "proof": proof,
    }


def validate_cell_not_applicable_proof(
    proof: Mapping[str, Any],
    *,
    cell_id: str,
    registry_digest: str | None = None,
) -> None:
    if (
        proof.get("schema_version") != 1
        or proof.get("kind") != "NOT_APPLICABLE_WITH_PROOF"
        or proof.get("cell_id") != cell_id
    ):
        raise ValueError("cell N/A proof is bound to the wrong cell")
    declared = proof.get("proof_digest")
    material = {key: value for key, value in proof.items() if key != "proof_digest"}
    if declared != canonical_digest(material):
        raise ValueError("cell N/A proof digest mismatch")
    if registry_digest is not None and proof.get("runtime_registry_digest") != registry_digest:
        raise ValueError("cell N/A proof registry mismatch")
    if not proof.get("missing_conditions") or not proof.get("evidence_refs"):
        raise ValueError("cell N/A proof lacks missing-condition evidence")


def _semantic_item(
    item: Mapping[str, Any],
    *,
    cell_id: str,
    category_id: str,
    evidence_plane: str,
) -> dict[str, Any]:
    value = dict(item)
    value.setdefault("cell_id", cell_id)
    value.setdefault("defect_class_id", str(item.get("witness") or category_id))
    value.setdefault("invariant_id", str(item.get("predicate_id") or evidence_plane))
    if "primary_locator" not in value:
        value["primary_locator"] = {
            "path": item.get("path") or item.get("locator") or "",
            "symbol": item.get("symbol"),
        }
    if "normalized_evidence" not in value:
        evidence = item.get("value") or item.get("evidence") or {}
        value["normalized_evidence"] = _normalize(evidence)
    return normalize_semantic_witness(value)


def _result_receipt(
    raw: Mapping[str, Any] | None,
    *,
    cell_id: str,
    category_id: str,
    evidence_plane: str,
    method_kind: str,
) -> dict[str, Any] | None:
    if raw is None:
        return None
    findings = raw.get("findings") or raw.get("facts") or []
    if isinstance(findings, Mapping):
        findings = list(findings.values())
    facts = [
        _semantic_item(
            item,
            cell_id=cell_id,
            category_id=category_id,
            evidence_plane=evidence_plane,
        )
        for item in findings
        if isinstance(item, Mapping)
    ]
    receipt: dict[str, Any] = {
        "method_id": str(
            raw.get("detector_id")
            or raw.get("method_id")
            or f"{method_kind}.{cell_id.casefold()}"
        ),
        "method_version": str(raw.get("detector_version") or "1.0.0"),
        "raw_status": str(raw.get("status") or raw.get("terminal_observation") or ""),
        "facts": [
            {
                "semantic_key": semantic_key(item),
                "semantic_fact_digest": item["semantic_digest"],
                "witness_refs": [item["semantic_digest"]],
            }
            for item in facts
        ],
        "raw_facts": facts,
        "error": raw.get("error") or raw.get("failure_code"),
    }
    receipt["result_digest"] = canonical_digest(receipt)
    return receipt


def build_cell_receipt(
    binding: Mapping[str, Any],
    *,
    detector_raw: Mapping[str, Any] | None,
    oracle_raw: Mapping[str, Any] | None,
    subject_digest: str | None,
    scope_id: str = "scope:current",
    phase: str = "DISCOVERY",
    recorded_at: str | None = None,
) -> dict[str, Any]:
    cell_id = str(binding["cell_id"])
    category_id = str(binding["category_id"])
    evidence_plane = str(binding["evidence_plane"])
    terminal = str(binding["terminal_state"])
    applicability = None
    if "applicability" in binding:
        applicability = binding["applicability"]
    if isinstance(binding.get("_applicability"), Mapping):
        applicability = binding["_applicability"]
    detector = _result_receipt(
        detector_raw,
        cell_id=cell_id,
        category_id=category_id,
        evidence_plane=evidence_plane,
        method_kind="detector",
    )
    oracle = _result_receipt(
        oracle_raw,
        cell_id=cell_id,
        category_id=category_id,
        evidence_plane=evidence_plane,
        method_kind="oracle",
    )
    findings: list[dict[str, Any]] = []
    comparison = "BLOCKED"
    failure_code: str | None = None
    status = "BLOCKED"
    not_applicable_proof = None

    if terminal == "NOT_APPLICABLE_WITH_PROOF":
        comparison = "AGREE_CLEAN"
        status = "CLEAN_WITH_PROOF"
        failure_code = None
    elif terminal == "COVERED_BY_INDEPENDENT_ORACLE":
        comparison = "NOT_COMPARED_ORACLE_ONLY"
        raw_status = str((oracle_raw or {}).get("status", ""))
        if raw_status in {"CLEAN", "PASS"}:
            status = "CLEAN"
        elif raw_status == "FINDING":
            status = "FINDING"
        elif raw_status == "EMPTY_RESULT":
            status = "UNCOVERED"
            failure_code = "EMPTY_RESULT"
        elif raw_status == "UNSUPPORTED":
            status = "UNSUPPORTED"
            failure_code = "UNSUPPORTED"
        else:
            status = "BLOCKED"
            failure_code = "ORACLE_PARTIAL"
        findings = list((oracle or {}).get("raw_facts", []))
    elif terminal == "COVERED_BY_EXACT_ADAPTER":
        comparison = "NOT_COMPARED_EXACT_ADAPTER"
        adapter_status = str((detector_raw or {}).get("status", ""))
        status = (
            "CLEAN"
            if adapter_status in {"CLEAN", "PASS"}
            else "FINDING"
            if adapter_status == "FINDING"
            else "BLOCKED"
        )
        failure_code = None if status == "CLEAN" else (
            str((detector_raw or {}).get("failure_code") or "BLOCKED_ADAPTER")
            if status == "BLOCKED"
            else None
        )
        if status == "FINDING":
            findings = list((detector_raw or {}).get("raw_facts", ()))
    else:
        detector_status = str((detector_raw or {}).get("status", ""))
        oracle_status = str((oracle_raw or {}).get("status", ""))
        if detector_status == "EMPTY_RESULT" and oracle_status == "EMPTY_RESULT":
            comparison = "UNCOVERED"
            status = "UNCOVERED"
            failure_code = "EMPTY_RESULT"
        elif detector_status == "UNSUPPORTED" or oracle_status == "UNSUPPORTED":
            comparison = "BLOCKED"
            status = "UNSUPPORTED"
            failure_code = "UNSUPPORTED"
        elif (
            detector_status.startswith("BLOCKED")
            or oracle_status.startswith("BLOCKED")
            or detector_raw is None
            or oracle_raw is None
        ):
            comparison = "BLOCKED"
            status = "BLOCKED"
            failure_code = (
                "DETECTOR_PARTIAL" if detector_raw is None else "ORACLE_PARTIAL"
            )
        else:
            compared = compare_semantic_witnesses(
                (detector or {}).get("raw_facts", ()),
                (oracle or {}).get("raw_facts", ()),
            )
            comparison = str(compared["comparison"])
            failure_code = compared.get("failure_code")
            if comparison == "AGREE_CLEAN":
                status = "CLEAN"
            elif comparison == "AGREE":
                status = "FINDING"
                findings = list(compared.get("facts", ()))
            else:
                status = "BLOCKED"

    raw_has_facts = bool(
        (detector or {}).get("raw_facts") or (oracle or {}).get("raw_facts")
    )
    if (
        terminal not in {"MERGED_WITH_PRIMARY_CELL", "NOT_APPLICABLE_WITH_PROOF"}
        and isinstance(applicability, Mapping)
        and applicability.get("applicable") is False
        and not raw_has_facts
    ):
        not_applicable_proof = dict(applicability["proof"])
        comparison = "NOT_APPLICABLE_WITH_PROOF"
        status = "CLEAN_WITH_PROOF"
        failure_code = None

    receipt: dict[str, Any] = {
        "schema_version": 1,
        "cell_id": cell_id,
        "target_kind": str(binding["target_kind"]),
        "category_id": category_id,
        "evidence_plane": evidence_plane,
        "terminal_state": terminal,
        "binding_id": str(binding["binding_id"]),
        "binding_digest": str(binding["binding_digest"]),
        "subject_digest": subject_digest,
        "scope_id": scope_id,
        "fixture_ids": list(binding.get("fixture_case_ids", ())),
        "detector_result": detector,
        "oracle_result": oracle,
        "comparison": comparison,
        "semantic_fact_set_digest": canonical_digest(findings),
        "status": status,
        "failure_code": failure_code,
        "resource_receipt": dict((detector_raw or {}).get("resource_receipt", {})),
        "process_tree_receipt": dict(
            (detector_raw or {}).get("process_tree_receipt", {})
        ),
        "network_guard_receipt": dict(
            (detector_raw or {}).get("network_guard_receipt", {})
        ),
        "findings": findings,
        "not_applicable_proof": not_applicable_proof,
        "applicability": dict(applicability) if isinstance(applicability, Mapping) else None,
        "phase": phase,
        "recorded_at": recorded_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt


def execute_semantic_matrix(
    subject: Any,
    registry: Any | None = None,
    *,
    snapshot: Mapping[str, Any] | None = None,
    phase: str = "DISCOVERY",
) -> dict[str, Any]:
    from .detector_registry import default_taxonomy_coverage
    from .r2_engine import run_native, run_oracle
    from .runtime_registry import load_registry
    from .source_inventory import build_source_inventory

    runtime_registry = registry or load_registry()
    cell_ids = runtime_registry.required_cells(getattr(subject, "subject_kind", "SKILL"))
    frozen_snapshot = dict(snapshot or _snapshot(subject))
    frozen_snapshot.setdefault("target_root", str(subject.root))
    source_inventory = build_source_inventory(
        subject,
        registry_snapshot=runtime_registry,
    )
    taxonomy = default_taxonomy_coverage(getattr(subject, "subject_kind", "SKILL"))
    cells: list[dict[str, Any]] = []
    primary_results: dict[str, dict[str, Any]] = {}
    execution_order = sorted(
        cell_ids,
        key=lambda item: (
            runtime_registry.cell_binding(item)["terminal_state"]
            == "MERGED_WITH_PRIMARY_CELL",
            item,
        ),
    )
    for cell_id in execution_order:
        binding = runtime_registry.cell_binding(cell_id)
        applicability = _cell_applicability(
            binding,
            subject,
            source_inventory,
            runtime_registry,
            taxonomy,
        )
        binding["_applicability"] = applicability
        terminal = str(binding["terminal_state"])
        if terminal == "MERGED_WITH_PRIMARY_CELL":
            primary_id = str(binding["primary_cell_id"])
            primary = primary_results.get(primary_id)
            if primary is None:
                cell = build_cell_receipt(
                    binding,
                    detector_raw={"status": "BLOCKED"},
                    oracle_raw={"status": "BLOCKED"},
                    subject_digest=frozen_snapshot.get("subject_digest"),
                    phase=phase,
                )
            else:
                cell = {
                    **primary,
                    "cell_id": cell_id,
                    "terminal_state": terminal,
                    "binding_id": binding["binding_id"],
                    "binding_digest": binding["binding_digest"],
                    "measurement_ref": primary_id,
                    "duplicate_measurement": False,
                    "phase": phase,
                }
                cell["receipt_digest"] = canonical_digest(
                    {key: value for key, value in cell.items() if key != "receipt_digest"}
                )
        elif terminal == "NOT_APPLICABLE_WITH_PROOF":
            cell = build_cell_receipt(
                binding,
                detector_raw=None,
                oracle_raw=None,
                subject_digest=frozen_snapshot.get("subject_digest"),
                phase=phase,
            )
        elif terminal == "COVERED_BY_EXACT_ADAPTER":
            if applicability["applicable"]:
                adapter_snapshot = dict(frozen_snapshot)
                disposable_root = None
                if binding["evidence_plane"] == "LIFECYCLE":
                    disposable_root = tempfile.mkdtemp(prefix="fir-lifecycle-fixture-")
                    shutil.copytree(
                        subject.root,
                        disposable_root,
                        dirs_exist_ok=True,
                    )
                    adapter_snapshot["target_root"] = disposable_root
                try:
                    adapter_raw = _run_exact_adapter(
                        cell_id,
                        adapter_snapshot,
                        timeout=_exact_adapter_timeout(
                            runtime_registry,
                            binding,
                        ),
                    )
                finally:
                    if disposable_root is not None:
                        shutil.rmtree(disposable_root, ignore_errors=True)
            else:
                adapter_raw = None
            cell = build_cell_receipt(
                binding,
                detector_raw=adapter_raw,
                oracle_raw={"status": "EMPTY_RESULT"},
                subject_digest=frozen_snapshot.get("subject_digest"),
                phase=phase,
            )
        elif terminal == "COVERED_BY_INDEPENDENT_ORACLE":
            raw = run_oracle(cell_id, frozen_snapshot)
            cell = build_cell_receipt(
                binding,
                detector_raw=None,
                oracle_raw=raw,
                subject_digest=frozen_snapshot.get("subject_digest"),
                phase=phase,
            )
        else:
            detector_raw = run_native(cell_id, frozen_snapshot)
            oracle_raw = run_oracle(cell_id, frozen_snapshot)
            cell = build_cell_receipt(
                binding,
                detector_raw=detector_raw,
                oracle_raw=oracle_raw,
                subject_digest=frozen_snapshot.get("subject_digest"),
                phase=phase,
            )
        primary_results[cell_id] = cell
        cells.append(cell)
    cells.sort(key=lambda item: str(item["cell_id"]))
    findings_by_semantic_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    for cell in cells:
        for finding in cell.get("findings", ()):
            findings_by_semantic_key[semantic_key(finding)] = finding
    findings = sorted(
        findings_by_semantic_key.values(),
        key=lambda item: item["semantic_digest"],
    )
    report: dict[str, Any] = {
        "schema_version": 2,
        "phase": phase,
        "scope_id": "scope:current",
        "subject_digest": frozen_snapshot.get("subject_digest"),
        "candidate_digest": frozen_snapshot.get("candidate_digest"),
        "runtime_registry_digest": runtime_registry.registry_digest,
        "taxonomy_digest": taxonomy["coverage_digest"],
        "source_inventory_digest": source_inventory["source_inventory_digest"],
        "cell_count": len(cells),
        "terminal_count": sum(
            item["status"] in {"CLEAN", "CLEAN_WITH_PROOF", "FINDING"}
            for item in cells
        ),
        "blocked_count": sum(item["status"] in {"BLOCKED", "UNSUPPORTED", "UNCOVERED"} for item in cells),
        "not_applicable_count": sum(
            item["status"] == "CLEAN_WITH_PROOF" for item in cells
        ),
        "uncovered_count": sum(item["status"] == "UNCOVERED" for item in cells),
        "cells": cells,
        "receipt_digests": [item["receipt_digest"] for item in cells],
        "findings": findings,
        "finding_count": len(findings),
        "semantic_fact_set_digest": canonical_digest(findings),
    }
    report["report_digest"] = canonical_digest(report)
    return report


run_semantic_matrix = execute_semantic_matrix
