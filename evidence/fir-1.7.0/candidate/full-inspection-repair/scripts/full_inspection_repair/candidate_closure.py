from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .adapters import build_subject
from .contracts import (
    ContractError,
    canonical_digest,
    dir_hash1,
    in_toto_statement,
    material_digest,
    validate_candidate_manifest,
    validate_risk_ledger_v2,
    validate_run_manifest,
    validate_source_inventory,
)
from .source_inventory import (
    assert_source_closure_complete,
    build_source_closure,
    build_source_closure_evidence,
    build_source_inventory,
)
from .runtime_registry import load_registry
from .semantic_matrix import (
    build_semantic_evaluation_matrix,
    execute_semantic_matrix,
    semantic_case_identities,
    semantic_report_projection,
)
from .verification_matrix import (
    build_case_registry,
    validate_case_registry,
    verify_matrix_binding,
)


class ClosureError(ValueError):
    """Raised when candidate evidence cannot prove a bounded closure."""

    def __init__(self, message: str, code: str = "BLOCKED_VERIFICATION") -> None:
        super().__init__(message)
        self.code = code


def _value(value: Any, path: str, default: Any = None) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, Mapping):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
        if current is None:
            return default
    return current


def _require(value: Any, message: str) -> Any:
    if value is None or value == "" or value == []:
        raise ClosureError(message)
    return value


def _equal(label: str, actual: Any, expected: Any, code: str = "BLOCKED_VERIFICATION") -> None:
    if actual != expected:
        raise ClosureError(
            f"{label} mismatch: expected {expected}, found {actual}", code
        )


def _validate_for_closure(callback, *args, **kwargs):
    try:
        return callback(*args, **kwargs)
    except ContractError as exc:
        raise ClosureError(str(exc), "BLOCKED_VERIFICATION") from exc


def _artifact_digest(artifact: Mapping[str, Any], *names: str) -> str:
    for name in names:
        value = artifact.get(name)
        if value:
            return str(value)
    raise ClosureError(
        f"candidate evidence lacks a digest ({', '.join(names)})",
        "BLOCKED_EVIDENCE",
    )


def _validate_report_binding(
    label: str,
    report: Mapping[str, Any],
    *,
    candidate_digest: str,
    run: Mapping[str, Any],
) -> str:
    expected = {
        "run_id": run["run_id"],
        "scope_digest": run["scope_digest"],
        "subject_digest": run["subject"]["tree_digest"],
        "candidate_digest": candidate_digest,
        "registry_digest": run["bindings"]["registry_digest"],
        "policy_digest": run["bindings"]["taxonomy_policy_digest"],
        "tool_closure_digest": run["bindings"]["tool_closure_digest"],
    }
    for field, value in expected.items():
        actual = report.get(field)
        if actual is None:
            raise ClosureError(f"{label} lacks {field}", "BLOCKED_EVIDENCE")
        _equal(f"{label} {field}", actual, value)
    digest = _artifact_digest(report, "report_digest")
    if digest != material_digest(report, "report_digest"):
        raise ClosureError(f"{label} report_digest mismatch", "BLOCKED_EVIDENCE")
    return digest


def build_candidate_source_inventory(
    *,
    run: Mapping[str, Any],
    candidate_digest: str,
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    inventory: dict[str, Any] = {
        "schema_version": 2,
        "run_id": run["run_id"],
        "scope_digest": run["scope_digest"],
        "subject_digest": run["subject"]["tree_digest"],
        "candidate_digest": candidate_digest,
        "policy_digest": run["bindings"]["taxonomy_policy_digest"],
        "sources": sources,
    }
    inventory["inventory_digest"] = material_digest(inventory, "inventory_digest")
    validate_source_inventory(inventory)
    return inventory


def _assert_no_semantic_findings(report: Mapping[str, Any]) -> None:
    findings = report.get("findings")
    if not findings:
        return
    finding_ids = sorted(
        str(item.get("semantic_digest"))
        for item in findings
        if isinstance(item, Mapping)
    )
    raise ClosureError(
        "candidate semantic execution retains findings: " + ", ".join(finding_ids),
        "BLOCKED_VERIFICATION",
    )


def _validate_source_evidence(
    *,
    source_inventory_report: Mapping[str, Any],
    semantic_report: Mapping[str, Any],
    source_closure: Mapping[str, Any],
    detection: Mapping[str, Any],
    oracle: Mapping[str, Any],
    run: Mapping[str, Any],
    candidate_digest: str,
    candidate_root: str | Path,
    registry: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if source_inventory_report.get("source_inventory_digest") != material_digest(
        dict(source_inventory_report), "source_inventory_digest"
    ):
        raise ClosureError(
            "source inventory report digest mismatch", "BLOCKED_EVIDENCE"
        )
    subject = build_subject(candidate_root, "SKILL")
    runtime_registry = load_registry()
    expected_registry_digest = (
        registry.get("registry_digest", registry.get("digest"))
        if isinstance(registry, Mapping)
        else str(registry)
    )
    if runtime_registry.registry_digest != expected_registry_digest:
        raise ClosureError("runtime registry is not the frozen registry", "BLOCKED_STALE_INPUT")
    registry_snapshot = runtime_registry
    expected_inventory = build_source_inventory(
        subject,
        candidate_digest=candidate_digest,
        registry_snapshot=registry_snapshot,
    )
    if expected_inventory != source_inventory_report:
        raise ClosureError(
            "source inventory report does not match candidate bytes",
            "BLOCKED_EVIDENCE",
        )
    expected_report = {
        "subject_digest": candidate_digest,
        "candidate_digest": candidate_digest,
        "runtime_registry_digest": run["bindings"]["registry_digest"],
        "source_inventory_digest": source_inventory_report[
            "source_inventory_digest"
        ],
        "taxonomy_digest": run["bindings"]["taxonomy_policy_digest"],
    }
    for field, expected in expected_report.items():
        if semantic_report.get(field) != expected:
            raise ClosureError(
                f"semantic report {field} mismatch", "BLOCKED_EVIDENCE"
            )
    if semantic_report.get("report_digest") != material_digest(
        dict(semantic_report), "report_digest"
    ):
        raise ClosureError("semantic report digest mismatch", "BLOCKED_EVIDENCE")
    cells = semantic_report.get("cells")
    if not isinstance(cells, list) or not cells:
        raise ClosureError("semantic report cells are missing", "BLOCKED_EVIDENCE")
    cell_ids = [str(cell["cell_id"]) for cell in cells]
    if [str(item) for item in semantic_report.get("receipt_digests", [])] != [
        str(cell.get("receipt_digest")) for cell in cells
    ]:
        raise ClosureError(
            "semantic report receipt list does not match its cells",
            "BLOCKED_EVIDENCE",
        )
    for cell in cells:
        if cell.get("receipt_digest") != material_digest(cell, "receipt_digest"):
            raise ClosureError(
                f"semantic cell receipt digest mismatch: {cell.get('cell_id')}",
                "BLOCKED_EVIDENCE",
            )
    for label, report in (("detection", detection), ("oracle", oracle)):
        report_cells = report.get("cells")
        if not isinstance(report_cells, list):
            raise ClosureError(f"{label} cells are missing", "BLOCKED_EVIDENCE")
        if [str(cell.get("cell_id")) for cell in report_cells] != cell_ids:
            raise ClosureError(
                f"{label} cells do not match the semantic report",
                "BLOCKED_EVIDENCE",
            )
        expected_receipts = []
        for cell in cells:
            role = "detector_result" if label == "detection" else "oracle_result"
            result = cell.get(role)
            receipt = (
                result.get("result_digest")
                if isinstance(result, Mapping) and result.get("result_digest")
                else cell.get("receipt_digest")
            )
            expected_receipts.append(str(receipt))
        if [str(cell.get("receipt_digest")) for cell in report_cells] != expected_receipts:
            raise ClosureError(
                f"{label} receipts do not match the semantic report",
                "BLOCKED_EVIDENCE",
            )
        if [str(item) for item in report.get("receipt_digests", [])] != expected_receipts:
            raise ClosureError(
                f"{label} receipt digests do not match the semantic report",
                "BLOCKED_EVIDENCE",
            )
    expected_evidence = build_source_closure_evidence(
        source_inventory_report,
        scope_id=str(run["run_id"]),
        semantic_report=semantic_report,
        environment_digest=str(run["bindings"]["environment_digest"]),
    )
    expected_closure = build_source_closure(
        source_inventory_report,
        scope_id=str(run["run_id"]),
        evidence=expected_evidence,
    )
    if dict(source_closure) != expected_closure:
        raise ClosureError(
            "source closure is not reproducible from the current evidence",
            "BLOCKED_EVIDENCE",
        )
    actual_semantic = execute_semantic_matrix(
        subject,
        runtime_registry,
        phase=str(semantic_report.get("phase") or "VERIFICATION"),
        candidate_digest=candidate_digest,
        scope_id=str(run["run_id"]),
    )
    _assert_no_semantic_findings(actual_semantic)
    if semantic_report_projection(actual_semantic) != semantic_report_projection(
        semantic_report
    ):
        raise ClosureError(
            "semantic report is not reproducible by the frozen executors",
            "BLOCKED_EVIDENCE",
        )
    registry_data = runtime_registry.as_dict()
    tool_digest = canonical_digest(
        {
            "known_tools": registry_data["known_tools"],
            "tool_closures": registry_data["tool_closures"],
            "sandbox_backends": registry_data["sandbox_backends"],
        }
    )
    expected_cases = build_case_registry(
        semantic_case_identities(actual_semantic, tool_digest)
    )
    expected_matrix = build_semantic_evaluation_matrix(
        actual_semantic,
        tool_digest=tool_digest,
        run_id=str(run["run_id"]),
        scope_digest=str(run["scope_digest"]),
        subject_digest=str(run["subject"]["tree_digest"]),
        candidate_digest=candidate_digest,
    )
    return expected_cases, expected_matrix


def require_candidate_closure(
    *,
    candidate: dict[str, Any],
    ledger: dict[str, Any],
    source_inventory: dict[str, Any],
    detection: dict[str, Any],
    oracle: dict[str, Any],
    taxonomy: dict[str, Any],
    impact: dict[str, Any],
    matrix: dict[str, Any],
    source_inventory_report: Mapping[str, Any],
    semantic_report: Mapping[str, Any],
    evaluation_case_registry: Mapping[str, Any],
    registry: Any,
    run: dict[str, Any],
    candidate_root: str | Path,
    source_closure: Mapping[str, Any] | None = None,
    source_denominator_digest: str | None = None,
) -> dict[str, Any]:
    validate_run_manifest(run)
    if isinstance(registry, Mapping):
        registry_digest = registry.get(
            "registry_digest", registry.get("digest")
        )
        if registry_digest != run["bindings"]["registry_digest"]:
            raise ClosureError(
                "runtime registry is not the frozen registry",
                "BLOCKED_STALE_INPUT",
            )
    elif registry is not None and isinstance(registry, str):
        _equal(
            "runtime registry",
            registry,
            run["bindings"]["registry_digest"],
            "BLOCKED_STALE_INPUT",
        )
    candidate_digest = str(candidate["candidate_digest"])
    _validate_for_closure(
        validate_candidate_manifest,
        candidate,
        expected={
            "subject_tree_digest": run["subject"]["tree_digest"],
            "candidate_digest": run["candidate_digest"],
            "repair_plan_digest": run["repair_plan_digest"],
        },
    )
    _equal(
        "candidate manifest digest",
        candidate_digest,
        run["candidate_digest"],
        "BLOCKED_EVIDENCE",
    )
    try:
        actual = build_subject(candidate_root, "SKILL")
    except ValueError as exc:
        raise ClosureError(
            f"candidate bytes cannot be rebuilt: {exc}"
        ) from exc
    _equal("candidate bytes", actual.tree_digest, candidate_digest)
    _equal("candidate dirHash1", dir_hash1(candidate_root), candidate["candidate_dir_hash1"])

    expected = {
        "run_id": run["run_id"],
        "scope_digest": run["scope_digest"],
        "subject_tree_digest": run["subject"]["tree_digest"],
        "candidate_digest": candidate_digest,
        "registry_digest": run["bindings"]["registry_digest"],
        "policy_digest": run["bindings"]["taxonomy_policy_digest"],
    }
    _validate_for_closure(
        validate_source_inventory,
        source_inventory,
        expected=expected,
    )
    sources = source_inventory["sources"]
    source_ids = [str(item["source_id"]) for item in sources]
    if len(source_ids) != len(set(source_ids)):
        raise ClosureError("candidate source inventory contains duplicate IDs")
    required_ids = set(ledger["required_sources"])
    observed_ids = {
        str(item["source_id"])
        for item in sources
        if item.get("applicability") != "NOT_APPLICABLE_WITH_PROOF"
    }
    proof_backed = {
        str(item["source_id"])
        for item in sources
        if item.get("applicability") == "NOT_APPLICABLE_WITH_PROOF"
        and item.get("proof_ref")
        and item.get("policy_digest") == run["bindings"]["taxonomy_policy_digest"]
    }
    if not required_ids.issubset(observed_ids | proof_backed):
        missing = sorted(required_ids - (observed_ids | proof_backed))
        raise ClosureError(
            "candidate source closure is incomplete: " + ", ".join(missing)
        )
    _equal(
        "ledger source inventory digest",
        ledger["source_inventory_digest"],
        source_inventory["inventory_digest"],
        "BLOCKED_EVIDENCE",
    )
    if source_closure is None:
        raise ClosureError("candidate source closure is missing", "BLOCKED_EVIDENCE")
    expected_case_registry, expected_matrix = _validate_source_evidence(
        source_inventory_report=source_inventory_report,
        semantic_report=semantic_report,
        source_closure=source_closure,
        detection=detection,
        oracle=oracle,
        run=run,
        candidate_digest=candidate_digest,
        candidate_root=candidate_root,
        registry=registry,
    )
    try:
        assert_source_closure_complete(source_closure)
    except ContractError as exc:
        raise ClosureError(str(exc), "BLOCKED_EVIDENCE") from exc
    _equal(
        "source closure candidate",
        source_closure.get("candidate_digest"),
        candidate_digest,
        "BLOCKED_EVIDENCE",
    )
    _equal(
        "source closure denominator",
        source_closure.get("source_denominator_digest"),
        source_denominator_digest,
        "BLOCKED_EVIDENCE",
    )
    _validate_for_closure(
        validate_risk_ledger_v2,
        ledger,
        expected={
            "run_id": run["run_id"],
            "scope_digest": run["scope_digest"],
            "subject_tree_digest": run["subject"]["tree_digest"],
            "candidate_digest": candidate_digest,
        },
    )
    if ledger["open_count"] != 0:
        raise ClosureError("candidate ledger retains open findings")
    for field in (
        "missing_sources",
        "unexpected_sources",
        "residual_risks",
        "unresolved_ids",
    ):
        if ledger[field]:
            raise ClosureError(f"candidate ledger retains {field}")

    detection_digest = _validate_report_binding(
        "detection", detection, candidate_digest=candidate_digest, run=run
    )
    oracle_digest = _validate_report_binding(
        "oracle", oracle, candidate_digest=candidate_digest, run=run
    )
    detection_cells = detection.get("cells")
    oracle_cells = oracle.get("cells")
    if not isinstance(detection_cells, list) or not isinstance(oracle_cells, list):
        raise ClosureError("detection and oracle cell sets are missing")
    detection_ids = {
        str(cell.get("cell_id"))
        for cell in detection_cells
        if isinstance(cell, Mapping) and cell.get("cell_id")
    }
    oracle_ids = {
        str(cell.get("cell_id"))
        for cell in oracle_cells
        if isinstance(cell, Mapping) and cell.get("cell_id")
    }
    if not detection_ids or detection_ids != oracle_ids:
        raise ClosureError("detection and oracle cells do not reconcile")
    for label, report in (("detection", detection), ("oracle", oracle)):
        statuses = {
            str(cell.get("status", cell.get("terminal_status", "")))
            for cell in report["cells"]
        }
        if statuses & {"BLOCKED", "UNCOVERED", "UNSUPPORTED"}:
            raise ClosureError(f"{label} report contains a non-terminal pass cell")
        if not report.get("receipt_digests"):
            raise ClosureError(f"{label} report has no execution receipts")

    for label, artifact in (
        ("taxonomy", taxonomy),
        ("impact", impact),
        ("matrix", matrix),
    ):
        _equal(
            f"{label} candidate",
            artifact.get("candidate_digest"),
            candidate_digest,
            "BLOCKED_EVIDENCE",
        )
        if artifact.get("scope_digest") is not None:
            _equal(
                f"{label} scope",
                artifact["scope_digest"],
                run["scope_digest"],
                "BLOCKED_EVIDENCE",
            )
        if artifact.get("subject_digest") is not None:
            _equal(
                f"{label} subject",
                artifact["subject_digest"],
                run["subject"]["tree_digest"],
                "BLOCKED_EVIDENCE",
            )
    taxonomy_digest = _artifact_digest(
        taxonomy, "report_digest", "coverage_digest", "taxonomy_digest"
    )
    impact_digest = _artifact_digest(impact, "graph_digest", "impact_digest")
    matrix_digest = _artifact_digest(matrix, "matrix_digest", "report_digest")
    for label, artifact, digest in (
        ("taxonomy", taxonomy, taxonomy_digest),
        ("impact", impact, impact_digest),
        ("matrix", matrix, matrix_digest),
    ):
        field = next(
            name
            for name in (
                "report_digest",
                "coverage_digest",
                "taxonomy_digest",
                "graph_digest",
                "impact_digest",
                "matrix_digest",
            )
            if artifact.get(name) == digest
        )
        if digest != material_digest(artifact, field):
            raise ClosureError(
                f"{label} evidence digest mismatch", "BLOCKED_EVIDENCE"
            )
    required_cells = int(
        taxonomy.get("required_cell_count", len(detection_ids))
    )
    covered_cells = int(
        taxonomy.get("covered_cell_count", len(detection_ids))
    )
    if required_cells <= 0 or covered_cells != required_cells:
        raise ClosureError("taxonomy does not cover every required candidate cell")
    if int(impact.get("unresolved_count", impact.get("open_count", 0))) != 0:
        raise ClosureError("candidate impact graph has unresolved edges")
    if matrix.get("status") != "PASS":
        raise ClosureError("candidate verification matrix is not PASS")
    if int(matrix.get("required_failures", 0)) != 0:
        raise ClosureError("candidate verification matrix has required failures")

    evidence = {
        "source_inventory_digest": source_inventory["inventory_digest"],
        "detection_digest": detection_digest,
        "oracle_digest": oracle_digest,
        "impact_digest": impact_digest,
        "taxonomy_digest": taxonomy_digest,
        "matrix_digest": matrix_digest,
        "ledger_digest": ledger["ledger_digest"],
        "registry_digest": run["bindings"]["registry_digest"],
    }
    ledger_evidence = ledger["evidence_digests"]
    for name, digest in evidence.items():
        if name == "ledger_digest":
            continue
        _equal(
            f"ledger evidence {name}",
            ledger_evidence.get(name),
            digest,
            "BLOCKED_EVIDENCE",
        )
    case_registry = validate_case_registry(evaluation_case_registry)
    case_registry_digest = str(case_registry["registry_digest"])
    if case_registry != expected_case_registry:
        raise ClosureError(
            "evaluation case registry is not derived from the executed matrix",
            "BLOCKED_EVIDENCE",
        )
    _equal(
        "evaluation case registry",
        run["bindings"]["evaluation_case_registry_digest"],
        case_registry_digest,
        "BLOCKED_EVIDENCE",
    )
    if matrix != expected_matrix:
        raise ClosureError(
            "verification matrix is not reproducible from the executed cases",
            "BLOCKED_EVIDENCE",
        )
    try:
        verify_matrix_binding(
            matrix,
            run_id=run["run_id"],
            scope_digest=run["scope_digest"],
            subject_digest=run["subject"]["tree_digest"],
            candidate_digest=candidate_digest,
            expected_identities=case_registry["cases"],
            case_registry_digest=case_registry_digest,
        )
    except ValueError as exc:
        raise ClosureError(str(exc)) from exc
    proof: dict[str, Any] = {
        "schema_version": 1,
        "candidate_digest": candidate_digest,
        "source_closure_digest": source_closure["closure_digest"],
        "subject_source_count": len(required_ids),
        "required_cell_count": required_cells,
        "covered_cell_count": covered_cells,
        "impact_unresolved_count": 0,
        "open_count": 0,
        "residual_risks": [],
        "unresolved_ids": [],
        "missing_sources": [],
        "unexpected_sources": [],
        "evidence": evidence,
    }
    proof["attestation"] = in_toto_statement(
        name=str(candidate["logical_identity"]),
        digest=candidate_digest,
        predicate_type="https://fir.local/attestation/candidate-closure/v1",
        predicate={
            "evidence": evidence,
            "proof_digest": material_digest(proof, "proof_digest"),
        },
    )
    proof["proof_digest"] = material_digest(proof, "proof_digest")
    return proof


def rebuild_candidate(
    *,
    candidate_root: str | Path,
    run: dict[str, Any],
    ledger: dict[str, Any],
    source_inventory: dict[str, Any],
    detection: dict[str, Any],
    oracle: dict[str, Any],
    taxonomy: dict[str, Any],
    impact: dict[str, Any],
    matrix: dict[str, Any],
    source_inventory_report: dict[str, Any],
    semantic_report: dict[str, Any],
    evaluation_case_registry: dict[str, Any],
    registry: Any,
    source_closure: dict[str, Any] | None = None,
    source_denominator_digest: str | None = None,
) -> dict[str, Any]:
    subject = build_subject(candidate_root, "SKILL")
    candidate = {
        "schema_version": 2,
        "candidate_id": canonical_digest(
            {
                "base_subject_digest": run["subject"]["tree_digest"],
                "candidate_digest": subject.tree_digest,
            }
        ),
        "base_subject_digest": run["subject"]["tree_digest"],
        "candidate_digest": subject.tree_digest,
        "candidate_dir_hash1": dir_hash1(candidate_root),
        "repair_plan_digest": run["repair_plan_digest"],
        "operation_receipt_digests": run.get("operation_receipt_digests", []),
        "logical_identity": run["subject"]["logical_identity"],
        "generation": 1,
        "files": [
            {"path": item.locator, "sha256": item.sha256, "size": item.size}
            for item in subject.files
        ],
    }
    candidate["candidate_manifest_digest"] = material_digest(
        candidate, "candidate_manifest_digest"
    )
    return require_candidate_closure(
        candidate=candidate,
        ledger=ledger,
        source_inventory=source_inventory,
        detection=detection,
        oracle=oracle,
        taxonomy=taxonomy,
        impact=impact,
        matrix=matrix,
        source_inventory_report=source_inventory_report,
        semantic_report=semantic_report,
        evaluation_case_registry=evaluation_case_registry,
        registry=registry,
        run=run,
        candidate_root=candidate_root,
        source_closure=source_closure,
        source_denominator_digest=source_denominator_digest,
    )
