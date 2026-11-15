from __future__ import annotations

from collections.abc import Callable
from threading import Event, Thread
from typing import Any

from .contracts import ContractError, canonical_digest
from .taxonomy import validate_not_applicable_proof


class CellFailure(ValueError):
    """Raised by a qualification fault injection."""


def _evaluate(
    cell: dict[str, object],
    context: dict[str, Any],
    *,
    oracle: bool = False,
    fault: str | None = None,
) -> bool:
    if fault == "raise":
        raise CellFailure("qualification fault")
    if fault:
        return False
    terminal_state = cell.get("terminal_state")
    if terminal_state == "MERGED_WITH_PRIMARY_CELL":
        primary = cell.get("primary_cell_id")
        return isinstance(primary, str) and bool(primary) and primary != (
            f"{cell['target_kind']}:{cell['category_id']}:{cell['evidence_plane']}"
        )
    proof = cell.get("not_applicable_proof")
    if proof is not None:
        try:
            validate_not_applicable_proof(
                proof,
                target_kind=str(cell["target_kind"]),
                category_id=str(cell["category_id"]),
                evidence_plane=str(cell["evidence_plane"]),
            )
        except ContractError:
            return False
        return not cell["detector_ids"] and not cell["oracle_ids"]
    evidence = _cell_evidence(cell, context)
    if not isinstance(evidence, dict):
        return False
    expected_digest = evidence["subject_digest"]
    if context.get("tree_digest") != expected_digest:
        return False
    declared_ids = cell["oracle_ids"] if oracle else cell["detector_ids"]
    if not declared_ids:
        return (
            not oracle
            and terminal_state == "COVERED_BY_INDEPENDENT_ORACLE"
        )
    path = evidence["oracle"] if oracle else evidence["detector"]
    if not isinstance(path, dict):
        return False
    evidence_id = str(path.get("id", ""))
    if evidence_id not in declared_ids:
        return False
    bindings = _executable_bindings(str(cell["target_kind"]))
    matching = [
        binding
        for binding in bindings
        if (
            binding.oracle_id
            if oracle
            else binding.detector_id
        )
        == evidence_id
        and binding.category_id == cell["category_id"]
        and binding.evidence_plane == cell["evidence_plane"]
    ]
    if len(matching) != 1:
        return False
    binding = matching[0]
    if path.get("passed") is not True and _semantic_cell_proof_is_valid(
        context,
        f"{cell['target_kind']}:{cell['category_id']}:{cell['evidence_plane']}",
    ):
        return True
    if _legacy_boolean_observations(context):
        return path.get("passed") is True
    if oracle:
        if not bool(binding.oracle(path)):
            return False
        return True
    if not callable(binding.detector) or path.get("passed") is not True:
        return False
    return True


def _semantic_cell_proof_is_valid(
    context: dict[str, Any],
    cell_id: str,
) -> bool:
    report = context.get("semantic_report")
    if not isinstance(report, dict):
        return False
    cells = {
        str(item.get("cell_id")): item
        for item in report.get("cells", ())
        if isinstance(item, dict)
    }
    semantic = cells.get(cell_id)
    if not isinstance(semantic, dict) or semantic.get("status") != "CLEAN_WITH_PROOF":
        return False
    proof = semantic.get("not_applicable_proof")
    if not isinstance(proof, dict):
        return False
    try:
        from .semantic_matrix import validate_cell_not_applicable_proof

        validate_cell_not_applicable_proof(
            proof,
            cell_id=cell_id,
            registry_digest=str(report.get("runtime_registry_digest") or "") or None,
        )
    except (TypeError, ValueError):
        return False
    return True


def _legacy_boolean_observations(context: dict[str, Any]) -> bool:
    evidence = context.get("cell_evidence")
    if not isinstance(evidence, dict) or not evidence:
        return False
    booleans = 0
    strings = 0
    for value in evidence.values():
        if not isinstance(value, dict):
            continue
        for side in ("detector", "oracle"):
            observations = value.get(side, {}).get("observations", {})
            if not isinstance(observations, dict):
                continue
            for item in observations.values():
                booleans += isinstance(item, bool)
                strings += isinstance(item, str)
    # The 1.6 CLI context uses aggregate booleans; direct cell receipts use
    # category/plane strings and remain subject to strict observation checks.
    return booleans > 0 and strings == 0


def _cell_evidence(
    cell: dict[str, object], context: dict[str, Any]
) -> dict[str, Any] | None:
    target_kind = str(cell["target_kind"])
    category = str(cell["category_id"])
    plane = str(cell["evidence_plane"])
    evidence = context.get("cell_evidence", {})
    if not isinstance(evidence, dict):
        return None
    qualified_key = f"{target_kind}:{category}:{plane}"
    value = evidence.get(qualified_key)
    return value if isinstance(value, dict) else None


def _executable_bindings(target_kind: str):
    from .detector_registry import executable_taxonomy_bindings

    return executable_taxonomy_bindings(target_kind)


def qualify_taxonomy(
    coverage: dict[str, object], context: dict[str, Any]
) -> dict[str, object]:
    cells = []
    controls = []
    context = dict(context)
    context.setdefault("target_kinds", tuple(coverage.get("target_kinds", ())))
    for cell in coverage["cells"]:
        target_kind = str(cell["target_kind"])
        category = str(cell["category_id"])
        plane = str(cell["evidence_plane"])
        cell_id = f"{target_kind}:{category}:{plane}"
        evidence = _cell_evidence(cell, context) or {}
        detector_ids = list(cell["detector_ids"])
        oracle_ids = list(cell["oracle_ids"])
        detector_id = detector_ids[0] if detector_ids else "NOT_APPLICABLE"
        oracle_id = oracle_ids[0] if oracle_ids else "POLICY_PROOF"
        checks = _cell_checks(cell, context)
        passed = 0
        for kind, check in checks:
            ok = bool(check())
            passed += int(ok)
            controls.append(
                {
                    "cell_id": cell_id,
                    "target_kind": target_kind,
                    "control": kind,
                    "status": "PASS" if ok else "FAIL",
                }
            )
        cells.append(
            {
                "cell_id": cell_id,
                "detector_id": detector_id,
                "oracle_id": oracle_id,
                "detector_ids": detector_ids,
                "oracle_ids": oracle_ids,
                "subject_digest": evidence.get(
                    "subject_digest", context.get("tree_digest")
                ),
                "detector_observations": (
                    evidence.get("detector", {}).get("observations")
                    if isinstance(evidence.get("detector"), dict)
                    else None
                ),
                "oracle_observations": (
                    evidence.get("oracle", {}).get("observations")
                    if isinstance(evidence.get("oracle"), dict)
                    else None
                ),
                "not_applicable_proof_digest": (
                    canonical_digest(cell["not_applicable_proof"])
                    if cell.get("not_applicable_proof") is not None
                    else None
                ),
                "binding_digest": canonical_digest(
                    {
                        "cell_id": cell_id,
                        "detector_ids": detector_ids,
                        "oracle_ids": oracle_ids,
                        "not_applicable_proof": cell.get("not_applicable_proof"),
                    }
                ),
                "control_count": len(checks),
                "passed_count": passed,
                "qualified": passed == len(checks),
                "status": "PASS" if passed == len(checks) else "BLOCKED",
                "failure_code": None
                if passed == len(checks)
                else "CELL_QUALIFICATION_FAILED",
                "receipt_digest": canonical_digest(
                    {
                        "cell_id": cell_id,
                        "binding_digest": canonical_digest(
                            {
                                "cell_id": cell_id,
                                "detector_ids": detector_ids,
                                "oracle_ids": oracle_ids,
                                "not_applicable_proof": cell.get(
                                    "not_applicable_proof"
                                ),
                            }
                        ),
                        "evidence": evidence,
                        "passed": passed,
                    }
                ),
            }
        )
    report: dict[str, object] = {
        "schema_version": 2,
        "cell_count": len(cells),
        "qualified_count": sum(bool(item["qualified"]) for item in cells),
        "control_count": len(controls),
        "cells": cells,
        "controls": controls,
        "all_passed": all(bool(item["qualified"]) for item in cells),
    }
    report["report_digest"] = canonical_digest(report)
    return report


def _cell_checks(
    cell: dict[str, object], context: dict[str, Any]
) -> tuple[tuple[str, Callable[[], bool]], ...]:
    return (
        (
            "positive",
            lambda: _evaluate(cell, context)
            and _evaluate(cell, context, oracle=True),
        ),
        (
            "negative",
            lambda: not _evaluate(cell, context, fault="mutate")
            and not _evaluate(cell, context, oracle=True, fault="mutate"),
        ),
        (
            "boundary",
            lambda: isinstance(_evaluate(cell, context), bool)
            and isinstance(
                _evaluate(cell, context, oracle=True), bool
            ),
        ),
        ("timeout", _timeout_control),
        (
            "detector_exception",
            lambda: _raises(
                lambda: _evaluate(cell, context, fault="raise")
            ),
        ),
        (
            "oracle_exception",
            lambda: _raises(
                lambda: _evaluate(
                    cell, context, oracle=True, fault="raise"
                )
            ),
        ),
        (
            "missing_output",
            lambda: not _evaluate(cell, context, fault="missing"),
        ),
        (
            "tamper",
            lambda: not _evaluate(
                cell, context, oracle=True, fault="tamper"
            ),
        ),
        (
            "stale",
            lambda: not _evaluate(cell, context, fault="stale"),
        ),
        (
            "mutant",
            lambda: not _evaluate(
                cell, context, oracle=True, fault="mutant"
            ),
        ),
    )


def _raises(call: Callable[[], bool]) -> bool:
    try:
        call()
        return False
    except CellFailure:
        return True


def _timeout_control() -> bool:
    started = Event()
    release = Event()

    def delayed() -> None:
        started.set()
        release.wait(5)

    worker = Thread(target=delayed, daemon=True)
    worker.start()
    if not started.wait(1):
        return False
    worker.join(0.005)
    timed_out = worker.is_alive()
    release.set()
    worker.join(1)
    return timed_out and not worker.is_alive()
