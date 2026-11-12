from __future__ import annotations

import time
from collections.abc import Callable
from queue import Empty, Queue
from threading import Thread
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
        return False
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
    if oracle:
        return bool(binding.oracle(path))
    return callable(binding.detector) and path.get("passed") is True


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
    result: Queue[bool] = Queue(maxsize=1)

    def delayed() -> None:
        time.sleep(0.05)
        result.put(True)

    worker = Thread(target=delayed, daemon=True)
    worker.start()
    worker.join(0.005)
    if worker.is_alive():
        return True
    try:
        result.get_nowait()
    except Empty:
        return False
    return False
