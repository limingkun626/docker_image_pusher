from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .capabilities import (
    CAPABILITY_ROOT,
    CapabilityBlocked,
    _resolve_logical_command,
    _substitute,
    _tree_binding,
    _tool_identity,
    fixture_case_identity,
    load_fixtures,
    load_pack,
    run_fixture_case,
    run_slice,
)
from .contracts import canonical_digest


class AdapterBlocked(RuntimeError):
    def __init__(self, failure_code: str, message: str) -> None:
        super().__init__(message)
        self.failure_code = failure_code


@dataclass(frozen=True)
class AdapterSpec:
    logical_tool_id: str
    version: str
    slice_id: str
    predicate: str
    invariant: str
    defect_class: str
    cells: tuple[str, ...]


PYTEST = AdapterSpec(
    logical_tool_id="pytest",
    version="9.1.1",
    slice_id="SLICE-57d9534a5fb62f57",
    predicate="behavioral-assertion-failure",
    invariant="declared behavior must match observed scenario outcome",
    defect_class="behavior.observed-failure",
    cells=(
        "SKILL:FUNCTIONAL_FAULT:BEHAVIOR",
        "SKILL:OMISSION:BEHAVIOR",
    ),
)
SCHEMATHESIS = AdapterSpec(
    logical_tool_id="schemathesis",
    version="4.33.4",
    slice_id="SLICE-703d9804d88fad61",
    predicate="response-schema-mismatch",
    invariant="observed behavior must conform to the declared schema",
    defect_class="behavior.schema-mismatch",
    cells=(
        "SKILL:RISK_EXPOSURE:BEHAVIOR",
        "SKILL:INCONSISTENCY:BEHAVIOR",
        "SKILL:BOUNDARY:BEHAVIOR",
    ),
)
MUTMUT = AdapterSpec(
    logical_tool_id="mutmut",
    version="3.8.0",
    slice_id="SLICE-b0f2f0e6cb318280",
    predicate="surviving-mutant-presence",
    invariant="tests must kill semantic mutations",
    defect_class="tests.surviving-mutant",
    cells=("SKILL:LATENT_DEFECT:BEHAVIOR",),
)
OPENGREP = AdapterSpec(
    logical_tool_id="opengrep",
    version="2.0.0",
    slice_id="SLICE-8511218645035615",
    predicate="security-pattern-presence",
    invariant="frozen security rules must have no matching finding",
    defect_class="security.rule-match",
    cells=("SKILL:VULNERABILITY:BEHAVIOR",),
)
IMPORT_LINTER = AdapterSpec(
    logical_tool_id="import-linter",
    version="2.16",
    slice_id="SLICE-4c97c069b2d3b694",
    predicate="forbidden-import-presence",
    invariant="configured lifecycle imports must satisfy the frozen contract",
    defect_class="lifecycle.import-contract",
    cells=("SKILL:INCONSISTENCY:LIFECYCLE",),
)

ADAPTERS = {
    cell_id: spec
    for spec in (PYTEST, SCHEMATHESIS, MUTMUT, OPENGREP, IMPORT_LINTER)
    for cell_id in spec.cells
}


def _manifest(spec: AdapterSpec) -> dict[str, Any]:
    selected = load_pack(slice_ids=[spec.slice_id])["slices"]
    if len(selected) != 1:
        raise AdapterBlocked("EXACT_ADAPTER_REGISTRY_MISMATCH", spec.slice_id)
    return selected[0]


def _facts(
    cell_id: str,
    spec: AdapterSpec,
    receipt: Mapping[str, Any],
) -> list[dict[str, Any]]:
    outcome = receipt.get("outcome")
    if outcome not in {"FINDING", "CLEAN"}:
        return []
    fact = {
        "cell_id": cell_id,
        "invariant_id": spec.invariant,
        "defect_class_id": spec.defect_class,
        "normalized_locator": ".",
        "logical_unit_id": spec.logical_tool_id,
        "predicate_id": spec.predicate,
        "normalized_value_digest": canonical_digest(
            {"outcome": outcome, "predicate": spec.predicate}
        ),
    }
    fact["fact_digest"] = canonical_digest(fact)
    return [fact]


def adapter_receipt(
    *,
    cell_id: str,
    logical_tool_id: str,
    mechanism_id: str,
    status: str,
    failure_code: str | None,
    executable: str | None,
    interpreter: str | None,
    expected_version: str,
    observed_version: str | None,
    argv: list[str],
    rule_digest: str | None,
    fixture_digest: str | None,
    target_digest: str | None,
    closure_digest: str | None,
    facts: list[dict[str, Any]],
    inner_receipt: Mapping[str, Any] | None = None,
    fixture_binding: Mapping[str, Any] | None = None,
    fixture_execution: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    value = {
        "schema_version": 3,
        "receipt_kind": "EXACT_ADAPTER",
        "cell_id": cell_id,
        "logical_tool_id": logical_tool_id,
        "mechanism_id": mechanism_id,
        "status": status,
        "failure_code": failure_code,
        "release_authority": False,
        "tool_identity": {
            "executable": executable,
            "interpreter": interpreter,
            "expected_version": expected_version,
            "observed_version": observed_version,
            "argv": argv,
            "argv_digest": canonical_digest(argv),
            "rule_digest": rule_digest,
            "fixture_digest": fixture_digest,
            "target_digest": target_digest,
            "closure_digest": closure_digest,
        },
        "facts": facts,
        "fixture_binding": (
            dict(fixture_binding) if fixture_binding is not None else None
        ),
        "fixture_execution": (
            dict(fixture_execution) if fixture_execution is not None else None
        ),
        "inner_receipt_digest": (
            canonical_digest(inner_receipt) if inner_receipt is not None else None
        ),
    }
    value["receipt_digest"] = canonical_digest(value)
    return value


def run_external_cell(
    cell_id: str,
    scratch_root: str | Path | None = None,
    *,
    fixture_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    spec = ADAPTERS.get(cell_id)
    if spec is None:
        return adapter_receipt(
            cell_id=cell_id,
            logical_tool_id="unregistered",
            mechanism_id="unregistered",
            status="BLOCKED_ADAPTER",
            failure_code="EXACT_ADAPTER_NOT_REGISTERED",
            executable=None,
            interpreter=None,
            expected_version="",
            observed_version=None,
            argv=[],
            rule_digest=None,
            fixture_digest=None,
            target_digest=None,
            closure_digest=None,
            facts=[],
        )
    manifest = _manifest(spec)
    fixtures = load_fixtures()["slices"]
    fixture = fixtures.get(spec.slice_id)
    if fixture is None:
        return adapter_receipt(
            cell_id=cell_id,
            logical_tool_id=spec.logical_tool_id,
            mechanism_id=spec.slice_id,
            status="BLOCKED_ADAPTER",
            failure_code="EXACT_ADAPTER_FIXTURE_UNAVAILABLE",
            executable=None,
            interpreter=None,
            expected_version=spec.version,
            observed_version=None,
            argv=[],
            rule_digest=manifest.get("rules_digest"),
            fixture_digest=None,
            target_digest=None,
            closure_digest=None,
            facts=[],
        )
    try:
        identities = {
            mode: fixture_case_identity(fixture, mode)
            for mode in ("positive", "negative")
        }
    except (CapabilityBlocked, KeyError) as error:
        return adapter_receipt(
            cell_id=cell_id,
            logical_tool_id=spec.logical_tool_id,
            mechanism_id=spec.slice_id,
            status="BLOCKED_ADAPTER",
            failure_code="EXACT_ADAPTER_FIXTURE_UNAVAILABLE",
            executable=None,
            interpreter=None,
            expected_version=spec.version,
            observed_version=None,
            argv=[],
            rule_digest=manifest.get("rules_digest"),
            fixture_digest=None,
            target_digest=None,
            closure_digest=None,
            facts=[],
        )
    if fixture_identity is not None:
        supplied = fixture_identity.get("fixture_digest")
        expected = {
            item["fixture_digest"] for item in identities.values()
        } | {canonical_digest(identities)}
        if supplied is not None and supplied not in expected:
            return adapter_receipt(
                cell_id=cell_id,
                logical_tool_id=spec.logical_tool_id,
                mechanism_id=spec.slice_id,
                status="BLOCKED_ADAPTER",
                failure_code="FIXTURE_IDENTITY_MISMATCH",
                executable=None,
                interpreter=None,
                expected_version=spec.version,
                observed_version=None,
                argv=[],
                rule_digest=manifest.get("rules_digest"),
                fixture_digest=str(supplied),
                target_digest=None,
                closure_digest=None,
                facts=[],
            )
    scratch_context = (
        tempfile.TemporaryDirectory(prefix="fir-exact-adapter-")
        if scratch_root is None
        else None
    )
    scratch = Path(scratch_context.name) if scratch_context else Path(scratch_root)
    scratch.mkdir(parents=True, exist_ok=True)
    try:
        positive = run_fixture_case(
            manifest,
            fixture,
            "positive",
            scratch_root=scratch,
        )
        negative = run_fixture_case(
            manifest,
            fixture,
            "negative",
            scratch_root=scratch,
        )
    finally:
        if scratch_context is not None:
            scratch_context.cleanup()
    values = {
        "target": str(scratch),
        "tooling": str(CAPABILITY_ROOT / "tooling"),
    }
    command = _resolve_logical_command(
        _substitute(list(manifest["command_template"]), values)
    )
    identity = _tool_identity(manifest, command)
    passed = (
        positive["terminal_status"] == "PASS"
        and negative["terminal_status"] == "PASS"
        and positive.get("outcome") == "FINDING"
        and negative.get("outcome") == "CLEAN"
        and "fixture_error" not in positive
        and "fixture_error" not in negative
    )
    facts = _facts(cell_id, spec, positive) if passed else []
    pair_fixture_digest = canonical_digest(identities)
    target_digest = canonical_digest(
        {
            "positive": positive["subject_digest"],
            "negative": negative["subject_digest"],
        }
    )
    return adapter_receipt(
        cell_id=cell_id,
        logical_tool_id=spec.logical_tool_id,
        mechanism_id=spec.slice_id,
        status="PASS" if passed else "BLOCKED_ADAPTER",
        failure_code=(
            None
            if passed
            else "FIXTURE_ASSERTION_FAILED"
            if (
                "fixture_error" in positive
                or "fixture_error" in negative
            )
            else str(
                positive.get("failure_code")
                or negative.get("failure_code")
                or "FIXTURE_ASSERTION_FAILED"
            )
        ),
        executable=identity["executable"],
        interpreter=identity["interpreter"],
        expected_version=spec.version,
        observed_version=identity["observed_version"],
        argv=command,
        rule_digest=manifest.get("rules_digest"),
        fixture_digest=pair_fixture_digest,
        target_digest=target_digest,
        closure_digest=identity["closure_digest"],
        facts=facts,
        inner_receipt={
            "positive": positive,
            "negative": negative,
            "fixture_identity": identities,
        },
        fixture_binding=identities,
        fixture_execution={
            "positive": positive,
            "negative": negative,
        },
    )


def run_for_snapshot(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    target_root = snapshot.get("target_root")
    if not isinstance(target_root, (str, Path)) or not Path(target_root).is_dir():
        return {
            "cell_id": cell_id,
            "status": "BLOCKED_ADAPTER",
            "failure_code": "TARGET_REQUIRED",
            "release_authority": False,
            "facts": [],
        }
    scratch_root = snapshot.get("fixture_scratch_root")
    fixture_identity = snapshot.get("fixture_identity")
    qualification = run_external_cell(
        cell_id,
        (
            scratch_root
            if isinstance(scratch_root, str)
            else None
        ),
        fixture_identity=(
            fixture_identity if isinstance(fixture_identity, dict) else None
        ),
    )
    if qualification.get("status") != "PASS":
        return qualification
    spec = ADAPTERS.get(cell_id)
    if spec is None:
        return qualification
    try:
        target_manifest = _manifest(spec)
        with tempfile.TemporaryDirectory(prefix="fir-exact-target-") as directory:
            target_copy = Path(directory).resolve() / "target"
            shutil.copytree(target_root, target_copy)
            target_copy_digest = str(_tree_binding(target_copy)["sha256"])
            target_receipt = run_slice(
                target_manifest,
                target_copy,
                mutation_copy_digest=target_copy_digest,
            )
    except (CapabilityBlocked, OSError, ValueError) as error:
        return adapter_receipt(
            cell_id=cell_id,
            logical_tool_id=spec.logical_tool_id,
            mechanism_id=spec.slice_id,
            status="BLOCKED_ADAPTER",
            failure_code="TARGET_EXECUTION_FAILED",
            executable=qualification["tool_identity"]["executable"],
            interpreter=qualification["tool_identity"]["interpreter"],
            expected_version=spec.version,
            observed_version=qualification["tool_identity"]["observed_version"],
            argv=qualification["tool_identity"]["argv"],
            rule_digest=qualification["tool_identity"]["rule_digest"],
            fixture_digest=qualification["tool_identity"]["fixture_digest"],
            target_digest=str(snapshot.get("subject_digest") or ""),
            closure_digest=qualification["tool_identity"]["closure_digest"],
            facts=[],
            inner_receipt={
                "qualification": qualification,
                "target_error": f"{type(error).__name__}: {error}",
            },
            fixture_binding=qualification.get("fixture_binding"),
            fixture_execution=qualification.get("fixture_execution"),
        )
    outcome = target_receipt.get("outcome")
    status = (
        "FINDING"
        if target_receipt.get("terminal_status") == "PASS" and outcome == "FINDING"
        else "PASS"
        if target_receipt.get("terminal_status") == "PASS" and outcome == "CLEAN"
        else "BLOCKED_ADAPTER"
    )
    target_for_facts = dict(target_receipt)
    target_for_facts["outcome"] = outcome
    facts = _facts(cell_id, spec, target_for_facts) if status == "FINDING" else []
    return adapter_receipt(
        cell_id=cell_id,
        logical_tool_id=spec.logical_tool_id,
        mechanism_id=spec.slice_id,
        status=status,
        failure_code=(
            None
            if status in {"PASS", "FINDING"}
            else str(target_receipt.get("failure_code") or "TARGET_EXECUTION_NOT_CONCLUSIVE")
        ),
        executable=qualification["tool_identity"]["executable"],
        interpreter=qualification["tool_identity"]["interpreter"],
        expected_version=spec.version,
        observed_version=qualification["tool_identity"]["observed_version"],
        argv=qualification["tool_identity"]["argv"],
        rule_digest=qualification["tool_identity"]["rule_digest"],
        fixture_digest=qualification["tool_identity"]["fixture_digest"],
        target_digest=str(target_receipt.get("subject_digest") or ""),
        closure_digest=qualification["tool_identity"]["closure_digest"],
        facts=facts,
        inner_receipt={
            "qualification": qualification,
            "target_execution": target_receipt,
        },
        fixture_binding=qualification.get("fixture_binding"),
        fixture_execution=qualification.get("fixture_execution"),
    )


def run_pytest(
    target: str | Path,
    *,
    cell_id: str = "SKILL:FUNCTIONAL_FAULT:BEHAVIOR",
    **kwargs: Any,
) -> dict[str, Any]:
    return run_external_cell(cell_id, target, **kwargs)


def run_schemathesis(
    target: str | Path,
    *,
    cell_id: str = "SKILL:RISK_EXPOSURE:BEHAVIOR",
    **kwargs: Any,
) -> dict[str, Any]:
    return run_external_cell(cell_id, target, **kwargs)


def run_mutmut(
    target: str | Path,
    *,
    cell_id: str = "SKILL:LATENT_DEFECT:BEHAVIOR",
    **kwargs: Any,
) -> dict[str, Any]:
    return run_external_cell(cell_id, target, **kwargs)


def run_opengrep(
    target: str | Path,
    *,
    cell_id: str = "SKILL:VULNERABILITY:BEHAVIOR",
    **kwargs: Any,
) -> dict[str, Any]:
    return run_external_cell(cell_id, target, **kwargs)


def run_import_linter(
    target: str | Path,
    *,
    cell_id: str = "SKILL:INCONSISTENCY:LIFECYCLE",
    **kwargs: Any,
) -> dict[str, Any]:
    return run_external_cell(cell_id, target, **kwargs)
