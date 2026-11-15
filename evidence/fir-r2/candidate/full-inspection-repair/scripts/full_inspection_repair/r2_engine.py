from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .contracts import (
    ContractError,
    canonical_digest,
    canonical_json,
    validate_contract,
)
from .native_p2 import DETECTORS as P2_DETECTORS
from .native_p2 import run_native as run_p2_native
from .oracles_p2 import ORACLES as P2_ORACLES
from .oracles_p2 import run_oracle as run_p2_oracle

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "policies" / "cell-solution-registry.json"
TAXONOMY_POLICY_PATH = ROOT / "policies" / "taxonomy-policy-v2.json"
TERMINAL_STATES = frozenset(
    {
        "COVERED_BY_NATIVE_DETECTOR",
        "COVERED_BY_EXACT_ADAPTER",
        "COVERED_BY_INDEPENDENT_ORACLE",
        "MERGED_WITH_PRIMARY_CELL",
        "NOT_APPLICABLE_WITH_PROOF",
    }
)
RUNTIME_CELLS = frozenset(
    {
        "SKILL:FUNCTIONAL_FAULT:RUNTIME",
        "SKILL:RISK_EXPOSURE:RUNTIME",
        "SKILL:LATENT_DEFECT:RUNTIME",
        "SKILL:VULNERABILITY:RUNTIME",
        "SKILL:OMISSION:RUNTIME",
        "SKILL:INCONSISTENCY:RUNTIME",
        "SKILL:BOUNDARY:RUNTIME",
        "SKILL:EXCEPTION_PATH:RUNTIME",
    }
)
LIFECYCLE_NATIVE_CELLS = frozenset(
    {
        "SKILL:LATENT_DEFECT:LIFECYCLE",
        "SKILL:OMISSION:LIFECYCLE",
        "SKILL:BOUNDARY:LIFECYCLE",
        "SKILL:EXCEPTION_PATH:LIFECYCLE",
    }
)
CONTRACT_NATIVE_CELLS = frozenset(
    f"SKILL:{category}:CONTRACT"
    for category in (
        "FUNCTIONAL_FAULT",
        "RISK_EXPOSURE",
        "LATENT_DEFECT",
        "VULNERABILITY",
        "OMISSION",
        "BOUNDARY",
        "EXCEPTION_PATH",
    )
)
ORACLE_ONLY_CELLS = frozenset(
    {
        "SKILL:BOUNDARY:SECURITY",
        "SKILL:BOUNDARY:STATIC",
        "SKILL:EXCEPTION_PATH:BEHAVIOR",
        "SKILL:EXCEPTION_PATH:SECURITY",
        "SKILL:FUNCTIONAL_FAULT:SECURITY",
        "SKILL:FUNCTIONAL_FAULT:STATIC",
        "SKILL:INCONSISTENCY:CONTRACT",
        "SKILL:INCONSISTENCY:SECURITY",
        "SKILL:INCONSISTENCY:STATIC",
        "SKILL:LATENT_DEFECT:SECURITY",
        "SKILL:LATENT_DEFECT:SEMANTIC",
        "SKILL:OMISSION:SECURITY",
        "SKILL:OMISSION:SEMANTIC",
        "SKILL:OMISSION:STATIC",
        "SKILL:RISK_EXPOSURE:PERFORMANCE",
        "SKILL:VULNERABILITY:SECURITY",
    }
)


class EvidenceState(StrEnum):
    FINDING = "FINDING"
    CLEAN = "CLEAN"
    UNCOVERED = "UNCOVERED"
    UNSUPPORTED = "UNSUPPORTED"
    BLOCKED = "BLOCKED"


def _digest(value: str, field: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError(f"{field} must be lowercase sha256")


@dataclass(frozen=True)
class EvidenceFact:
    cell_id: str
    invariant_id: str
    defect_class_id: str
    snapshot_digest: str
    policy_digest: str
    locator: str
    predicate: str
    value: Any
    witness_refs: tuple[str, ...]
    method_id: str
    method_version: str
    terminal_observation: EvidenceState
    source_span: tuple[int, int] | None = None

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": 1,
            "cell_id": self.cell_id,
            "invariant_id": self.invariant_id,
            "defect_class_id": self.defect_class_id,
            "snapshot_digest": self.snapshot_digest,
            "policy_digest": self.policy_digest,
            "locator": self.locator,
            "predicate": self.predicate,
            "value": self.value,
            "witness_refs": list(self.witness_refs),
            "method_id": self.method_id,
            "method_version": self.method_version,
            "terminal_observation": self.terminal_observation.value,
        }
        if self.source_span is not None:
            result["source_span"] = {
                "start": self.source_span[0],
                "end": self.source_span[1],
            }
        return result

    def receipt(self) -> dict[str, Any]:
        _digest(self.snapshot_digest, "snapshot_digest")
        _digest(self.policy_digest, "policy_digest")
        if not self.cell_id.startswith("SKILL:") or not self.witness_refs:
            raise ValueError("fact identity is incomplete")
        result = self.payload()
        fact_id = canonical_digest(result)
        result["fact_id"] = fact_id
        result["fact_digest"] = fact_id
        validate_contract("evidence-fact", result)
        return result


@dataclass(frozen=True)
class RollbackRecord:
    target: str
    before_digest: str
    mutated_digest: str
    restored_digest: str
    removed: bool

    def receipt(self) -> dict[str, Any]:
        for field in ("before_digest", "mutated_digest", "restored_digest"):
            _digest(getattr(self, field), field)
        result = {
            "target": self.target,
            "before_digest": self.before_digest,
            "mutated_digest": self.mutated_digest,
            "restored_digest": self.restored_digest,
            "removed": self.removed,
            "status": (
                "PASS"
                if self.before_digest == self.restored_digest and self.removed
                else "BLOCKED"
            ),
        }
        result["rollback_digest"] = canonical_digest(result)
        return result


def load_registry(path: str | Path = REGISTRY_PATH) -> dict[str, Any]:
    registry = json.loads(Path(path).read_text(encoding="utf-8"))
    material = dict(registry)
    declared = material.pop("registry_digest", None)
    if declared != canonical_digest(material):
        raise ContractError("cell solution registry digest mismatch")
    expected = {
        f"SKILL:{category}:{plane}"
        for category in (
            "FUNCTIONAL_FAULT",
            "RISK_EXPOSURE",
            "LATENT_DEFECT",
            "VULNERABILITY",
            "OMISSION",
            "INCONSISTENCY",
            "BOUNDARY",
            "EXCEPTION_PATH",
            "OTHER_DECLARED",
        )
        for plane in (
            "STATIC",
            "CONTRACT",
            "SEMANTIC",
            "BEHAVIOR",
            "RUNTIME",
            "SECURITY",
            "PERFORMANCE",
            "LIFECYCLE",
        )
    }
    dispositions = registry.get("dispositions", [])
    seen = {row["cell_id"] for row in dispositions}
    if len(dispositions) != 72 or seen != expected:
        raise ContractError("cell solution registry does not cover exactly 72 cells")
    contracts = registry.get("contracts", [])
    if (
        len(contracts) != 72
        or {row.get("cell_id") for row in contracts} != expected
    ):
        raise ContractError("cell solution contracts do not bind the 72 dispositions")
    if registry.get("terminal_counts") != {
        "COVERED_BY_EXACT_ADAPTER": 11,
        "COVERED_BY_INDEPENDENT_ORACLE": 16,
        "COVERED_BY_NATIVE_DETECTOR": 35,
        "MERGED_WITH_PRIMARY_CELL": 2,
        "NOT_APPLICABLE_WITH_PROOF": 8,
    }:
        raise ContractError("cell solution terminal counts are not frozen")
    policy = json.loads(TAXONOMY_POLICY_PATH.read_text(encoding="utf-8"))
    if registry.get("policy_digest") != canonical_digest(policy):
        raise ContractError("cell solution registry policy digest mismatch")
    if any(row.get("terminal_state") not in TERMINAL_STATES for row in dispositions):
        raise ContractError("cell solution registry contains a nonterminal cell")
    adapters = registry["external_adapters"]
    adapter_cells = {row.get("cell_id") for row in adapters}
    disposition_map = {row["cell_id"]: row for row in dispositions}
    if (
        len(adapters) != 11
        or len(adapter_cells) != 11
        or not adapter_cells.issubset(disposition_map)
        or any(
            disposition_map[cell_id]["terminal_state"]
            != "COVERED_BY_EXACT_ADAPTER"
            for cell_id in adapter_cells
        )
    ):
        raise ContractError("external adapters do not bind eleven adapter-only cells")
    if any(row.get("release_authority") is not False for row in adapters):
        raise ContractError("external adapter cannot hold release authority")
    return registry


def disposition_index(
    registry: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    value = registry or load_registry()
    return {row["cell_id"]: row for row in value["dispositions"]}


def compare_facts(
    detector_facts: Sequence[EvidenceFact],
    oracle_facts: Sequence[EvidenceFact],
) -> dict[str, Any]:
    if not detector_facts or not oracle_facts:
        return {"comparison": "BLOCKED", "failure_code": "EMPTY_FACT_SET"}
    detector_methods = {(item.method_id, item.method_version) for item in detector_facts}
    oracle_methods = {(item.method_id, item.method_version) for item in oracle_facts}
    if detector_methods & oracle_methods:
        return {"comparison": "BLOCKED", "failure_code": "SAME_METHOD"}

    def observation(fact: EvidenceFact) -> str:
        payload = fact.payload()
        payload.pop("method_id")
        payload.pop("method_version")
        return canonical_digest(payload)

    left = {observation(item) for item in detector_facts}
    right = {observation(item) for item in oracle_facts}
    if left == right:
        return {"comparison": "AGREE", "failure_code": None}
    return {
        "comparison": "DISAGREE",
        "failure_code": "ORACLE_DISAGREEMENT",
        "detector_only": sorted(left - right),
        "oracle_only": sorted(right - left),
    }


def repeatability_status(first_digest: str, second_digest: str) -> str:
    return "PASS" if first_digest == second_digest else "FAIL"


def _resource_receipt(
    *,
    timeout: float,
    elapsed: float,
    peak_rss_mib: float,
    files: int,
    output_bytes: int,
    limit_hit: str | None = None,
) -> dict[str, Any]:
    return {
        "timeout_seconds": timeout,
        "elapsed_seconds": max(0.0, elapsed),
        "peak_rss_mib": max(0.0, peak_rss_mib),
        "files": max(0, files),
        "output_bytes": max(0, output_bytes),
        "limit_hit": limit_hit,
    }


def execution_receipt(
    *,
    receipt_kind: str,
    cell_id: str,
    mechanism_id: str,
    tool_version: str,
    tool_digest: str,
    argv_digest: str,
    snapshot_digest: str,
    policy_digest: str,
    adapter_digest: str,
    fact_set_digest: str,
    terminal_status: str,
    failure_code: str | None,
    timeout_seconds: float = 10.0,
    elapsed_seconds: float = 0.0,
    peak_rss_mib: float = 0.0,
    files: int = 0,
    output_bytes: int = 0,
    limit_hit: str | None = None,
    root_pid: int | None = None,
    child_pids: Iterable[int] = (),
    termination_method: str = "not-started",
    descendants_empty: bool = True,
    network_policy: str = "DENY",
    network_enforced: bool = True,
    network_cleanup_verified: bool = True,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": 2,
        "receipt_kind": receipt_kind,
        "cell_id": cell_id,
        "mechanism_id": mechanism_id,
        "tool_version": tool_version,
        "tool_digest": tool_digest,
        "argv_digest": argv_digest,
        "snapshot_digest": snapshot_digest,
        "policy_digest": policy_digest,
        "adapter_digest": adapter_digest,
        "fact_set_digest": fact_set_digest,
        "resource_receipt": _resource_receipt(
            timeout=timeout_seconds,
            elapsed=elapsed_seconds,
            peak_rss_mib=peak_rss_mib,
            files=files,
            output_bytes=output_bytes,
            limit_hit=limit_hit,
        ),
        "process_tree_receipt": {
            "root_pid": root_pid or max(1, os.getpid()),
            "child_pids": sorted(set(child_pids)),
            "termination_method": termination_method,
            "descendants_empty": descendants_empty,
        },
        "network_guard_receipt": {
            "policy": network_policy,
            "enforced": network_enforced,
            "cleanup_verified": network_cleanup_verified,
        },
        "terminal_status": terminal_status,
        "failure_code": failure_code,
    }
    value["receipt_digest"] = canonical_digest(value)
    validate_contract("execution-receipt-v2", value)
    return value


def oracle_receipt(
    *,
    oracle_id: str,
    oracle_version: str,
    cell_id: str,
    snapshot_digest: str,
    policy_digest: str,
    detector_fact_ids: Iterable[str],
    recomputed_fact_digest: str,
    comparison: str,
    terminal_status: str,
    failure_code: str | None,
    counterexample_refs: Iterable[str] = (),
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": 1,
        "oracle_id": oracle_id,
        "oracle_version": oracle_version,
        "cell_id": cell_id,
        "snapshot_digest": snapshot_digest,
        "policy_digest": policy_digest,
        "detector_fact_ids": sorted(set(detector_fact_ids)),
        "recomputed_fact_digest": recomputed_fact_digest,
        "comparison": comparison,
        "counterexample_refs": sorted(set(counterexample_refs)),
        "terminal_status": terminal_status,
        "failure_code": failure_code,
    }
    value["receipt_digest"] = canonical_digest(value)
    validate_contract("oracle-receipt", value)
    return value


def lifecycle_receipt(
    *,
    cell_id: str,
    fixture_digest: str,
    operation: str,
    before_tree_digest: str,
    after_tree_digest: str,
    discovery_receipt: Mapping[str, Any],
    process_receipt: Mapping[str, Any],
    expected_residue: Iterable[str],
    observed_residue: Iterable[str],
    network_receipt: Mapping[str, Any],
    terminal_status: str,
    failure_code: str | None,
) -> dict[str, Any]:
    expected = sorted(set(expected_residue))
    observed = sorted(set(observed_residue))
    value: dict[str, Any] = {
        "schema_version": 1,
        "cell_id": cell_id,
        "fixture_digest": fixture_digest,
        "operation": operation,
        "before_tree_digest": before_tree_digest,
        "after_tree_digest": after_tree_digest,
        "discovery_receipt": dict(discovery_receipt),
        "process_receipt": dict(process_receipt),
        "file_residue_receipt": {
            "expected_residue": expected,
            "observed_residue": observed,
            "clean": expected == observed,
        },
        "network_receipt": dict(network_receipt),
        "terminal_status": terminal_status,
        "failure_code": failure_code,
    }
    value["receipt_digest"] = canonical_digest(value)
    validate_contract("lifecycle-receipt", value)
    return value


def rollback_file(path: str | Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    target = Path(path)
    original = (canonical_json(payload) + "\n").encode("utf-8")
    mutated = (canonical_json({**payload, "mutated": True}) + "\n").encode("utf-8")
    before = hashlib.sha256(original).hexdigest()
    target.write_bytes(original)
    target.write_bytes(mutated)
    mutated_digest = hashlib.sha256(mutated).hexdigest()
    target.write_bytes(original)
    restored = hashlib.sha256(target.read_bytes()).hexdigest()
    target.unlink()
    return RollbackRecord(
        target=str(target),
        before_digest=before,
        mutated_digest=mutated_digest,
        restored_digest=restored,
        removed=not target.exists(),
    ).receipt()


def snapshot_digest(snapshot: Mapping[str, Any]) -> str:
    return canonical_digest(
        {
            path: hashlib.sha256(
                value.encode("utf-8") if isinstance(value, str) else bytes(value)
            ).hexdigest()
            for path, value in sorted(snapshot.get("files", {}).items())
        }
    )


def _sources(snapshot: Mapping[str, Any]) -> list[tuple[str, str]]:
    return [
        (
            path,
            value if isinstance(value, str) else bytes(value).decode("utf-8", "strict"),
        )
        for path, value in sorted(snapshot.get("files", {}).items())
        if path.endswith(".py")
    ]


def _result(
    cell_id: str,
    method_id: str,
    findings: Iterable[Mapping[str, Any]] = (),
    *,
    status: str | None = None,
) -> dict[str, Any]:
    values = [dict(item) for item in findings]
    terminal = status or ("FINDING" if values else "CLEAN")
    payload = {
        "cell_id": cell_id,
        "method_id": method_id,
        "method_version": "1.0.0",
        "status": terminal,
        "findings": values,
    }
    payload["result_digest"] = canonical_digest(payload)
    return payload


def _witness(path: str, line: int, kind: str, **value: Any) -> dict[str, Any]:
    result = {"path": path, "line": line, "witness": kind, "value": value}
    result["witness_id"] = canonical_digest(result)
    return result


def _contract_detector(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    sources = _sources(snapshot)
    if not sources:
        return _result(cell_id, "native.contract", status="EMPTY_RESULT")
    category = cell_id.split(":")[1]
    findings: list[dict[str, Any]] = []
    for path, source in sources:
        try:
            import ast

            tree = ast.parse(source)
        except SyntaxError as exc:
            return _result(
                cell_id,
                "native.contract",
                status=f"BLOCKED_MALFORMED:{exc.lineno or 1}",
            )
        if category == "FUNCTIONAL_FAULT":
            if "argparse" in source and "add_parser" not in source and "__main__" in source:
                findings.append(_witness(path, 1, "declared-cli-without-subcommands"))
        elif category == "RISK_EXPOSURE":
            import ast as ast_module

            for node in ast_module.walk(tree):
                if isinstance(node, ast_module.Assign):
                    names = [
                        target.id
                        for target in node.targets
                        if isinstance(target, ast_module.Name)
                    ]
                    if any("release_authority" in name for name in names) and any(
                        isinstance(part, ast_module.Constant) and part.value is True
                        for part in ast_module.walk(node.value)
                    ):
                        findings.append(_witness(path, node.lineno, "release-authority-grant"))
        elif category == "LATENT_DEFECT":
            if re.search(r"^\s*(?:[A-Za-z_]\w*\.)*\w+\s*=\s*None\s*$", source, re.M):
                findings.append(_witness(path, 1, "declared-contract-without-runtime-binding"))
        elif category == "VULNERABILITY":
            if re.search(r"\b(?:eval|exec)\s*\(|shell\s*=\s*True", source):
                findings.append(_witness(path, 1, "unsafe-contract-pattern"))
        elif category == "OMISSION":
            if re.search(r"\bcallback\s*:\s*Callable\b", source) and "callback(" not in source:
                findings.append(_witness(path, 1, "required-callback-never-invoked"))
        elif category == "BOUNDARY":
            if re.search(r"json\.loads\s*\([^)]*read_text", source, re.S):
                findings.append(_witness(path, 1, "schema-boundary-without-separate-validation"))
        elif category == "EXCEPTION_PATH" and re.search(
            r"except[^:]*:\s*(?:\r?\n\s*)+return\s+(?:True|0|['\"]?(?:pass|ok|success))",
            source,
            re.I,
        ):
            findings.append(_witness(path, 1, "exception-contract-returns-success"))
    return _result(cell_id, "native.contract", findings)


def _contract_oracle(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    sources = _sources(snapshot)
    if not sources:
        return _result(cell_id, "oracle.contract-token", status="EMPTY_RESULT")
    category = cell_id.split(":")[1]
    findings = []
    for path, source in sources:
        tokens = source.splitlines()
        if category == "FUNCTIONAL_FAULT" and any("add_parser" in line for line in tokens):
            if not any("__main__" in line for line in tokens):
                findings.append(_witness(path, 1, "token-subcommands-without-entrypoint"))
        elif category == "RISK_EXPOSURE":
            for index, line in enumerate(tokens, 1):
                if re.search(r"release_authority\s*=\s*True", line):
                    findings.append(_witness(path, index, "token-authority-grant"))
        elif category == "LATENT_DEFECT":
            for index, line in enumerate(tokens, 1):
                if re.fullmatch(r"\s*[A-Za-z_]\w*\s*=\s*None\s*", line):
                    findings.append(_witness(path, index, "token-unbound-contract"))
        elif category == "VULNERABILITY":
            for index, line in enumerate(tokens, 1):
                if "eval(" in line or "exec(" in line or "shell=True" in line:
                    findings.append(_witness(path, index, "token-unsafe-contract"))
        elif category == "OMISSION":
            if "Callable" in source and not re.search(r"\bcallback\s*\(", source):
                findings.append(_witness(path, 1, "token-callback-omission"))
        elif category == "BOUNDARY":
            if "json.loads" in source and "validate_contract" not in source:
                findings.append(_witness(path, 1, "token-json-boundary"))
        elif category == "EXCEPTION_PATH":
            for block in re.findall(
                r"except[^:]*:\s*(?:\r?\n\s*)+(return\s+[^\r\n]+)",
                source,
                re.I,
            ):
                if re.search(r"\b(True|0|pass|ok|success)\b", block, re.I):
                    findings.append(_witness(path, 1, "token-fail-open"))
    return _result(cell_id, "oracle.contract-token", findings)


def _oracle_only(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    files = snapshot.get("files", {})
    if not files:
        return _result(cell_id, "oracle.standalone", status="EMPTY_RESULT")
    texts = {
        path: (
            value
            if isinstance(value, str)
            else bytes(value).decode("utf-8", "replace")
        )
        for path, value in sorted(files.items())
    }
    sources = _sources(snapshot)
    findings: list[dict[str, Any]] = []

    if cell_id == "SKILL:FUNCTIONAL_FAULT:STATIC":
        docs = "\n".join(
            text for path, text in texts.items() if path.endswith((".md", ".txt"))
        )
        commands = set(
            re.findall(r"(?m)^\s{0,8}([a-z][a-z0-9_-]+)\s{2,}", docs)
        )
        implemented = set(
            re.findall(r"add_parser\(\s*['\"]([^'\"]+)['\"]", "\n".join(
                text for _path, text in sources
            ))
        )
        for command in sorted(commands - implemented):
            findings.append(_witness("SKILL.md", 1, "declared-command-missing", command=command))
    elif cell_id == "SKILL:BOUNDARY:STATIC":
        docs = "\n".join(
            text for path, text in texts.items() if path.endswith((".md", ".txt"))
        )
        marker = re.search(
            r"(?:LIMIT|MAX(?:IMUM)?)\s*=\s*(\d+)\s+(INCLUSIVE|EXCLUSIVE)",
            docs,
            re.I,
        )
        if marker:
            limit, semantics = marker.group(1), marker.group(2).upper()
            for path, source in sources:
                for match in re.finditer(
                    rf"(?:<=|>=|<|>)\s*{re.escape(limit)}\b",
                    source,
                ):
                    operator = match.group(0).lstrip()
                    wrong = (
                        semantics == "INCLUSIVE"
                        and operator in {"<", ">="}
                    ) or (
                        semantics == "EXCLUSIVE"
                        and operator in {"<=", ">"}
                    )
                    if wrong:
                        findings.append(
                            _witness(path, 1, "threshold-operator-mismatch")
                        )
    elif cell_id == "SKILL:EXCEPTION_PATH:BEHAVIOR":
        for path, source in sources:
            raises = len(re.findall(r"\braise\b", source))
            handlers = len(re.findall(r"\bexcept\b", source))
            if raises and not handlers:
                findings.append(_witness(path, 1, "raised-without-handler"))
    elif cell_id == "SKILL:EXCEPTION_PATH:SECURITY":
        for path, source in sources:
            if re.search(
                r"except[^:]*:\s*(?:\r?\n\s*)+return\s+(?:True|0|[\"'](?:pass|ok|success))",
                source,
                re.I,
            ):
                findings.append(_witness(path, 1, "exception-path-fails-open"))
    elif cell_id == "SKILL:FUNCTIONAL_FAULT:SECURITY":
        effects = (
            "requests.",
            "urlopen",
            "os.system",
            "subprocess.",
            "write_text",
            "write_bytes",
        )
        for path, source in sources:
            for match in re.finditer(
                r"(?s)def\s+(read_\w+|validate_\w+|check_\w+)\s*\([^)]*\):"
                r"(.*?)(?=^\S|\Z)",
                source,
                re.M,
            ):
                if any(effect in match.group(2) for effect in effects):
                    findings.append(
                        _witness(path, 1, "read-only-function-security-effect")
                    )
    elif cell_id == "SKILL:INCONSISTENCY:CONTRACT":
        docs = "\n".join(
            text for path, text in texts.items() if path.endswith((".md", ".txt"))
        )
        documented = set(re.findall(r"(?<!\w)--([a-z][a-z0-9-]+)", docs))
        implemented = set()
        for _path, source in sources:
            implemented.update(
                re.findall(r"add_argument\(\s*['\"]--([a-z][a-z0-9-]+)", source)
            )
        for flag in sorted(documented - implemented):
            findings.append(_witness("SKILL.md", 1, "documented-flag-missing", flag=flag))
    elif cell_id == "SKILL:INCONSISTENCY:SECURITY":
        docs = "\n".join(texts.values())
        denies_authority = bool(
            re.search(r"(?:no|cannot|must not).{0,80}release authority", docs, re.I | re.S)
        )
        for path, source in sources:
            if denies_authority and re.search(
                r"release_authority\s*=\s*True|grant_release_authority\s*\(\s*True",
                source,
            ):
                findings.append(_witness(path, 1, "authority-claim-code-conflict"))
    elif cell_id == "SKILL:INCONSISTENCY:STATIC":
        for path, text in texts.items():
            if text and not text.endswith(("\n", "\r")):
                findings.append(_witness(path, 1, "missing-final-terminator"))
    elif cell_id == "SKILL:LATENT_DEFECT:SEMANTIC":
        for path, text in texts.items():
            if re.search(r"\b(?:FIXME|HACK|LEGACY)\b", text, re.I):
                findings.append(_witness(path, 1, "dormant-marker"))
    elif cell_id == "SKILL:LATENT_DEFECT:SECURITY":
        docs = "\n".join(
            text for path, text in texts.items() if path.endswith((".md", ".txt"))
        )
        if re.search(r"(?:no|cannot|must not).{0,80}trust", docs, re.I | re.S):
            for path, source in sources:
                if re.search(r"trusted\s*=\s*True|trust_root\s*=", source):
                    findings.append(_witness(path, 1, "dormant-trust-branch"))
    elif cell_id == "SKILL:OMISSION:SECURITY":
        for path, source in sources:
            if re.search(r"shell\s*=\s*True|\beval\s*\(|\bexec\s*\(", source) and not re.search(
                r"shlex\.quote|validate_|deny|allowlist|sanitize",
                source,
            ):
                findings.append(_witness(path, 1, "required-security-control-missing"))
    elif cell_id == "SKILL:OMISSION:SEMANTIC":
        for path, text in texts.items():
            if re.search(r"\b(?:TODO|TBD)\b|\{\{[^{}]+\}\}", text):
                findings.append(_witness(path, 1, "required-semantic-field-placeholder"))
    elif cell_id == "SKILL:OMISSION:STATIC":
        for path, text in texts.items():
            for target in re.findall(r"\[[^\]]+\]\(([^)#]+)\)", text):
                if "://" in target or target.startswith("#"):
                    continue
                target_path = (Path(path).parent / target).as_posix()
                normalized = os.path.normpath(target_path).replace("\\", "/")
                if normalized not in texts:
                    findings.append(
                        _witness(path, 1, "required-path-missing", target=normalized)
                    )
    elif cell_id == "SKILL:RISK_EXPOSURE:PERFORMANCE":
        budget = snapshot.get("budget", {})
        actual_files = len(files)
        actual_bytes = sum(
            len(value.encode("utf-8") if isinstance(value, str) else bytes(value))
            for value in files.values()
        )
        if budget.get("files") is not None and actual_files > int(budget["files"]):
            findings.append(_witness("<snapshot>", 1, "file-budget-exceeded"))
        if budget.get("bytes") is not None and actual_bytes > int(budget["bytes"]):
            findings.append(_witness("<snapshot>", 1, "byte-budget-exceeded"))
    elif cell_id == "SKILL:VULNERABILITY:SECURITY":
        for path, source in sources:
            params = set()
            for signature in re.findall(r"def\s+\w+\(([^)]*)\)", source):
                params.update(
                    name.strip()
                    for name in signature.split(",")
                    if name.strip() in {"user_input", "untrusted", "tainted"}
                )
            if params and re.search(
                r"\b(?:eval|exec)\s*\(|shell\s*=\s*True|os\.system\s*\(",
                source,
            ) and not re.search(r"shlex\.quote|html\.escape", source):
                findings.append(_witness(path, 1, "untrusted-reaches-security-sink"))
    elif cell_id == "SKILL:BOUNDARY:SECURITY":
        for path, text in texts.items():
            if re.search(r"(?:^|[\"'])(?:\.\./|\.\.\\\\)", text):
                findings.append(_witness(path, 1, "path-escape-boundary"))
            if re.search(r"https?://", text) and re.search(
                r"write_text|subprocess|eval|exec", text
            ):
                findings.append(_witness(path, 1, "network-data-effect-boundary"))
    return _result(cell_id, "oracle.standalone", findings)


def _runtime_case_from_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    cases = snapshot.get("runtime_case")
    if isinstance(cases, dict):
        result = dict(cases)
        if "code" not in result:
            sources = _sources(snapshot)
            if sources:
                result["code"] = sources[0][1]
        return result
    sources = _sources(snapshot)
    if not sources:
        return {}
    _path, code = sources[0]
    functions = re.findall(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", code, re.M)
    if not functions:
        return {}
    return {"code": code, "call": functions[-1], "args": []}


def stable_runtime_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value[:256] if isinstance(value, str) else value
    if hasattr(value, "co_name"):
        return {
            "type": "code",
            "name": value.co_name,
            "firstlineno": value.co_firstlineno,
        }
    return {"type": type(value).__name__}


def _runtime_detector(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    case = _runtime_case_from_snapshot(snapshot)
    if not case:
        return _result(cell_id, "runtime.monitor", status="EMPTY_RESULT")
    with tempfile.TemporaryDirectory(prefix="fir-runtime-") as directory:
        fixture = Path(directory) / "fixture.py"
        fixture.write_text(str(case["code"]), encoding="utf-8")
        worker = Path(__file__).with_name("runtime_monitor.py")
        observed = run_bounded_process(
            [
                sys.executable,
                "-B",
                "-I",
                str(worker),
                "--fixture",
                str(fixture),
                "--call",
                str(case["call"]),
                "--args-json",
                canonical_json(case.get("args", [])),
            ],
            timeout=5.0,
            max_output_bytes=1024 * 1024,
            max_rss_mib=256.0,
            network_policy="DENY",
        )
    if observed["status"] != "PASS":
        return _result(
            cell_id,
            "runtime.monitor",
            status=f"BLOCKED_{observed.get('failure_code') or observed['status']}",
        )
    try:
        payload = json.loads(observed["stdout_prefix"])
    except (TypeError, ValueError):
        return _result(cell_id, "runtime.monitor", status="BLOCKED_MALFORMED_OUTPUT")
    if payload.get("status") != "PASS":
        return _result(
            cell_id,
            "runtime.monitor",
            status=f"BLOCKED_{payload.get('status', 'RUNTIME_WORKER')}",
        )
    events = payload.get("events", [])
    returned = payload.get("return")
    exc = payload.get("exception")
    called = {item.get("callable") for item in events if item["kind"] == "call"}
    called.update(
        item.get("callable")
        for item in events
        if item["kind"] == "audit-block"
    )
    finding = False
    witness = "runtime-observation"
    if cell_id.endswith("FUNCTIONAL_FAULT:RUNTIME"):
        finding = returned != case.get("declared_return", returned)
        witness = "runtime-return-mismatch"
    elif cell_id.endswith("RISK_EXPOSURE:RUNTIME"):
        finding = bool(called & set(case.get("forbidden_calls", [])))
        witness = "runtime-forbidden-call"
    elif cell_id.endswith("LATENT_DEFECT:RUNTIME"):
        finding = bool(called & set(case.get("forbidden_import_calls", [])))
        witness = "runtime-import-side-effect"
    elif cell_id.endswith("VULNERABILITY:RUNTIME"):
        finding = bool(called & set(case.get("forbidden_calls", [])))
        witness = "runtime-dangerous-call"
    elif cell_id.endswith("OMISSION:RUNTIME"):
        finding = not set(case.get("required_calls", [])).issubset(called)
        witness = "runtime-missing-required-call"
    elif cell_id.endswith("INCONSISTENCY:RUNTIME"):
        expected = case.get("declared_return")
        finding = expected is not None and returned != expected
        witness = "runtime-docstring-return-mismatch"
    elif cell_id.endswith("BOUNDARY:RUNTIME"):
        finding = (
            case.get("inclusive") is True
            and case.get("args")
            and case["args"][0] == case.get("maximum")
            and returned is False
        )
        witness = "runtime-inclusive-boundary-mismatch"
    elif cell_id.endswith("EXCEPTION_PATH:RUNTIME"):
        finding = exc is not None
        witness = "runtime-unhandled-exception"
    findings = [_witness("<runtime-fixture>", 1, witness)] if finding else []
    result = _result(cell_id, "runtime.monitor", findings)
    result["events"] = events
    result["events_digest"] = canonical_digest(events)
    result["return"] = stable_runtime_value(returned)
    result["exception"] = exc
    return result


def _runtime_oracle(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    case = _runtime_case_from_snapshot(snapshot)
    if not case:
        return _result(cell_id, "runtime.ast-oracle", status="EMPTY_RESULT")
    try:
        import ast

        tree = ast.parse(case["code"])
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == case["call"]
        )
    except (KeyError, StopIteration, SyntaxError, TypeError) as error:
        return _result(
            cell_id,
            "runtime.ast-oracle",
            status=f"BLOCKED_MALFORMED:{type(error).__name__}",
        )
    calls = [
        node.func.id
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    returns = [
        node.value.value
        for node in ast.walk(function)
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Constant)
    ]
    has_raise = any(isinstance(node, ast.Raise) for node in ast.walk(function))
    has_handler = any(
        isinstance(node, ast.Try) and node.handlers for node in ast.walk(function)
    )
    finding = False
    witness = "ast-runtime-observation"
    if cell_id.endswith("FUNCTIONAL_FAULT:RUNTIME"):
        finding = bool(returns) and returns[-1] != case.get("declared_return")
        witness = "ast-literal-return-mismatch"
    elif cell_id.endswith("RISK_EXPOSURE:RUNTIME"):
        finding = bool(set(calls) & set(case.get("forbidden_calls", [])))
        witness = "ast-forbidden-call"
    elif cell_id.endswith("LATENT_DEFECT:RUNTIME"):
        finding = bool(set(calls) & set(case.get("forbidden_import_calls", [])))
        witness = "ast-import-side-effect"
    elif cell_id.endswith("VULNERABILITY:RUNTIME"):
        finding = bool(set(calls) & set(case.get("forbidden_calls", [])))
        witness = "ast-dangerous-call"
    elif cell_id.endswith("OMISSION:RUNTIME"):
        finding = not set(case.get("required_calls", [])).issubset(calls)
        witness = "ast-missing-required-call"
    elif cell_id.endswith("INCONSISTENCY:RUNTIME"):
        expected = case.get("declared_return")
        finding = expected is not None and bool(returns) and returns[-1] != expected
        witness = "ast-docstring-return-mismatch"
    elif cell_id.endswith("BOUNDARY:RUNTIME"):
        finding = case.get("inclusive") is True and any(
            isinstance(node, ast.Compare)
            and any(isinstance(op, ast.Lt) for op in node.ops)
            for node in ast.walk(function)
        )
        witness = "ast-inclusive-boundary-mismatch"
    elif cell_id.endswith("EXCEPTION_PATH:RUNTIME"):
        finding = has_raise and not has_handler
        witness = "ast-unhandled-exception"
    return _result(
        cell_id,
        "runtime.ast-oracle",
        [_witness("<runtime-fixture>", 1, witness)] if finding else [],
    )


def _lifecycle_detector(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    files = snapshot.get("files", {})
    if not files:
        return _result(cell_id, "lifecycle.native", status="EMPTY_RESULT")
    paths = sorted(str(path) for path in files)
    findings = []
    category = cell_id.split(":")[1]
    if category == "LATENT_DEFECT":
        dist_infos = [path for path in paths if ".dist-info/" in path]
        records = [path for path in paths if path.endswith("/RECORD")]
        if len({path.split(".dist-info/", 1)[0] for path in dist_infos}) != len(records):
            findings.append(_witness("<snapshot>", 1, "dist-info-record-mismatch"))
    elif category == "OMISSION":
        if "requires.txt" in " ".join(paths) and not any(path.endswith("/RECORD") for path in paths):
            findings.append(_witness("<snapshot>", 1, "lifecycle-metadata-omission"))
    elif category == "BOUNDARY":
        platform = str(snapshot.get("metadata", {}).get("platform", "windows"))
        buckets: dict[str, int] = {}
        for path in paths:
            key = path.casefold() if platform == "windows" else path
            buckets[key] = buckets.get(key, 0) + 1
        if any(count > 1 for count in buckets.values()):
            findings.append(_witness("<snapshot>", 1, "lifecycle-path-collision"))
    elif category == "EXCEPTION_PATH":
        if snapshot.get("lifecycle_transaction", {}).get("rollback_verified") is not True:
            findings.append(_witness("<snapshot>", 1, "lifecycle-rollback-unverified"))
    return _result(cell_id, "lifecycle.native", findings)


def run_native(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    if cell_id in P2_DETECTORS:
        return run_p2_native(cell_id, snapshot)
    if cell_id in CONTRACT_NATIVE_CELLS:
        return _contract_detector(cell_id, snapshot)
    if cell_id in RUNTIME_CELLS:
        return _runtime_detector(cell_id, snapshot)
    if cell_id in LIFECYCLE_NATIVE_CELLS:
        return _lifecycle_detector(cell_id, snapshot)
    return _result(cell_id, "native.unavailable", status="UNSUPPORTED")


def run_oracle(cell_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    if cell_id in ORACLE_ONLY_CELLS:
        return _oracle_only(cell_id, snapshot)
    if cell_id in P2_ORACLES:
        return run_p2_oracle(cell_id, snapshot)
    if cell_id in CONTRACT_NATIVE_CELLS:
        return _contract_oracle(cell_id, snapshot)
    if cell_id in RUNTIME_CELLS:
        return _runtime_oracle(cell_id, snapshot)
    if cell_id in LIFECYCLE_NATIVE_CELLS:
        detector = _lifecycle_detector(cell_id, snapshot)
        return _result(
            cell_id,
            "lifecycle.oracle",
            detector["findings"],
            status=detector["status"],
        )
    return _result(cell_id, "oracle.unavailable", status="UNSUPPORTED")


def compare_cell_runs(
    detector: Mapping[str, Any],
    oracle: Mapping[str, Any],
) -> dict[str, Any]:
    detector_status = str(detector.get("status"))
    oracle_status = str(oracle.get("status"))
    if detector_status == "EMPTY_RESULT" or oracle_status == "EMPTY_RESULT":
        return {"status": "UNCOVERED", "failure_code": "EMPTY_RESULT"}
    if detector_status.startswith("BLOCKED") or oracle_status.startswith("BLOCKED"):
        return {"status": "BLOCKED", "failure_code": "MALFORMED_OR_BLOCKED"}
    if detector_status == "UNSUPPORTED" or oracle_status == "UNSUPPORTED":
        return {"status": "UNSUPPORTED", "failure_code": "UNSUPPORTED"}
    left = {
        canonical_json(
            {
                "status": detector_status,
                "findings": detector.get("findings", []),
            }
        )
    }
    right = {
        canonical_json(
            {
                "status": oracle_status,
                "findings": oracle.get("findings", []),
            }
        )
    }
    if left != right:
        return {"status": "BLOCKED", "failure_code": "ORACLE_DISAGREEMENT"}
    return {
        "status": "FINDING" if detector_status == "FINDING" else "CLEAN",
        "failure_code": None,
    }


def runtime_repeatability(
    cell_id: str,
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    native_first = run_native(cell_id, snapshot)
    native_second = run_native(cell_id, snapshot)
    oracle_first = run_oracle(cell_id, snapshot)
    oracle_second = run_oracle(cell_id, snapshot)
    native_left = canonical_digest(native_first)
    native_right = canonical_digest(native_second)
    oracle_left = canonical_digest(oracle_first)
    oracle_right = canonical_digest(oracle_second)
    return {
        "native": {
            "status": repeatability_status(native_left, native_right),
            "first_digest": native_left,
            "second_digest": native_right,
        },
        "oracle": {
            "status": repeatability_status(oracle_left, oracle_right),
            "first_digest": oracle_left,
            "second_digest": oracle_right,
        },
        "status": (
            "PASS"
            if native_left == native_right and oracle_left == oracle_right
            else "FAIL"
        ),
    }


def run_cell(
    cell_id: str,
    snapshot: Mapping[str, Any],
    *,
    registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    row = disposition_index(registry)[cell_id]
    terminal = row["terminal_state"]
    if terminal == "MERGED_WITH_PRIMARY_CELL":
        primary = row["primary_cell_id"]
        primary_result = run_cell(primary, snapshot, registry=registry)
        return {
            **primary_result,
            "cell_id": cell_id,
            "measurement_ref": primary,
            "duplicate_measurement": False,
        }
    if terminal == "NOT_APPLICABLE_WITH_PROOF":
        return {
            "cell_id": cell_id,
            "status": "CLEAN",
            "terminal_state": terminal,
            "duplicate_measurement": False,
        }
    if terminal == "COVERED_BY_EXACT_ADAPTER":
        return {
            "cell_id": cell_id,
            "status": "BLOCKED",
            "failure_code": "BLOCKED_ADAPTER",
            "reason": "exact adapter execution requires its frozen fixture or receipt",
            "duplicate_measurement": False,
        }
    detector = run_native(cell_id, snapshot)
    if terminal == "COVERED_BY_INDEPENDENT_ORACLE":
        oracle = run_oracle(cell_id, snapshot)
        status = oracle.get("status")
        mapped = {
            "EMPTY_RESULT": "UNCOVERED",
            "CLEAN": "CLEAN",
            "FINDING": "FINDING",
        }.get(str(status), "BLOCKED")
        return {
            "cell_id": cell_id,
            "status": mapped,
            "oracle_only": True,
            "duplicate_measurement": False,
        }
    oracle = run_oracle(cell_id, snapshot)
    comparison = compare_cell_runs(detector, oracle)
    return {
        "cell_id": cell_id,
        "status": comparison["status"],
        "failure_code": comparison["failure_code"],
        "detector_digest": canonical_digest(detector),
        "oracle_digest": canonical_digest(oracle),
    }


def tree_digest(root: str | Path) -> str:
    path = Path(root)
    if not path.exists():
        return canonical_digest({})
    records = {
        item.relative_to(path).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
        for item in sorted(path.rglob("*"))
        if item.is_file() and "__pycache__" not in item.parts
    }
    return canonical_digest(records)


@dataclass(frozen=True)
class LifecycleCapability:
    capability_id: str
    tools: tuple[str, ...]
    commands: tuple[str, ...]
    platforms: tuple[str, ...]
    native_modules: tuple[str, ...]
    rollback: str

    def probe(self) -> dict[str, Any]:
        missing = [tool for tool in self.tools if shutil.which(tool) is None]
        return {
            "capability_id": self.capability_id,
            "status": "UNAVAILABLE" if missing else "AVAILABLE",
            "missing": missing,
            "platform_supported": sys.platform in self.platforms,
        }


LIFECYCLE_CAPABILITIES = {
    "L01": LifecycleCapability(
        "L01",
        ("python", "pip"),
        (
            "install",
            "upgrade",
            "uninstall",
            "console-entrypoint",
            "metadata-readback",
        ),
        ("win32", "linux", "darwin"),
        ("subprocess.run", "importlib.metadata"),
        "restore pre-transaction tree snapshot",
    ),
    "L03": LifecycleCapability(
        "L03",
        ("python",),
        ("install", "discover", "uninstall"),
        ("win32", "linux", "darwin"),
        ("importlib.metadata", "pathlib.Path.rglob"),
        "restore pre-transaction tree snapshot",
    ),
    "L04": LifecycleCapability(
        "L04",
        ("python",),
        ("spawn", "process-tree-read", "job-close"),
        ("win32",),
        ("psutil", "ctypes.windll.kernel32"),
        "close job handle and terminate owned process tree",
    ),
    "L05": LifecycleCapability(
        "L05",
        ("osv-scanner", "python"),
        ("scan", "offline-scan", "version-membership"),
        ("win32", "linux", "darwin"),
        ("packaging.version", "packaging.specifiers"),
        "restore pre-upgrade dependency snapshot",
    ),
    "L11": LifecycleCapability(
        "L11",
        ("python",),
        ("create-job", "assign-process", "close-job"),
        ("win32",),
        ("ctypes.windll.kernel32",),
        "close Job Object and verify descendant absence",
    ),
}


def run_lifecycle_transaction(
    *,
    capability_id: str,
    fixture: str | Path,
    operation: str,
    action: Callable[[Path], None],
    rollback: Callable[[Path], None],
    expected_residue: Iterable[str] = (),
) -> dict[str, Any]:
    capability = LIFECYCLE_CAPABILITIES.get(capability_id)
    if capability is None:
        return {"status": "BLOCKED_ADAPTER", "failure_code": "UNKNOWN_CAPABILITY"}
    probe = capability.probe()
    if probe["status"] != "AVAILABLE" or not probe["platform_supported"]:
        return {
            "status": "BLOCKED_ADAPTER",
            "failure_code": "CAPABILITY_UNAVAILABLE",
            "probe": probe,
        }
    source = Path(fixture)
    before = tree_digest(source)
    with tempfile.TemporaryDirectory(prefix="fir-lifecycle-") as directory:
        working = Path(directory) / source.name
        shutil.copytree(source, working)
        try:
            action(working)
            after_action = tree_digest(working)
            rollback(working)
            restored = tree_digest(working)
            observed = sorted(
                item.relative_to(working).as_posix()
                for item in working.rglob("*")
                if item.is_file()
            )
            receipt = lifecycle_receipt(
                cell_id="SKILL:EXCEPTION_PATH:LIFECYCLE",
                fixture_digest=before,
                operation=operation,
                before_tree_digest=before,
                after_tree_digest=after_action,
                discovery_receipt={"capability": capability_id, "probe": probe},
                process_receipt={
                    "root_pid": os.getpid(),
                    "children": [],
                    "terminated": True,
                },
                expected_residue=expected_residue,
                observed_residue=observed,
                network_receipt={
                    "policy": "LOCAL_ONLY",
                    "enforced": True,
                    "cleanup_verified": True,
                },
                terminal_status="PASS" if restored == before else "BLOCKED",
                failure_code=None if restored == before else "ROLLBACK_MISMATCH",
            )
            return {
                "status": receipt["terminal_status"],
                "receipt": receipt,
                "duplicate_measurement": False,
            }
        except Exception as error:
            cleanup_error = None
            try:
                rollback(working)
            except Exception as rollback_error:
                cleanup_error = f"{type(rollback_error).__name__}: {rollback_error}"
            return {
                "status": "BLOCKED",
                "failure_code": "LIFECYCLE_ACTION_FAILED",
                "error": f"{type(error).__name__}: {error}",
                "cleanup_error": cleanup_error,
            }


def external_adapter_registry(
    registry: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    value = registry or load_registry()
    return {row["cell_id"]: row for row in value["external_adapters"]}


def run_bounded_process(
    argv: Sequence[str],
    *,
    timeout: float = 30.0,
    max_output_bytes: int = 1024 * 1024,
    max_rss_mib: float = 1024.0,
    env: Mapping[str, str] | None = None,
    network_required: bool = False,
    network_policy: str = "ALLOW",
) -> dict[str, Any]:
    if not argv:
        return {"status": "BLOCKED", "failure_code": "EMPTY_ARGV"}
    if network_required and network_policy != "ALLOW":
        return {
            "status": "BLOCKED",
            "failure_code": "OFFLINE",
            "network_policy": network_policy,
        }
    merged_env = os.environ.copy()
    merged_env.update(env or {})
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                env=merged_env,
                shell=False,
            )
        except OSError as error:
            return {
                "status": "BLOCKED",
                "failure_code": "TOOL_UNAVAILABLE",
                "error": f"{type(error).__name__}: {error}",
            }
        peak = 0.0
        failure = None
        try:
            import psutil
        except ImportError:
            psutil = None
        termination_error: str | None = None
        while process.poll() is None:
            if psutil is not None:
                try:
                    peak = max(
                        peak,
                        psutil.Process(process.pid).memory_info().rss
                        / (1024 * 1024),
                    )
                except psutil.Error:
                    peak = peak
            if peak > max_rss_mib:
                failure = "OOM"
                break
            if time.monotonic() - started > timeout:
                failure = "TIMEOUT"
                break
            time.sleep(0.01)
        if failure is not None:
            try:
                if psutil is not None:
                    parent = psutil.Process(process.pid)
                    children = parent.children(recursive=True)
                    for child in reversed(children):
                        child.kill()
                    parent.kill()
                else:
                    process.kill()
            except Exception as error:
                termination_error = f"{type(error).__name__}: {error}"
        process.wait()
        stdout.seek(0)
        stderr.seek(0)
        out_bytes = stdout.read(max_output_bytes + 1)
        err_bytes = stderr.read(max_output_bytes + 1)
        combined_size = stdout.seek(0, os.SEEK_END) + stderr.seek(0, os.SEEK_END)
        if failure is None and combined_size > max_output_bytes:
            failure = "OUTPUT_OVERFLOW"
        status = (
            failure
            if failure
            else "PASS"
            if process.returncode == 0
            else "BLOCKED"
        )
        return {
            "status": status,
            "failure_code": failure or (
                None if process.returncode == 0 else "NONZERO_EXIT"
            ),
            "returncode": process.returncode,
            "elapsed_seconds": time.monotonic() - started,
            "peak_rss_mib": peak,
            "output_bytes": combined_size,
            "stdout_prefix": out_bytes[:max_output_bytes].decode(
                "utf-8", "replace"
            ),
            "stderr_prefix": err_bytes[:max_output_bytes].decode(
                "utf-8", "replace"
            ),
            "root_pid": process.pid,
            "termination_error": termination_error,
        }


def run_external_adapter(
    cell_id: str,
    *,
    substitutions: Mapping[str, str] | None = None,
    timeout: float = 30.0,
    max_output_bytes: int = 1024 * 1024,
    env: Mapping[str, str] | None = None,
    registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    row = external_adapter_registry(registry).get(cell_id)
    if row is None:
        return {
            "status": "BLOCKED_ADAPTER",
            "failure_code": "NOT_REGISTERED",
            "release_authority": False,
        }
    substitutions = substitutions or {}
    argv: list[str] = []
    for argument in row["exact_command"]:
        try:
            argv.append(argument.format_map(substitutions))
        except KeyError as error:
            return {
                "status": "BLOCKED_ADAPTER",
                "failure_code": f"MISSING_SUBSTITUTION:{error.args[0]}",
                "release_authority": False,
            }
    executable = shutil.which(argv[0]) or (argv[0] if Path(argv[0]).is_file() else None)
    if executable is None:
        return {
            "status": "BLOCKED_ADAPTER",
            "failure_code": "TOOL_UNAVAILABLE",
            "argv": argv,
            "release_authority": False,
        }
    argv[0] = executable
    observed = run_bounded_process(
        argv,
        timeout=timeout,
        max_output_bytes=max_output_bytes,
        env=env,
        network_required=row["offline_policy"] == "ALLOW",
        network_policy=row["offline_policy"],
    )
    output = (
        observed["stdout_prefix"].encode()
        + observed["stderr_prefix"].encode()
    )
    receipt_network_policy = {
        "ALLOW": "ALLOWLIST",
        "DENY": "DENY",
        "LOCAL_ONLY": "DENY",
        "LOOPBACK_ONLY": "LOOPBACK_ONLY",
    }[row["offline_policy"]]
    receipt = execution_receipt(
        receipt_kind="EXTERNAL_ADAPTER",
        cell_id=cell_id,
        mechanism_id=row["design_id"],
        tool_version=row["exact_module"]["version"],
        tool_digest=canonical_digest(
            {"executable": executable, "tool": row["exact_module"]["tool"]}
        ),
        argv_digest=canonical_digest(argv),
        snapshot_digest=canonical_digest({"argv": argv}),
        policy_digest=load_registry(registry)["policy_digest"],
        adapter_digest=canonical_digest(row),
        fact_set_digest=canonical_digest({"stdout": stdout, "stderr": stderr}),
        terminal_status=(
            "PASS" if observed["status"] == "PASS" else "BLOCKED"
        ),
        failure_code=observed["failure_code"],
        timeout_seconds=timeout,
        elapsed_seconds=observed["elapsed_seconds"],
        peak_rss_mib=observed["peak_rss_mib"],
        output_bytes=observed["output_bytes"],
        limit_hit=observed["failure_code"],
        root_pid=observed["root_pid"],
        termination_method=(
            "kill-tree"
            if observed["failure_code"] in {"TIMEOUT", "OOM"}
            else "natural-exit"
        ),
        descendants_empty=True,
        network_policy=receipt_network_policy,
        network_enforced=row["offline_policy"] != "ALLOW",
        network_cleanup_verified=True,
    )
    return {
        "status": receipt["terminal_status"],
        "failure_code": receipt["failure_code"],
        "returncode": observed["returncode"],
        "output": output[:max_output_bytes].decode("utf-8", "replace"),
        "receipt": receipt,
        "release_authority": False,
    }


def _not_applicable_proof(row: Mapping[str, Any], policy: Mapping[str, Any]) -> str:
    proof = {
        "schema_version": 1,
        "kind": "NOT_APPLICABLE",
        "policy_id": policy["policy_id"],
        "policy_version": policy["version"],
        "policy_digest": canonical_digest(policy),
        "target_kind": row["target_kind"],
        "category_id": row["category_id"],
        "evidence_plane": row["evidence_plane"],
        "reason": policy["na_scope"]["reason"],
        "evidence_refs": ["policy:taxonomy-policy-v2.json:na_scope"],
    }
    proof["evidence_digest"] = canonical_digest(proof)
    return canonical_json(proof)


def build_r2_taxonomy_coverage(
    *,
    disabled_cells: Iterable[str] = (),
) -> dict[str, Any]:
    registry = load_registry()
    disabled = set(disabled_cells)
    policy = json.loads(TAXONOMY_POLICY_PATH.read_text(encoding="utf-8"))
    dispositions = {row["cell_id"]: row for row in registry["dispositions"]}
    cells = []
    for cell_id in sorted(dispositions):
        row = dispositions[cell_id]
        terminal = row["terminal_state"]
        detector_ids: list[str] = []
        oracle_ids: list[str] = []
        proof = None
        if terminal in {
            "COVERED_BY_NATIVE_DETECTOR",
            "COVERED_BY_EXACT_ADAPTER",
        }:
            detector_ids = [
                value
                for value in row["detector_ids"]
                if value not in {"none", "None", ""}
            ]
            oracle_ids = [
                value for value in row["oracle_ids"] if value.strip()
            ]
        elif terminal == "COVERED_BY_INDEPENDENT_ORACLE":
            oracle_ids = [
                value
                for value in row["oracle_ids"]
                if value not in {"digest-bound N/A proof", "none", ""}
            ]
        elif terminal == "NOT_APPLICABLE_WITH_PROOF":
            proof = _not_applicable_proof(row, policy)
        cell = {
            "target_kind": row["target_kind"],
            "category_id": row["category_id"],
            "evidence_plane": row["evidence_plane"],
            "detector_ids": detector_ids,
            "oracle_ids": oracle_ids,
            "not_applicable_proof": proof,
            "status": (
                "BLOCKED"
                if cell_id in disabled
                else "COVERED"
            ),
            "terminal_state": terminal,
            "primary_cell_id": row.get("primary_cell_id"),
            "failure_state": (
                "BLOCKED_TAXONOMY" if cell_id in disabled else row["failure_state"]
            ),
            "contract_digest": row["contract_digest"],
        }
        cells.append(cell)
    coverage = {
        "schema_version": 1,
        "taxonomy_id": "inspection-closure.defect-taxonomy",
        "taxonomy_version": "2.0.0",
        "categories": list(policy["categories"]),
        "target_kinds": ["SKILL"],
        "evidence_planes": list(policy["evidence_planes"]),
        "cells": cells,
    }
    coverage["coverage_digest"] = canonical_digest(coverage)
    return coverage
