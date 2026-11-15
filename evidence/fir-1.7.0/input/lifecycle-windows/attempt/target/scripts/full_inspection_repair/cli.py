from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import sys
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .adapters import AdapterError, build_required_sources, build_subject
from .capabilities import (
    CapabilityBlocked,
    run_contract_matrix,
    run_pack,
    validate_pack,
)
from .candidate_closure import (
    ClosureError,
    build_candidate_source_inventory,
    require_candidate_closure,
)
from .contracts import (
    ContractError,
    build_run_manifest,
    canonical_digest,
    dir_hash1,
    material_digest,
    validate_contract,
    validate_risk_ledger_consistency,
)
from .controlplane import ControlPlaneBlocked, resolve_layout
from .coverage import build_complete_coverage
from .detector_registry import default_taxonomy_coverage
from .detectors import DEFAULT_DETECTORS, DetectorResult, run_default_detectors
from .impact import assert_impact_closed, build_impact_graph
from .knowledge import (
    KnowledgeError,
    default_knowledge_pack,
    load_frozen_pack_files,
)
from .ledger import build_risk_ledger
from .observation import ObservationJournal
from .protected_reader import MAX_FILE_BYTES
from .repair import RepairBlocked, apply_batch, plan_batch
from .runtime_registry import RegistryError, current_platform, load_registry
from .semantic_matrix import execute_semantic_matrix
from .source_inventory import (
    SourceInventoryError,
    assert_source_closure_complete,
    build_source_closure,
    build_source_closure_evidence,
    build_source_inventory,
)
from .state_machine import advance
from .strict import (
    StrictJSONError,
    fsync_directory,
    strict_loads,
    write_all,
)
from .taxonomy import assert_taxonomy_complete
from .taxonomy_qualification import qualify_taxonomy
from .verification import (
    VerificationBlocked,
    reconcile_detector_results,
    verify_repair,
)
from .verification_matrix import MatrixBlocked, reconcile_evaluation
from .write_ahead import (
    WriteAheadJournal,
    load_journal_checkpoint,
    verify_journal,
    write_journal_checkpoint,
)


class EvidenceBlocked(ContractError):
    """Raised when durable evidence cannot be trusted."""


class StaleInputBlocked(ContractError):
    """Raised when a frozen input changed during the run."""


class TaxonomyBlocked(ContractError):
    """Raised when frozen taxonomy coverage is incomplete."""


REDACTION_POLICY_VERSION = "2.0.0"
_REDACTION_RULES = (
    (
        "private-key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("openai-token", re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "secret-assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|token|secret|password)\b"
            r"(\s*[:=]\s*)[\"']?([^\s\"']+)"
        ),
    ),
    (
        "email",
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    ),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("home-path", re.compile(r"(?i)([A-Z]:[\\/]Users[\\/]|/home/)[^\\/\s]+")),
)


def _redaction_policy_digest() -> str:
    return canonical_digest(
        {
            "policy": "full-inspection-repair-redaction",
            "version": REDACTION_POLICY_VERSION,
            "rules": [name for name, _ in _REDACTION_RULES],
        }
    )


def _redact_text(value: str) -> str:
    redacted = value
    for name, pattern in _REDACTION_RULES:
        if name == "secret-assignment":
            redacted = pattern.sub(r"\1\2[REDACTED_SECRET]", redacted)
        elif name == "home-path":
            redacted = pattern.sub(r"\1[REDACTED_USER]", redacted)
        else:
            redacted = pattern.sub(f"[REDACTED_{name.upper()}]", redacted)
    return redacted


def _redact_value(value: object) -> object:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _artifact_path(relative: str) -> Path:
    return Path(__file__).resolve().parents[2] / relative


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _detector_ids() -> list[str]:
    return [str(row[0]) for row in DEFAULT_DETECTORS]


def _artifact_identities(
    subject_kind: str,
    taxonomy: dict[str, object],
    knowledge_pack: dict[str, object] | None = None,
) -> dict[str, object]:
    root = Path(__file__).resolve().parents[2]
    artifact_paths = [
        *sorted((root / "scripts").rglob("*.py")),
        *sorted((root / "contracts").glob("*.schema.json")),
        *sorted((root / "policies").glob("*.json")),
        root / "requirements.txt",
        root / "SKILL.md",
    ]
    artifact_files = {
        path.relative_to(root).as_posix(): _file_sha256(path)
        for path in artifact_paths
        if path.is_file() and "__pycache__" not in path.parts
    }
    detector_files = {
        name: _file_sha256(_artifact_path(f"scripts/full_inspection_repair/{name}"))
        for name in ("detectors.py", "detector_registry.py")
    }
    detector_ids = _detector_ids()
    knowledge_artifact = _file_sha256(
        _artifact_path("scripts/full_inspection_repair/knowledge.py")
    )
    pack = knowledge_pack or default_knowledge_pack(
        detector_ids=detector_ids,
        artifact_sha256=knowledge_artifact,
        target_kinds=[subject_kind, "ARTICLE", "OTHER", "PLAN", "PROJECT"],
    )
    evidence_files = {
        name: _file_sha256(_artifact_path(f"scripts/full_inspection_repair/{name}"))
        for name in (
            "contracts.py",
            "ledger.py",
            "observation.py",
            "verification.py",
            "write_ahead.py",
        )
    }
    return {
        "adapter_contract_digest": _file_sha256(
            _artifact_path("scripts/full_inspection_repair/adapters.py")
        ),
        "knowledge_pack_digest": pack["pack_digest"],
        "knowledge_pack_id": pack["pack_id"],
        "detector_pack_digest": canonical_digest(
            {"files": detector_files, "detector_ids": detector_ids}
        ),
        "defect_taxonomy_digest": canonical_digest(taxonomy),
        "fingerprint_registry_digest": canonical_digest(
            {"fingerprint_version": "1.0.0", "knowledge": knowledge_artifact}
        ),
        "evidence_policy_digest": canonical_digest(evidence_files),
        "config_digest": canonical_digest(
            {
                "subject_kind": subject_kind,
                "detector_ids": detector_ids,
                "artifacts": artifact_files,
            }
        ),
    }


def _environment_identity() -> str:
    packages = {}
    for name in (
        "cryptography",
        "jsonschema",
        "PyYAML",
        "pytest",
        "sigstore",
    ):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    return canonical_digest(
        {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "executable_sha256": _file_sha256(Path(sys.executable)),
            "packages": packages,
        }
    )


def _policy_identity(
    subject_kind: str,
    taxonomy: dict[str, object],
    knowledge_pack: dict[str, object] | None = None,
) -> str:
    return canonical_digest(
        {
            "taxonomy": taxonomy["coverage_digest"],
            "artifacts": _artifact_identities(
                subject_kind,
                taxonomy,
                knowledge_pack,
            ),
        }
    )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _write_json(path: Path, value: Any) -> None:
    _atomic_write(
        path,
        (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8"),
    )


def _write_failure(
    output: Path,
    *,
    status: str,
    failure_code: str,
    error: str,
    command: str,
    failures: list[str] | None = None,
) -> None:
    if status in {"CHECKED", "REPAIRED_CANDIDATE"}:
        raise AssertionError("failure receipt cannot claim success")
    output.mkdir(parents=True, exist_ok=True)
    _write_json(
        output / "summary.json",
        {
            "schema_version": 2,
            "status": status,
            "failure_code": failure_code,
            "error": error,
            "failures": failures or [error],
            "command": command,
            "recorded_at": datetime.now(UTC)
            .replace(microsecond=0)
            .isoformat(),
        },
    )


class _RunState:
    def __init__(self, path: Path):
        self.path = path
        if path.exists():
            raise ContractError("run state already exists; use a new output directory")
        self.run_id = f"run:{uuid.uuid4().hex}"
        self.current = "SCOPE_FROZEN"
        self.bindings: dict[str, object] = {}
        self.history = [
            {
                "from": "INTAKE",
                "event": "freeze_scope",
                "to": "SCOPE_FROZEN",
            }
        ]
        self._persist()

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _write_json(
            self.path,
            {
                "schema_version": 1,
                "run_id": self.run_id,
                "current_state": self.current,
                "history": self.history,
                **self.bindings,
            },
        )

    def bind(self, **bindings: object) -> None:
        self.bindings.update(bindings)
        self._persist()

    def transition(self, event: str, **bindings: object) -> None:
        self.bindings.update(bindings)
        next_state = advance(self.current, event)
        self.history.append(
            {"from": self.current, "event": event, "to": next_state}
        )
        self.current = next_state
        self._persist()

def _write_jsonl(path: Path, values: list[dict[str, object]]) -> None:
    _atomic_write(
        path,
        (
            "".join(
                json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n"
                for value in values
            )
        ).encode("utf-8"),
    )


def _write_coverage_ledgers(
    output: Path, coverage_report: dict[str, object]
) -> None:
    files = coverage_report["files"]
    binary = coverage_report["binary_files"]
    _write_jsonl(
        output / "byte-ledger.jsonl",
        [
            {
                "path": item["path"],
                "kind": item["kind"],
                "bytes": item["bytes"],
                "raw_sha256": item.get("raw_sha256", item.get("sha256")),
            }
            for item in [*files, *binary]
        ],
    )
    _write_jsonl(
        output / "codepoint-ledger.jsonl",
        [
            {"path": item["path"], **span}
            for item in files
            for span in item["codepoint_spans"]
        ],
    )
    _write_jsonl(
        output / "line-ledger.jsonl",
        [
            {"path": item["path"], **line}
            for item in files
            for line in item["lines"]
        ],
    )
    _write_jsonl(
        output / "unit-ledger.jsonl",
        [
            {"view": view, **unit}
            for item in files
            for view, key in (
                ("SYNTAX_LINE", "units"),
                ("SENTENCE", "sentence_units"),
                ("PARAGRAPH", "paragraph_units"),
                ("CLAUSE", "clause_units"),
            )
            for unit in item[key]
        ],
    )
    _write_jsonl(output / "binary-structure-ledger.jsonl", binary)
    _write_jsonl(output / "projection-ledger.jsonl", binary)
    _write_json(
        output / "uncovered-character-ranges.json",
        {
            "uncovered": coverage_report["uncovered"],
            "gaps": coverage_report["gaps"],
            "coverage_digest": coverage_report["coverage_digest"],
        },
    )


def _subject_manifest(
    subject,
    taxonomy: dict[str, object],
    coverage_report: dict[str, object] | None = None,
    knowledge_pack: dict[str, object] | None = None,
) -> dict[str, object]:
    identities = _artifact_identities(
        subject.subject_kind,
        taxonomy,
        knowledge_pack,
    )
    return {
        "schema_version": 2,
        "subject_id": subject.subject_id,
        "subject_kind": subject.subject_kind,
        "subject_root": str(subject.root),
        "adapter_id": "protected-reader",
        "adapter_version": "2.0.0",
        "adapter_contract_digest": identities["adapter_contract_digest"],
        "knowledge_pack_id": identities["knowledge_pack_id"],
        "knowledge_pack_digest": identities["knowledge_pack_digest"],
        "detector_pack_digest": identities["detector_pack_digest"],
        "defect_taxonomy_digest": identities["defect_taxonomy_digest"],
        "taxonomy_coverage_digest": taxonomy["coverage_digest"],
        "fingerprint_registry_digest": identities["fingerprint_registry_digest"],
        "evidence_policy_digest": identities["evidence_policy_digest"],
        "tree_digest": subject.tree_digest,
        "config_digest": identities["config_digest"],
        "generation": 1,
        "snapshot_digest": subject.snapshot_digest,
        "root_generation": subject.root_generation,
        "directories": list(subject.directories),
        "character_coverage_digest": (
            coverage_report["coverage_digest"]
            if coverage_report is not None
            else canonical_digest({"coverage": "not-yet-built"})
        ),
        "codepoint_count": coverage_report["codepoint_count"] if coverage_report else 0,
        "punctuation_count": (
            coverage_report["punctuation_count"] if coverage_report else 0
        ),
        "uncovered_character_count": (
            coverage_report["uncovered_count"] if coverage_report else 0
        ),
        "coverage_gap_count": coverage_report["gap_count"] if coverage_report else 0,
        "files": [
            {
                "locator": item.locator,
                "size": item.size,
                "sha256": item.sha256,
                "same_handle": item.metadata.get("same_handle"),
            }
            for item in subject.files
        ],
    }


def _assert_manifest_pack_identity(
    manifest: dict[str, object],
    subject_kind: str,
    taxonomy: dict[str, object],
    knowledge_pack: dict[str, object] | None = None,
) -> None:
    identities = _artifact_identities(subject_kind, taxonomy, knowledge_pack)
    expected = {
        "knowledge_pack_id": identities["knowledge_pack_id"],
        "knowledge_pack_digest": identities["knowledge_pack_digest"],
    }
    actual = {
        "knowledge_pack_id": manifest.get("knowledge_pack_id"),
        "knowledge_pack_digest": manifest.get("knowledge_pack_digest"),
    }
    if actual != expected:
        raise ContractError("subject manifest knowledge pack ID/digest mismatch")


def _detection_json(results: tuple[DetectorResult, ...]) -> list[dict[str, object]]:
    return [
        {
            "detector_id": result.detector_id,
            "status": result.status,
            "findings": list(result.findings),
            "error": result.error,
        }
        for result in results
    ]


def _semantic_risk_findings(
    report: dict[str, object],
    subject,
) -> list[dict[str, object]]:
    locators = {item.locator for item in subject.files}
    output: dict[str, dict[str, object]] = {}
    for cell in report.get("cells", ()):
        if not isinstance(cell, dict):
            continue
        for witness in cell.get("findings", ()):
            if not isinstance(witness, dict):
                continue
            primary = witness.get("primary_locator", {})
            locator = str(primary.get("path", "")) if isinstance(primary, dict) else ""
            if locator not in locators:
                continue
            category = str(cell.get("category_id") or witness.get("cell_id"))
            defect_class = str(witness.get("defect_class_id") or "SEMANTIC")
            invariant = str(witness.get("invariant_id") or cell.get("cell_id"))
            mechanism = canonical_digest(
                {
                    "cell_id": cell.get("cell_id"),
                    "semantic_fact_digest": witness.get("semantic_digest"),
                }
            )
            identity = {
                "subject": subject.tree_digest,
                "cell_id": cell.get("cell_id"),
                "locator": locator,
                "semantic_digest": witness.get("semantic_digest"),
            }
            risk_id = canonical_digest(identity)
            output[risk_id] = {
                "risk_id": risk_id,
                "invariant_id": invariant,
                "defect_class_id": defect_class,
                "taxonomy_category_id": category,
                "subject_id": subject.subject_id,
                "source_id": f"source:{locator}",
                "severity": "High",
                "message": f"semantic matrix detected {defect_class} at {locator}",
                "mechanism": "cell-specific detector and independent oracle agreed",
                "affected_refs": [locator],
                "root_cause_id": canonical_digest(
                    {"category": category, "defect_class": defect_class}
                ),
                "status": "OPEN",
                "evidence_refs": [str(cell.get("receipt_digest"))],
                "evidence_sha256": str(witness.get("semantic_digest")),
                "closed_by": None,
                "closed_at": None,
                "verification_check": None,
                "residual_risk": None,
            }
    return sorted(output.values(), key=lambda item: str(item["risk_id"]))


def _merge_finding_sets(
    detected: list[dict[str, object]],
    semantic: list[dict[str, object]],
) -> list[dict[str, object]]:
    merged = {str(item["risk_id"]): item for item in detected}
    for candidate in semantic:
        category = str(candidate["taxonomy_category_id"])
        locator = str(candidate["affected_refs"][0])
        candidate_tokens = {
            token
            for token in re.split(r"[^a-z0-9]+", str(candidate["defect_class_id"]).lower())
            if token and token not in {"semantic", "required", "content", "field"}
        }
        duplicate = False
        for current in merged.values():
            if (
                str(current["taxonomy_category_id"]) == category
                and str(current["affected_refs"][0]) == locator
            ):
                current_tokens = {
                    token
                    for token in re.split(
                        r"[^a-z0-9]+",
                        str(current["defect_class_id"]).lower(),
                    )
                    if token and token not in {"semantic", "required", "content", "field"}
                }
                duplicate = bool(candidate_tokens & current_tokens)
                if duplicate:
                    break
        if not duplicate:
            merged[str(candidate["risk_id"])] = candidate
    return list(merged.values())


def _observation_payload(
    subject,
    finding: dict[str, object],
    *,
    source_phase: str,
    source_run_id: str,
) -> dict[str, object]:
    message = _redact_text(str(finding["message"]))
    mechanism = _redact_text(str(finding["mechanism"]))
    safe_feedback = _redact_text(str(finding["mechanism"]))
    root_cause = _redact_value(finding["root_cause_id"])
    evidence_refs = _redact_value(finding["evidence_refs"])
    if not isinstance(evidence_refs, list):
        raise EvidenceBlocked("finding evidence_refs must be a list")
    policy_digest = _redaction_policy_digest()
    evidence_digest = canonical_digest(
        {
            "source_evidence_sha256": finding["evidence_sha256"],
            "source_run_id": source_run_id,
            "source_phase": source_phase,
            "subject_digest": subject.tree_digest,
            "evidence_refs": evidence_refs,
            "redacted_fields_digest": canonical_digest(
                {
                    "message": message,
                    "mechanism": mechanism,
                    "safe_feedback": safe_feedback,
                }
            ),
            "redaction_policy_digest": policy_digest,
        }
    )
    return {
        "source_run_id": source_run_id,
        "source_phase": source_phase,
        "producer_id": "full-inspection-repair",
        "subject_id": subject.subject_id,
        "subject_kind": subject.subject_kind,
        "subject_digest": subject.tree_digest,
        "invariant_id": finding["invariant_id"],
        "defect_class_id": finding["defect_class_id"],
        "taxonomy_category_id": finding["taxonomy_category_id"],
        "fingerprint": str(root_cause),
        "fingerprint_version": "1.0.0",
        "message": message,
        "mechanism": mechanism,
        "root_cause_hypothesis": str(root_cause),
        "evidence_refs": evidence_refs,
        "evidence_sha256": evidence_digest,
        "redaction_policy_digest": policy_digest,
        "severity": finding["severity"],
        "analogous_surfaces": [],
        "status": "CONFIRMED",
        "safe_feedback": safe_feedback,
        "recorded_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
    }


def _append_issue_observations(
    journal: ObservationJournal,
    subject,
    findings: list[dict[str, object]],
    *,
    source_phase: str,
    source_run_id: str,
) -> int:
    for finding in findings:
        journal.append(
            _observation_payload(
                subject,
                finding,
                source_phase=source_phase,
                source_run_id=source_run_id,
            )
        )
    return len(findings)


def _verify_observation_journal(
    path: Path,
    *,
    expected_count: int,
    source_run_id: str,
    redaction_policy_digest: str,
) -> dict[str, object]:
    journal = ObservationJournal(path)
    try:
        checkpoint = (
            journal.empty_checkpoint(
                source_run_id=source_run_id,
                redaction_policy_digest=redaction_policy_digest,
                create=True,
            )
            if expected_count == 0
            else journal.checkpoint()
        )
        count = journal.verify(checkpoint=checkpoint)
    except (ContractError, OSError, ValueError) as exc:
        raise EvidenceBlocked(f"observation journal verification failed: {exc}") from exc
    if count != expected_count:
        raise EvidenceBlocked(
            f"observation journal count mismatch: expected={expected_count} actual={count}"
        )
    manifest = {
        "schema_version": 1,
        "status": "PASS",
        "record_count": count,
        "head_digest": checkpoint["head_digest"],
        "journal_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "checkpoint": checkpoint,
        "verified_at": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat(),
    }
    _write_json(path.with_name("observation-journal-manifest.json"), manifest)
    return manifest


def _require_journal_pass(path: Path, checkpoint: dict[str, Any]) -> dict[str, object]:
    receipt = verify_journal(path, checkpoint=checkpoint)
    if receipt["status"] != "PASS":
        failures = ", ".join(str(item) for item in receipt["failures"])
        raise EvidenceBlocked(f"write-ahead journal verification failed: {failures}")
    return receipt


def _load_evaluation_matrix(path: str | None) -> dict[str, object] | None:
    if path is None:
        return None
    evidence = strict_loads(Path(path).read_bytes())
    if not isinstance(evidence, dict):
        raise ContractError("evaluation evidence must be a JSON object")
    case_identities = evidence.get("case_identities")
    if not isinstance(case_identities, dict) or not case_identities:
        raise MatrixBlocked("evaluation case identities are missing")
    bindings = {
        name: evidence.get(name)
        for name in ("run_id", "scope_digest", "subject_digest", "candidate_digest")
    }
    if not isinstance(bindings["run_id"], str) or not bindings["run_id"]:
        raise MatrixBlocked("evaluation run binding is missing")
    for name in ("scope_digest", "subject_digest", "candidate_digest"):
        value = bindings[name]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise MatrixBlocked(f"evaluation {name} binding is missing")
    return reconcile_evaluation(
        requested=[str(item) for item in evidence.get("requested", [])],
        attempts={
            str(key): str(value)
            for key, value in dict(evidence.get("attempts", {})).items()
        },
        f2p={str(item) for item in evidence.get("f2p", [])},
        p2p={str(item) for item in evidence.get("p2p", [])},
        case_identities=case_identities,
        expected_identities=case_identities,
        run_id=bindings["run_id"],
        scope_digest=bindings["scope_digest"],
        subject_digest=bindings["subject_digest"],
        candidate_digest=bindings["candidate_digest"],
    )


def _load_requested_knowledge_pack(args, subject_kind: str) -> dict[str, object] | None:
    pack_value = getattr(args, "knowledge_pack", None)
    lock_value = getattr(args, "knowledge_pack_lock", None)
    if pack_value is None and lock_value is None:
        return None
    if not pack_value or not lock_value:
        raise EvidenceBlocked(
            "--knowledge-pack and --knowledge-pack-lock must be provided together"
        )
    try:
        return load_frozen_pack_files(
            pack_path=pack_value,
            lock_path=lock_value,
            target_kinds=[subject_kind],
        )
    except KnowledgeError as exc:
        message = str(exc)
        if any(
            marker in message
            for marker in (
                "different file",
                "different frozen pack",
                "pack_digest mismatch",
                "pack_file_sha256 mismatch",
                "scope",
            )
        ):
            raise StaleInputBlocked(message) from exc
        raise EvidenceBlocked(message) from exc


def _assert_inputs_current(
    args,
    state: _RunState,
    *,
    expected_subject_digest: str,
) -> None:
    current = build_subject(args.target, args.kind)
    frozen_expected = getattr(args, "expected_tree_digest", None)
    if frozen_expected and current.tree_digest != frozen_expected:
        state.transition("input_drift")
        raise StaleInputBlocked(
            "target tree differs from the frozen expected tree digest"
        )
    if current.tree_digest != expected_subject_digest:
        state.transition("input_drift")
        raise StaleInputBlocked("target tree changed during the run")
    taxonomy_path = Path(args.taxonomy) if args.taxonomy else None
    taxonomy = _load_taxonomy(taxonomy_path, current.subject_kind)
    requested_pack = _load_requested_knowledge_pack(args, current.subject_kind)
    try:
        registry = load_registry()
    except RegistryError as exc:
        state.transition("input_drift")
        raise StaleInputBlocked(
            f"runtime registry/tool changed during the run: {exc}"
        ) from exc
    current_policy = _policy_identity(
        current.subject_kind,
        taxonomy,
        requested_pack,
    )
    current_environment = _environment_identity()
    current_knowledge_pack = (
        requested_pack.get("pack_digest")
        if requested_pack is not None
        else None
    )
    frozen_identities = (
        ("taxonomy", taxonomy["coverage_digest"], "taxonomy_digest"),
        ("runtime registry/tool", registry.registry_digest, "runtime_registry_digest"),
        ("policy or adapter", current_policy, "policy_digest"),
        ("knowledge pack", current_knowledge_pack, "knowledge_pack_digest"),
        ("environment", current_environment, "environment_digest"),
    )
    for label, current_digest, binding in frozen_identities:
        if current_digest != state.bindings.get(binding):
            state.transition("input_drift")
            raise StaleInputBlocked(f"{label} digest changed during the run")
    expected_policy = getattr(args, "expected_policy_digest", None)
    if expected_policy and current_policy != expected_policy:
        state.transition("input_drift")
        raise StaleInputBlocked("policy or adapter digest changed during the run")
    expected_environment = getattr(args, "expected_environment_digest", None)
    if expected_environment and current_environment != expected_environment:
        state.transition("input_drift")
        raise StaleInputBlocked("environment digest changed during the run")


def _load_taxonomy(path: Path | None, subject_kind: str) -> dict[str, object]:
    taxonomy = (
        default_taxonomy_coverage(subject_kind)
        if path is None
        else strict_loads(path.read_bytes())
    )
    try:
        assert_taxonomy_complete(taxonomy, (subject_kind,))
    except ContractError as exc:
        if "taxonomy" not in str(exc):
            raise
        raise TaxonomyBlocked(str(exc)) from exc
    return taxonomy


def _prepare_run(
    args,
    state: _RunState,
) -> tuple[
    Path,
    Any,
    tuple[DetectorResult, ...],
    list[dict[str, object]],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object] | None,
    dict[str, object],
]:
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    subject = build_subject(args.target, args.kind)
    knowledge_pack = _load_requested_knowledge_pack(args, subject.subject_kind)
    registry = load_registry()
    state.bind(
        target=str(subject.root),
        subject_kind=subject.subject_kind,
        subject_id=subject.subject_id,
        tree_digest=subject.tree_digest,
        snapshot_digest=subject.snapshot_digest,
        knowledge_pack_id=(
            knowledge_pack.get("pack_id") if knowledge_pack is not None else None
        ),
        knowledge_pack_digest=(
            knowledge_pack.get("pack_digest") if knowledge_pack is not None else None
        ),
        runtime_registry_id=registry.registry_id,
        runtime_registry_version=registry.registry_version,
        runtime_registry_digest=registry.registry_digest,
    )
    expected_tree_digest = getattr(args, "expected_tree_digest", None)
    if expected_tree_digest and subject.tree_digest != expected_tree_digest:
        state.transition("input_drift")
        raise StaleInputBlocked("target does not match the frozen tree digest")
    state.transition("census")
    coverage_report = build_complete_coverage(
        {item.locator: item.content for item in subject.files}
    )
    taxonomy_path = Path(args.taxonomy) if args.taxonomy else None
    taxonomy = _load_taxonomy(taxonomy_path, subject.subject_kind)
    policy_digest = _policy_identity(
        subject.subject_kind,
        taxonomy,
        knowledge_pack,
    )
    environment_digest = _environment_identity()
    identities = _artifact_identities(
        subject.subject_kind,
        taxonomy,
        knowledge_pack,
    )
    scope_digest = canonical_digest(
        {
            "run_id": state.run_id,
            "subject_kind": subject.subject_kind,
            "subject_tree_digest": subject.tree_digest,
            "runtime_registry_digest": registry.registry_digest,
            "taxonomy_coverage_digest": taxonomy["coverage_digest"],
            "knowledge_pack_digest": identities["knowledge_pack_digest"],
            "environment_digest": environment_digest,
            "config_digest": identities["config_digest"],
        }
    )
    state.bind(
        scope_digest=scope_digest,
        scope_id=state.run_id,
        policy_digest=policy_digest,
        environment_digest=environment_digest,
        taxonomy_digest=taxonomy["coverage_digest"],
    )
    expected_policy = getattr(args, "expected_policy_digest", None)
    if expected_policy and policy_digest != expected_policy:
        state.transition("input_drift")
        raise StaleInputBlocked("policy or adapter digest does not match the frozen value")
    expected_environment = getattr(args, "expected_environment_digest", None)
    if expected_environment and environment_digest != expected_environment:
        state.transition("input_drift")
        raise StaleInputBlocked("environment digest does not match the frozen value")
    state.transition("discover")
    journal = WriteAheadJournal(
        output / "write-ahead-journal.jsonl",
        subject_digest=subject.tree_digest,
        source_run_id=state.run_id,
    )
    journal.append(
        event_key="detectors:run",
        boundary="INTENT",
        phase="detection",
        action="run-all",
        evidence={"detector_pack": "default"},
    )
    results = run_default_detectors(subject)
    reconcile_detector_results(results, _detector_ids())
    journal.append(
        event_key="detectors:run",
        boundary="COMPLETION",
        phase="detection",
        action="run-all",
        evidence={
            "detectors": [
                {"id": item.detector_id, "status": item.status}
                for item in results
            ]
        },
    )
    journal.append(
        event_key="semantic-matrix:execute",
        boundary="INTENT",
        phase="detection",
        action="execute-72-cells",
        evidence={"runtime_registry_digest": registry.registry_digest},
    )
    semantic_report = execute_semantic_matrix(
        subject,
        registry,
        phase="DISCOVERY",
    )
    journal.append(
        event_key="semantic-matrix:execute",
        boundary="COMPLETION",
        phase="detection",
        action="execute-72-cells",
        evidence={
            "cell_count": semantic_report["cell_count"],
            "blocked_count": semantic_report["blocked_count"],
            "report_digest": semantic_report["report_digest"],
        },
    )
    findings = _merge_finding_sets(
        [finding for result in results for finding in result.findings],
        _semantic_risk_findings(semantic_report, subject),
    )
    source_inventory_report = build_source_inventory(
        subject,
        registry_snapshot=registry,
    )
    source_closure = build_source_closure(
        source_inventory_report,
        scope_id=state.run_id,
        evidence=build_source_closure_evidence(
            source_inventory_report,
            semantic_report=semantic_report,
            environment_digest=str(state.bindings["environment_digest"]),
        ),
    )
    assert_source_closure_complete(source_closure)
    state.bind(
        source_inventory_digest=source_inventory_report["source_inventory_digest"],
        source_closure_digest=source_closure["closure_digest"],
    )
    resource_ids = {
        str(row["locator"]): str(row["source_id"])
        for row in source_inventory_report["sources"]
        if row["source_type"] == "RESOURCE"
    }
    mapped_findings = []
    for finding in findings:
        mapped = dict(finding)
        source_id = str(mapped["source_id"])
        if source_id.startswith("source:"):
            mapped["source_id"] = resource_ids.get(
                source_id.removeprefix("source:"),
                source_id,
            )
        mapped_findings.append(mapped)
    findings = mapped_findings
    observations = ObservationJournal(output / "observations.jsonl")
    source_run_id = state.run_id
    redaction_policy_digest = _redaction_policy_digest()
    _append_issue_observations(
        observations,
        subject,
        findings,
        source_phase="CHECK",
        source_run_id=source_run_id,
    )
    _verify_observation_journal(
        output / "observations.jsonl",
        expected_count=len(findings),
        source_run_id=source_run_id,
        redaction_policy_digest=redaction_policy_digest,
    )
    required_ids = [
        str(item["source_id"]) for item in source_inventory_report["sources"]
    ]
    present_ids = [
        str(item["source_id"])
        for item in source_inventory_report["sources"]
        if item["applicability"] != "REQUIRED_MISSING"
    ]
    source_inventory = [
        {
            "source_id": str(item["source_id"]),
            "locator": str(item["locator"]),
            "sha256": str(item.get("sha256") or item["obligation_digest"]),
            "present": item["applicability"] != "REQUIRED_MISSING",
        }
        for item in source_inventory_report["sources"]
    ]
    ledger = build_risk_ledger(
        scope_digest=subject.tree_digest,
        required_sources=required_ids,
        findings=findings,
        observed_sources=present_ids,
        source_inventory=source_inventory,
    )
    impact_graph = build_impact_graph(subject, findings)
    assert_impact_closed(impact_graph)
    state.transition("impact")
    context = _taxonomy_context(
        subject,
        results,
        findings,
        ledger,
        taxonomy,
        impact_graph,
        coverage_report,
        knowledge_pack,
        semantic_report,
    )
    journal.append(
        event_key="taxonomy:qualification",
        boundary="INTENT",
        phase="taxonomy",
        action="evaluate-cells",
        evidence={"cell_count": len(taxonomy["cells"])},
    )
    taxonomy_report = qualify_taxonomy(taxonomy, context)
    journal.append(
        event_key="taxonomy:qualification",
        boundary="COMPLETION",
        phase="taxonomy",
        action="evaluate-cells",
        evidence={
            "all_passed": taxonomy_report["all_passed"],
            "report_digest": taxonomy_report["report_digest"],
        },
    )
    journal.close()
    checkpoint = journal.checkpoint()
    write_journal_checkpoint(
        output / "write-ahead-journal-checkpoint.json",
        checkpoint,
    )
    _require_journal_pass(output / "write-ahead-journal.jsonl", checkpoint)
    matrix = _load_evaluation_matrix(getattr(args, "evaluation_evidence", None))
    _assert_inputs_current(
        args,
        state,
        expected_subject_digest=subject.tree_digest,
    )

    _write_json(
        output / "subject-manifest.json",
        _subject_manifest(
            subject,
            taxonomy,
            coverage_report,
            knowledge_pack,
        ),
    )
    _write_jsonl(
        output / "required-sources.jsonl",
        list(source_inventory_report["sources"]),
    )
    _write_json(output / "source-inventory.json", source_inventory_report)
    _write_jsonl(
        output / "source-inventory.jsonl",
        list(source_inventory_report["sources"]),
    )
    _write_json(output / "source-closure.json", source_closure)
    _write_json(output / "detections.json", _detection_json(results))
    _write_json(output / "impact-graph.json", impact_graph)
    _write_json(output / "risk-ledger.json", ledger)
    _write_json(output / "taxonomy-coverage.json", taxonomy)
    _write_json(output / "taxonomy-qualification.json", taxonomy_report)
    _write_json(output / "runtime-registry.snapshot.json", registry.as_dict())
    _write_json(output / "semantic-matrix.json", semantic_report)
    _write_jsonl(output / "semantic-cells.jsonl", list(semantic_report["cells"]))
    _write_json(output / "character-coverage.json", coverage_report)
    _write_jsonl(
        output / "punctuation-ledger.jsonl",
        coverage_report.get("punctuation_runs", coverage_report.get("punctuation", [])),
    )
    _write_jsonl(
        output / "whitespace-control-ledger.jsonl",
        coverage_report.get(
            "whitespace_control_runs",
            coverage_report.get("whitespace_control", []),
        ),
    )
    _write_coverage_ledgers(output, coverage_report)
    _write_json(
        output / "write-ahead-journal-check.json",
        _require_journal_pass(
            output / "write-ahead-journal.jsonl",
            load_journal_checkpoint(output / "write-ahead-journal-checkpoint.json"),
        ),
    )
    if matrix is not None:
        _write_json(output / "verification-matrix.json", matrix)
    return (
        output,
        subject,
        results,
        findings,
        ledger,
        impact_graph,
        taxonomy_report,
        coverage_report,
        matrix,
        semantic_report,
    )


def _capability_evidence(
    args,
    output: Path,
    subject,
) -> dict[str, object] | None:
    pack_path = getattr(args, "capability_pack", None)
    if not pack_path:
        return None
    evidence = run_pack(
        target=subject.root,
        output=output / "capability-evidence",
        pack_path=pack_path,
        strict=bool(getattr(args, "capability_required", False)),
        include_mutation=False,
    )
    _write_json(output / "capability-evidence.json", evidence)
    if (
        getattr(args, "capability_required", False)
        and evidence["status"] != "PASS"
    ):
        raise CapabilityBlocked(
            "required capability evidence did not complete: "
            + ", ".join(evidence["nonterminal"])
        )
    return evidence


def _taxonomy_context(
    subject,
    results: tuple[DetectorResult, ...],
    findings: list[dict[str, object]],
    ledger: dict[str, object],
    taxonomy: dict[str, object],
    impact_graph: dict[str, object],
    coverage_report: dict[str, object],
    knowledge_pack: dict[str, object] | None = None,
    semantic_report: dict[str, object] | None = None,
) -> dict[str, object]:
    validate_risk_ledger_consistency(ledger)
    subject_manifest = _subject_manifest(
        subject,
        taxonomy,
        coverage_report,
        knowledge_pack,
    )
    _assert_manifest_pack_identity(
        subject_manifest,
        subject.subject_kind,
        taxonomy,
        knowledge_pack,
    )
    validate_contract("subject-manifest", subject_manifest)
    validate_contract("defect-taxonomy", taxonomy)
    schema_count = len(
        tuple((Path(__file__).resolve().parents[2] / "contracts").glob("*.schema.json"))
    )
    recomputed_tree = canonical_digest(
        {item.locator: item.sha256 for item in subject.files}
    )
    named_streams = [
        item.locator for item in subject.files if item.metadata["named_streams"]
    ]
    reparse_points = [
        item.locator
        for item in subject.files
        if item.metadata.get("reparse_tag") or item.metadata.get("reparse_point")
    ]
    try:
        strict_loads('{"duplicate":1,"duplicate":2}')
        duplicate_rejected = False
    except StrictJSONError:
        duplicate_rejected = True
    required_modules = ("yaml", "jsonschema", "pytest")
    dependency_status = {
        name: importlib.util.find_spec(name) is not None for name in required_modules
    }
    contained = all(
        str(item.absolute_path.resolve()).startswith(str(subject.root.resolve()))
        for item in subject.files
    )
    finding_ids = {item["risk_id"] for item in findings}
    impact_ids = {
        edge["from"]
        for edge in impact_graph["edges"]
        if edge["kind"] == "AFFECTS"
    }
    detector_ids = [result.detector_id for result in results]
    coverage_detector = (
        coverage_report["uncovered_count"] == 0
        and coverage_report["gap_count"] == 0
    )
    coverage_oracle = coverage_report["file_count"] == len(subject.files)
    plane_evidence = {
        "STATIC": (
            len(subject.files) > 0,
            subject_manifest["generation"] == 1
            and len(subject_manifest["files"]) == len(subject.files),
        ),
        "CONTRACT": (
            schema_count > 0,
            taxonomy["coverage_digest"]
            == canonical_digest(
                {
                    key: value
                    for key, value in taxonomy.items()
                    if key != "coverage_digest"
                }
            ),
        ),
        "SEMANTIC": (
            not ledger["unexpected_sources"],
            len(ledger["required_sources"]) >= len(subject.files),
        ),
        "BEHAVIOR": (
            all(result.status != "BLOCKED" for result in results),
            len(set(detector_ids)) == len(detector_ids),
        ),
        "RUNTIME": (
            sys.version_info >= (3, 12),
            all(dependency_status.values()),
        ),
        "SECURITY": (
            duplicate_rejected and not reparse_points,
            not named_streams and contained,
        ),
        "PERFORMANCE": (
            sum(item.size for item in subject.files) <= 64 * 1024 * 1024,
            all(item.size <= MAX_FILE_BYTES for item in subject.files),
        ),
        "LIFECYCLE": (
            subject.root.is_dir() and bool(subject.root_generation),
            ((ledger["open_count"] + ledger["closed_count"]) == len(ledger["items"]))
            and contained,
        ),
    }
    plane_evidence = {
        key: (detector and coverage_detector, oracle and coverage_oracle)
        for key, (detector, oracle) in plane_evidence.items()
    }
    category_evidence = {
        "FUNCTIONAL_FAULT": (
            len(results) == 10,
            len(results) > 0,
        ),
        "RISK_EXPOSURE": (
            all(item["severity"] in {"Critical", "High", "Medium", "Low"} for item in findings),
            ledger["open_count"] == sum(
                item["status"] == "OPEN" for item in ledger["items"]
            ),
        ),
        "LATENT_DEFECT": (
            all(item.metadata["two_reads_equal"] for item in subject.files),
            all(
                item.sha256 == item.metadata["content_sha256"]
                for item in subject.files
            ),
        ),
        "VULNERABILITY": (
            not reparse_points and not named_streams,
            duplicate_rejected and contained,
        ),
        "OMISSION": (
            not ledger["missing_sources"],
            len(subject.files) == len(subject_manifest["files"]),
        ),
        "INCONSISTENCY": (
            recomputed_tree == subject.tree_digest,
            taxonomy["coverage_digest"]
            == canonical_digest(
                {
                    key: value
                    for key, value in taxonomy.items()
                    if key != "coverage_digest"
                }
            ),
        ),
        "BOUNDARY": (
            contained,
            all(".." not in item.locator.split("/") for item in subject.files),
        ),
        "EXCEPTION_PATH": (
            all(result.status in {"PASS", "FINDINGS", "BLOCKED"} for result in results),
            all(result.error is None or result.status == "BLOCKED" for result in results),
        ),
        "OTHER_DECLARED": (
            all(
                item["taxonomy_category_id"] in taxonomy["categories"]
                for item in findings
            ),
            finding_ids == {item["risk_id"] for item in findings}
            and impact_ids.issubset({f"finding:{item}" for item in finding_ids}),
        ),
    }
    semantic_cells = {}
    if semantic_report is not None:
        semantic_cells = {
            str(cell["cell_id"]): cell
            for cell in semantic_report.get("cells", [])
            if isinstance(cell, dict) and cell.get("cell_id")
        }
    cell_evidence = {}
    for cell in taxonomy["cells"]:
        category = str(cell["category_id"])
        plane = str(cell["evidence_plane"])
        cell_id = f"{subject.subject_kind}:{category}:{plane}"
        if semantic_report is not None:
            semantic = semantic_cells.get(cell_id)
            if not isinstance(semantic, dict):
                continue
            passed = semantic.get("status") in {"CLEAN", "FINDING"}
            detector_ids = list(cell.get("detector_ids", []))
            oracle_ids = list(cell.get("oracle_ids", []))
            cell_evidence[cell_id] = {
                "subject_digest": subject.tree_digest,
                "semantic_receipt_digest": semantic.get("receipt_digest"),
                "detector": {
                    "id": detector_ids[0] if detector_ids else "NOT_APPLICABLE",
                    "passed": passed,
                    "observations": {
                        "category": category,
                        "plane": plane,
                    },
                },
                "oracle": {
                    "id": oracle_ids[0] if oracle_ids else "POLICY_PROOF",
                    "passed": passed,
                    "observations": {
                        "category": category,
                        "plane": plane,
                    },
                },
            }
            continue
        detector_category, oracle_category = category_evidence[category]
        detector_plane, oracle_plane = plane_evidence[plane]
        detector_ids = list(cell["detector_ids"])
        oracle_ids = list(cell["oracle_ids"])
        cell_evidence[cell_id] = {
            "subject_digest": subject.tree_digest,
            "detector": {
                "id": (
                    detector_ids[0]
                    if detector_ids
                    else "policy-proof"
                ),
                "passed": detector_category and detector_plane,
                "observations": {
                    "category": detector_category,
                    "plane": detector_plane,
                },
            },
            "oracle": {
                "id": oracle_ids[0] if oracle_ids else "policy-proof",
                "passed": oracle_category and oracle_plane,
                "observations": {
                    "category": oracle_category,
                    "plane": oracle_plane,
                },
            },
        }
    return {
        "tree_digest": subject.tree_digest,
        "cell_evidence": cell_evidence,
        "semantic_report": semantic_report,
        "dependency_status": dependency_status,
        "schema_count": schema_count,
    }


def _summary(
    *,
    status: str,
    subject,
    results: tuple[DetectorResult, ...],
    ledger: dict[str, object],
    **extra: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "status": status,
        "subject_id": subject.subject_id,
        "subject_kind": subject.subject_kind,
        "tree_digest": subject.tree_digest,
        "detectors": len(results),
        "blocked_detectors": [
            result.detector_id for result in results if result.status == "BLOCKED"
        ],
        "open_count": ledger["open_count"],
        "closed_count": ledger["closed_count"],
    }
    value.update(extra)
    return value


def _failure_status(exc: Exception, current_state: str) -> tuple[str, str]:
    if isinstance(exc, StaleInputBlocked):
        return "BLOCKED_STALE_INPUT", "input_drift"
    if isinstance(exc, TaxonomyBlocked):
        return "BLOCKED_TAXONOMY", "taxonomy_gap"
    if isinstance(exc, AdapterError):
        return "BLOCKED_ADAPTER", "adapter_failed"
    if isinstance(exc, CapabilityBlocked):
        return "BLOCKED_DETECTOR", "capability_failed"
    if isinstance(exc, MatrixBlocked):
        return "BLOCKED_VERIFICATION", "evaluation_failed"
    if isinstance(exc, VerificationBlocked):
        if current_state in {"SCOPE_FROZEN", "SUBJECT_CENSUS", "ISSUE_DISCOVERY"}:
            return "BLOCKED_DETECTOR", "detector_failed"
        return "BLOCKED_VERIFICATION", "verification_failed"
    if isinstance(exc, RepairBlocked):
        return "BLOCKED_REPAIR_PLAN", "repair_plan_failed"
    if isinstance(exc, ClosureError):
        event = (
            "input_drift"
            if exc.code == "BLOCKED_STALE_INPUT"
            else "evidence_failed"
            if exc.code == "BLOCKED_EVIDENCE"
            else "verification_failed"
        )
        return exc.code, event
    if isinstance(exc, EvidenceBlocked):
        return "BLOCKED_EVIDENCE", "evidence_failed"
    if isinstance(exc, StrictJSONError):
        return "BLOCKED_EVIDENCE", "evidence_failed"
    if isinstance(exc, ContractError):
        return "BLOCKED_EVIDENCE", "evidence_failed"
    return "BLOCKED_EVIDENCE", "evidence_failed"


def _matrix_failure_status(report: dict[str, object]) -> str | None:
    blocked = [
        cell
        for cell in report.get("cells", ())
        if isinstance(cell, dict) and cell.get("status") in {"BLOCKED", "UNSUPPORTED", "UNCOVERED"}
    ]
    if not blocked:
        return None
    codes = {str(cell.get("failure_code") or "") for cell in blocked}
    if any("ADAPTER" in code for code in codes):
        return "BLOCKED_ADAPTER"
    if any(cell.get("status") in {"UNSUPPORTED", "UNCOVERED"} for cell in blocked):
        return "BLOCKED_TAXONOMY"
    if any("DISAGREE" in code or "EVIDENCE" in code for code in codes):
        return "BLOCKED_EVIDENCE"
    return "BLOCKED_DETECTOR"


def _logical_skill_id(subject) -> str:
    skill = next((item for item in subject.files if item.locator == "SKILL.md"), None)
    if skill is None:
        return subject.subject_id
    text = skill.content.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return subject.subject_id
    try:
        end = next(index for index in range(1, len(lines)) if lines[index].strip() == "---")
        metadata = yaml.safe_load("\n".join(lines[1:end])) or {}
    except (StopIteration, yaml.YAMLError):
        return subject.subject_id
    name = metadata.get("name") if isinstance(metadata, dict) else None
    return name.strip() if isinstance(name, str) and name.strip() else subject.subject_id


def _run_manifest(
    *,
    state: _RunState,
    subject,
    taxonomy: dict[str, object],
    coverage_report: dict[str, object],
    knowledge_pack: dict[str, object] | None,
    registry,
    batch: dict[str, object],
    candidate_digest: str,
) -> dict[str, object]:
    subject_manifest = _subject_manifest(
        subject,
        taxonomy,
        coverage_report,
        knowledge_pack,
    )
    trust_path = Path(__file__).resolve().parents[2] / "policies" / "trust-policy.json"
    trust_policy_digest = canonical_digest(strict_loads(trust_path.read_bytes()))
    registry_data = (
        registry.as_dict() if hasattr(registry, "as_dict") else dict(registry)
    )
    tool_closure_digest = canonical_digest(
        {
            "known_tools": registry_data["known_tools"],
            "tool_closures": registry_data["tool_closures"],
            "sandbox_backends": registry_data["sandbox_backends"],
        }
    )
    bindings = {
        "registry_digest": registry.registry_digest,
        "taxonomy_policy_digest": str(taxonomy["coverage_digest"]),
        "trust_policy_digest": trust_policy_digest,
        "knowledge_pack_digest": str(subject_manifest["knowledge_pack_digest"]),
        "tool_closure_digest": tool_closure_digest,
        "environment_digest": str(state.bindings["environment_digest"]),
        "config_digest": str(subject_manifest["config_digest"]),
    }
    return build_run_manifest(
        run_id=state.run_id,
        scope_id=state.run_id,
        scope_digest=str(state.bindings["scope_digest"]),
        platform=current_platform(),
        subject_manifest_digest=canonical_digest(subject_manifest),
        subject_tree_digest=subject.tree_digest,
        subject_dir_hash1=dir_hash1(subject.root),
        logical_identity=_logical_skill_id(subject),
        bindings=bindings,
        repair_plan_digest=str(batch["batch_digest"]),
        candidate_digest=candidate_digest,
    )


def _role_report(
    semantic_report: dict[str, object],
    run: dict[str, object],
    *,
    role: str,
) -> dict[str, object]:
    cells = []
    receipt_digests = []
    for cell in semantic_report["cells"]:
        result = cell.get(f"{role}_result")
        result = result if isinstance(result, dict) else {}
        status = str(result.get("raw_status") or cell["status"])
        if status in {"CLEAN_WITH_PROOF"} or cell["status"] == "CLEAN_WITH_PROOF":
            status = "CLEAN"
        receipt_digest = result.get("result_digest") or cell["receipt_digest"]
        receipt_digests.append(receipt_digest)
        cells.append(
            {
                "cell_id": cell["cell_id"],
                "status": status,
                "comparison": cell["comparison"],
                "receipt_digest": receipt_digest,
            }
        )
    report: dict[str, object] = {
        "schema_version": 2,
        "run_id": run["run_id"],
        "scope_digest": run["scope_digest"],
        "subject_digest": run["subject"]["tree_digest"],
        "candidate_digest": run["candidate_digest"],
        "registry_digest": run["bindings"]["registry_digest"],
        "policy_digest": run["bindings"]["taxonomy_policy_digest"],
        "tool_closure_digest": run["bindings"]["tool_closure_digest"],
        "cells": cells,
        "receipt_digests": receipt_digests,
    }
    report["report_digest"] = material_digest(report, "report_digest")
    return report


def _candidate_source_inventory(
    candidate_inventory: dict[str, object],
    *,
    candidate_digest: str,
    run: dict[str, object],
) -> dict[str, object]:
    sources = []
    for source in candidate_inventory["sources"]:
        row = {
            "source_id": source["source_id"],
            "locator": source["locator"],
            "applicability": source["applicability"],
        }
        if source["applicability"] == "NOT_APPLICABLE_WITH_PROOF":
            row["proof_ref"] = source["proof_ref"]
            row["policy_digest"] = run["bindings"]["taxonomy_policy_digest"]
        sources.append(row)
    return build_candidate_source_inventory(
        run=run,
        candidate_digest=candidate_digest,
        sources=sources,
    )


def _candidate_taxonomy_artifact(
    taxonomy_report: dict[str, object],
    run: dict[str, object],
) -> dict[str, object]:
    artifact: dict[str, object] = {
        "schema_version": 2,
        "scope_digest": run["scope_digest"],
        "subject_digest": run["subject"]["tree_digest"],
        "candidate_digest": run["candidate_digest"],
        "required_cell_count": int(taxonomy_report["cell_count"]),
        "covered_cell_count": int(taxonomy_report["qualified_count"]),
        "source_report_digest": taxonomy_report["report_digest"],
    }
    artifact["report_digest"] = material_digest(artifact, "report_digest")
    return artifact


def _candidate_impact_artifact(
    graph: dict[str, object],
    run: dict[str, object],
) -> dict[str, object]:
    assert_impact_closed(graph)
    nodes = graph.get("nodes")
    finding_closure = graph.get("finding_closure")
    if not isinstance(nodes, list) or not isinstance(finding_closure, dict):
        raise EvidenceBlocked("impact graph is missing unresolved-node evidence")
    unresolved_ids = {
        str(node.get("id"))
        for node in nodes
        if isinstance(node, dict)
        and node.get("kind")
        in {"UNRESOLVED", "UNRESOLVED_IMPORT", "UNRESOLVED_REFERENCE"}
    }
    unresolved_ids.update(
        str(node_id)
        for node_id, closure in finding_closure.items()
        if isinstance(closure, dict)
        and closure.get("status") in {"UNRESOLVED", "OPEN_TERMINAL_EVIDENCE"}
    )
    artifact = dict(graph)
    artifact.update(
        {
            "schema_version": max(2, int(artifact.get("schema_version", 1))),
            "scope_digest": run["scope_digest"],
            "subject_digest": run["subject"]["tree_digest"],
            "candidate_digest": run["candidate_digest"],
            "unresolved_count": len(unresolved_ids),
        }
    )
    artifact["graph_digest"] = material_digest(artifact, "graph_digest")
    return artifact


def _candidate_matrix_artifact(
    semantic_report: dict[str, object],
    run: dict[str, object],
) -> dict[str, object]:
    cell_ids = [str(cell["cell_id"]) for cell in semantic_report["cells"]]
    attempts = {
        str(cell["cell_id"]): (
            "PASS"
            if cell["status"] in {"CLEAN", "CLEAN_WITH_PROOF", "FINDING"}
            else "INFRA_ERROR"
        )
        for cell in semantic_report["cells"]
    }
    identities = {
        str(cell["cell_id"]): {
            "fixture_digest": str(cell["binding_digest"]),
            "runner_digest": str(cell["receipt_digest"]),
            "tool_digest": str(run["bindings"]["tool_closure_digest"]),
        }
        for cell in semantic_report["cells"]
    }
    return reconcile_evaluation(
        requested=cell_ids,
        attempts=attempts,
        f2p=set(cell_ids),
        p2p=set(),
        case_identities=identities,
        expected_identities=identities,
        run_id=str(run["run_id"]),
        scope_digest=str(run["scope_digest"]),
        subject_digest=str(run["subject"]["tree_digest"]),
        candidate_digest=str(run["candidate_digest"]),
    )


def _record_failure(
    *,
    output: Path,
    command: str,
    state: _RunState,
    exc: Exception,
) -> int:
    status, event = _failure_status(exc, state.current)
    if state.current not in {
        "CLOSED_FOR_DECLARED_UNIVERSE",
        "BLOCKED_SCOPE",
        "BLOCKED_ADAPTER",
        "BLOCKED_TAXONOMY",
        "BLOCKED_STALE_INPUT",
        "BLOCKED_DETECTOR",
        "BLOCKED_EVIDENCE",
        "BLOCKED_REPAIR_PLAN",
        "BLOCKED_REPAIR_CONFLICT",
        "BLOCKED_VERIFICATION",
        "BLOCKED_INDEPENDENT_REVIEW",
    }:
        state.transition(event)
    _write_failure(
        output,
        status=status,
        failure_code=type(exc).__name__,
        error=str(exc),
        command=command,
    )
    return 2


def _check(args) -> int:
    output = resolve_layout(
        "check",
        target=args.target,
        output=args.output,
    ).output
    state = _RunState(output / "run-state.json")
    try:
        (
            output,
            subject,
            results,
            _findings,
            ledger,
            impact_graph,
            taxonomy_report,
            coverage_report,
            matrix,
            semantic_report,
        ) = _prepare_run(args, state)
        taxonomy = _load_taxonomy(
            Path(args.taxonomy) if args.taxonomy else None,
            subject.subject_kind,
        )
        capability = _capability_evidence(args, output, subject)
    except Exception as exc:  # noqa: BLE001 - CLI failure boundary
        return _record_failure(
            output=output,
            command="check",
            state=state,
            exc=exc,
        )

    matrix_failure = _matrix_failure_status(semantic_report)
    status = (
        matrix_failure
        or ("BLOCKED_TAXONOMY" if not taxonomy_report["all_passed"] else None)
        or (
            "BLOCKED_DETECTOR"
            if any(result.status == "BLOCKED" for result in results)
            else "CHECKED"
        )
    )
    if status != "CHECKED":
        state.transition(
            "adapter_failed"
            if status == "BLOCKED_ADAPTER"
            else "taxonomy_gap"
            if status == "BLOCKED_TAXONOMY"
            else "detector_failed"
        )
        _write_failure(
            output,
            status=status,
            failure_code=status,
            error="check did not complete cleanly",
            command="check",
        )
        return 2
    _write_json(
        output / "summary.json",
        _summary(
            status=status,
            subject=subject,
            results=results,
            ledger=ledger,
            impact_digest=impact_graph["graph_digest"],
            taxonomy_digest=taxonomy_report["report_digest"],
            coverage_digest=coverage_report["coverage_digest"],
            matrix_digest=matrix["matrix_digest"] if matrix else None,
            capability_digest=(
                capability["evidence_digest"] if capability else None
            ),
            capability_status=(
                capability["status"] if capability else None
            ),
            semantic_matrix_digest=semantic_report["report_digest"],
            semantic_cell_count=semantic_report["cell_count"],
        ),
    )
    return 0


def _repair(args) -> int:
    layout = resolve_layout(
        "repair",
        target=args.target,
        output=args.output,
        candidate=args.candidate,
    )
    output = layout.output
    state = _RunState(output / "run-state.json")
    try:
        (
            output,
            subject,
            results,
            findings,
            ledger,
            impact_graph,
            taxonomy_report,
            coverage_report,
            matrix,
            semantic_report,
        ) = _prepare_run(args, state)
        taxonomy = _load_taxonomy(
            Path(args.taxonomy) if args.taxonomy else None,
            subject.subject_kind,
        )
        capability = _capability_evidence(args, output, subject)
        matrix_failure = _matrix_failure_status(semantic_report)
        if matrix_failure or not taxonomy_report["all_passed"] or any(
            result.status == "BLOCKED" for result in results
        ):
            status = (
                matrix_failure
                or ("BLOCKED_TAXONOMY" if not taxonomy_report["all_passed"] else None)
                or "BLOCKED_DETECTOR"
            )
            state.transition(
                "adapter_failed"
                if status == "BLOCKED_ADAPTER"
                else "taxonomy_gap"
                if status == "BLOCKED_TAXONOMY"
                else "detector_failed"
            )
            _write_failure(
                output,
                status=status,
                failure_code=status,
                error="repair check phase is blocked",
                command="repair",
            )
            return 2
        if not findings:
            _write_json(
                output / "summary.json",
                _summary(
                    status="CHECKED",
                    subject=subject,
                    results=results,
                    ledger=ledger,
                    impact_digest=impact_graph["graph_digest"],
                    taxonomy_digest=taxonomy_report["report_digest"],
                    coverage_digest=coverage_report["coverage_digest"],
                    matrix_digest=matrix["matrix_digest"] if matrix else None,
                    capability_digest=(
                        capability["evidence_digest"] if capability else None
                    ),
                    capability_status=(
                        capability["status"] if capability else None
                    ),
                    semantic_matrix_digest=semantic_report["report_digest"],
                    semantic_cell_count=semantic_report["cell_count"],
                ),
            )
            return 0

        state.transition("plan")
        decisions = None
        if getattr(args, "decisions", None):
            loaded_decisions = strict_loads(Path(args.decisions).read_bytes())
            if not isinstance(loaded_decisions, dict):
                raise EvidenceBlocked("decisions must be a JSON object")
            decisions = loaded_decisions
        batch = plan_batch(
            findings,
            subject,
            scope_id=state.run_id,
            registry_digest=state.bindings["runtime_registry_digest"],
            policy_digest=state.bindings["taxonomy_digest"],
            decisions=decisions,
        )
        _write_json(output / "repair-plan-v2.json", batch)
        _write_json(output / "repair-batch.json", batch)
        state.transition("preflight")
        receipt = apply_batch(
            subject,
            batch,
            args.candidate,
            receipt_path=output / "candidate-transaction.json",
        )
        state.transition("build_candidate")
        candidate_subject = build_subject(args.candidate, subject.subject_kind)
        candidate_coverage_report = build_complete_coverage(
            {item.locator: item.content for item in candidate_subject.files}
        )
        candidate_manifest = receipt["candidate_manifest"]
        if not isinstance(candidate_manifest, dict):
            raise EvidenceBlocked("repair transaction has no candidate-manifest-v2")
        state.transition(
            "verify",
            candidate=str(candidate_subject.root),
            candidate_digest=candidate_subject.tree_digest,
            candidate_snapshot_digest=candidate_subject.snapshot_digest,
        )
        candidate_results = run_default_detectors(candidate_subject)
        candidate_semantic_report = execute_semantic_matrix(
            candidate_subject,
            state.bindings.get("runtime_registry_snapshot") or load_registry(),
            phase="VERIFICATION",
        )
        matrix_failure = _matrix_failure_status(candidate_semantic_report)
        if matrix_failure is not None:
            raise VerificationBlocked(
                f"candidate semantic matrix is blocked: {matrix_failure}"
            )
        candidate_semantic_findings = _semantic_risk_findings(
            candidate_semantic_report,
            candidate_subject,
        )
        candidate_inventory_report = build_source_inventory(
            candidate_subject,
            candidate_digest=candidate_subject.tree_digest,
            registry_snapshot=load_registry(),
        )
        candidate_resource_ids = {
            str(row["locator"]): str(row["source_id"])
            for row in candidate_inventory_report["sources"]
            if row["source_type"] == "RESOURCE"
        }
        mapped_candidate_results = []
        for result in candidate_results:
            mapped = []
            for finding in result.findings:
                item = dict(finding)
                source_id = str(item["source_id"])
                if source_id.startswith("source:"):
                    item["source_id"] = candidate_resource_ids.get(
                        source_id.removeprefix("source:"),
                        source_id,
                    )
                mapped.append(item)
            mapped_candidate_results.append(
                DetectorResult(
                    result.detector_id,
                    result.status,
                    tuple(mapped),
                    result.error,
                    result.detector_version,
                    result.taxonomy_category_id,
                    result.evidence_plane,
                )
            )
        candidate_results = tuple(mapped_candidate_results)
        for finding in candidate_semantic_findings:
            source_id = str(finding["source_id"])
            if source_id.startswith("source:"):
                finding["source_id"] = candidate_resource_ids.get(
                    source_id.removeprefix("source:"),
                    source_id,
                )
        run = _run_manifest(
            state=state,
            subject=subject,
            taxonomy=taxonomy,
            coverage_report=coverage_report,
            knowledge_pack=_load_requested_knowledge_pack(args, subject.subject_kind),
            registry=load_registry(),
            batch=batch,
            candidate_digest=candidate_subject.tree_digest,
        )
        candidate_inventory = _candidate_source_inventory(
            candidate_inventory_report,
            candidate_digest=candidate_subject.tree_digest,
            run=run,
        )
        candidate_impact = _candidate_impact_artifact(
            build_impact_graph(
                candidate_subject,
                [
                    finding
                    for result in candidate_results
                    for finding in result.findings
                ]
                + candidate_semantic_findings,
            ),
            run,
        )
        candidate_context = _taxonomy_context(
            candidate_subject,
            candidate_results,
            [
                finding
                for result in candidate_results
                for finding in result.findings
            ]
            + candidate_semantic_findings,
            ledger,
            taxonomy,
            candidate_impact,
            candidate_coverage_report,
            _load_requested_knowledge_pack(args, subject.subject_kind),
            candidate_semantic_report,
        )
        candidate_taxonomy_report = qualify_taxonomy(taxonomy, candidate_context)
        candidate_taxonomy = _candidate_taxonomy_artifact(
            candidate_taxonomy_report,
            run,
        )
        detection_report = _role_report(
            candidate_semantic_report,
            run,
            role="detector",
        )
        oracle_report = _role_report(
            candidate_semantic_report,
            run,
            role="oracle",
        )
        candidate_matrix = _candidate_matrix_artifact(
            candidate_semantic_report,
            run,
        )
        candidate_required_sources = [
            str(item["source_id"]) for item in candidate_inventory_report["sources"]
        ]
        candidate_observed_sources = [
            str(item["source_id"])
            for item in candidate_inventory_report["sources"]
            if item["applicability"] != "REQUIRED_MISSING"
        ]
        final_ledger = verify_repair(
            original_findings=findings,
            candidate_results=candidate_results,
            candidate_digest=candidate_subject.tree_digest,
            scope_digest=str(run["scope_digest"]),
            required_sources=candidate_required_sources,
            observed_sources=candidate_observed_sources,
            source_inventory=candidate_inventory,
            expected_detector_ids=_detector_ids(),
            run=run,
            subject_digest=subject.tree_digest,
            detection_report=detection_report,
            oracle_report=oracle_report,
            taxonomy_report=candidate_taxonomy,
            impact_graph=candidate_impact,
            matrix=candidate_matrix,
            additional_candidate_findings=candidate_semantic_findings,
        )
        candidate_source_closure = build_source_closure(
            candidate_inventory_report,
            scope_id=str(run["run_id"]),
            evidence=build_source_closure_evidence(
                candidate_inventory_report,
                semantic_report=candidate_semantic_report,
                environment_digest=str(state.bindings["environment_digest"]),
            ),
        )
        assert_source_closure_complete(candidate_source_closure)
        original_ids = {str(item["risk_id"]) for item in findings}
        candidate_findings = [
            item
            for item in final_ledger["items"]
            if str(item["risk_id"]) not in original_ids
        ]
        observations = ObservationJournal(output / "observations.jsonl")
        _append_issue_observations(
            observations,
            candidate_subject,
            candidate_findings,
            source_phase="VERIFICATION",
            source_run_id=state.run_id,
        )
        _verify_observation_journal(
            output / "observations.jsonl",
            expected_count=len(findings) + len(candidate_findings),
            source_run_id=state.run_id,
            redaction_policy_digest=_redaction_policy_digest(),
        )
        candidate_closure = require_candidate_closure(
            candidate=candidate_manifest,
            ledger=final_ledger,
            source_inventory=candidate_inventory,
            detection=detection_report,
            oracle=oracle_report,
            taxonomy=candidate_taxonomy,
            impact=candidate_impact,
            matrix=candidate_matrix,
            registry=load_registry(),
            run=run,
            candidate_root=candidate_subject.root,
            source_closure=candidate_source_closure,
            source_denominator_digest=(
                candidate_inventory_report["source_denominator_digest"]
            ),
        )
        _write_json(output / "run-manifest-v2.json", run)
        _write_json(
            output / "candidate-subject-manifest.json",
            _subject_manifest(
                candidate_subject,
                taxonomy,
                candidate_coverage_report,
                _load_requested_knowledge_pack(args, subject.subject_kind),
            ),
        )
        _write_json(
            output / "candidate-character-coverage.json",
            candidate_coverage_report,
        )
        _write_json(output / "candidate-source-inventory.json", candidate_inventory)
        _write_jsonl(
            output / "candidate-required-sources.jsonl",
            list(candidate_inventory_report["sources"]),
        )
        _write_json(
            output / "candidate-source-closure.json",
            candidate_source_closure,
        )
        _write_json(
            output / "candidate-semantic-matrix.json",
            candidate_semantic_report,
        )
        _write_jsonl(
            output / "candidate-semantic-cells.jsonl",
            list(candidate_semantic_report["cells"]),
        )
        _write_json(output / "candidate-detections.json", detection_report)
        _write_json(output / "candidate-oracles.json", oracle_report)
        _write_json(output / "candidate-impact-graph.json", candidate_impact)
        _write_json(output / "candidate-taxonomy-coverage.json", candidate_taxonomy)
        _write_json(
            output / "candidate-taxonomy-qualification.json",
            candidate_taxonomy_report,
        )
        _write_json(
            output / "candidate-verification-matrix.json",
            candidate_matrix,
        )
        _write_json(output / "candidate-closure.json", candidate_closure)
        _assert_inputs_current(
            args,
            state,
            expected_subject_digest=subject.tree_digest,
        )
        _write_json(
            output / "candidate-manifest-v2.json",
            candidate_manifest,
        )
        _write_json(output / "candidate-manifest.json", candidate_manifest)
        _write_json(output / "final-risk-ledger.json", final_ledger)
        status = "REPAIRED_CANDIDATE"
        if status != "REPAIRED_CANDIDATE":
            state.transition("verification_failed")
            _write_failure(
                output,
                status=status,
                failure_code="OPEN_FINDINGS",
                error="candidate verification retained open findings",
                command="repair",
            )
            return 2
        _write_json(
            output / "summary.json",
            _summary(
                status=status,
                subject=subject,
                results=results,
                ledger=final_ledger,
                impact_digest=candidate_impact["graph_digest"],
                candidate_digest=candidate_subject.tree_digest,
                taxonomy_digest=candidate_taxonomy["report_digest"],
                coverage_digest=candidate_coverage_report["coverage_digest"],
                matrix_digest=candidate_matrix["matrix_digest"],
                run_manifest_digest=run["manifest_digest"],
                candidate_closure_digest=candidate_closure["proof_digest"],
                capability_digest=(
                    capability["evidence_digest"] if capability else None
                ),
                capability_status=(
                    capability["status"] if capability else None
                ),
                semantic_matrix_digest=semantic_report["report_digest"],
                semantic_cell_count=semantic_report["cell_count"],
            ),
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI failure boundary
        return _record_failure(
            output=output,
            command="repair",
            state=state,
            exc=exc,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="full-inspection-repair")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "repair"):
        command = subparsers.add_parser(name)
        command.add_argument("--target", required=True)
        command.add_argument("--kind", required=True)
        command.add_argument("--output", required=True)
        command.add_argument("--taxonomy")
        command.add_argument("--expected-tree-digest")
        command.add_argument("--expected-policy-digest")
        command.add_argument("--expected-environment-digest")
        command.add_argument("--evaluation-evidence")
        command.add_argument("--capability-pack")
        command.add_argument("--capability-required", action="store_true")
        command.add_argument("--knowledge-pack")
        command.add_argument("--knowledge-pack-lock")
        command.add_argument("--decisions")
        if name == "repair":
            command.add_argument("--candidate", required=True)
    taxonomy = subparsers.add_parser("build-taxonomy")
    taxonomy.add_argument("--kind", required=True)
    taxonomy.add_argument("--output", required=True)
    capabilities = subparsers.add_parser("capabilities")
    capability_subparsers = capabilities.add_subparsers(
        dest="capability_command",
        required=True,
    )
    validate = capability_subparsers.add_parser("validate")
    validate.add_argument("--pack")
    validate.add_argument("--output")
    run = capability_subparsers.add_parser("run")
    run.add_argument("--target", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--pack")
    run.add_argument("--slice", action="append", default=[])
    run.add_argument("--allow-mutation", action="store_true")
    run.add_argument("--non-strict", action="store_true")
    matrix = capability_subparsers.add_parser("matrix")
    matrix.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "build-taxonomy":
        output = Path(args.output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            coverage = default_taxonomy_coverage(args.kind)
            assert_taxonomy_complete(coverage, (args.kind.upper(),))
        except (ValueError, ContractError) as exc:
            _write_json(
                output,
                {"status": "BLOCKED_TAXONOMY", "error": str(exc)},
            )
            return 2
        _write_json(output, coverage)
        return 0
    if args.command == "capabilities":
        try:
            if args.capability_command == "validate":
                result = validate_pack(args.pack or Path(__file__).resolve().parents[2] / "capabilities/pack.json")
                if args.output:
                    _write_json(Path(args.output).resolve(), result)
                print(json.dumps(result, ensure_ascii=False, sort_keys=True))
                return 0
            if args.capability_command == "run":
                result = run_pack(
                    target=args.target,
                    output=args.output,
                    pack_path=(
                        args.pack
                        or Path(__file__).resolve().parents[2]
                        / "capabilities/pack.json"
                    ),
                    slice_ids=args.slice or None,
                    strict=not args.non_strict,
                    include_mutation=args.allow_mutation,
                )
                print(json.dumps(result, ensure_ascii=False, sort_keys=True))
                return 0 if result["status"] in {"PASS", "INCOMPLETE"} else 2
            if args.capability_command == "matrix":
                result = run_contract_matrix(args.output)
                print(json.dumps(result, ensure_ascii=False, sort_keys=True))
                return 0 if result["status"] == "PASS" else 2
            raise AssertionError(
                f"unhandled capability command: {args.capability_command}"
            )
        except CapabilityBlocked as exc:
            output_arg = getattr(args, "output", None)
            output = None
            if output_arg:
                output_root = Path(output_arg).resolve()
                if args.capability_command == "matrix":
                    output = output_root / "blocked-matrix.json"
                elif args.capability_command == "run":
                    output = output_root / "blocked-run.json"
                else:
                    output = output_root
            result = {
                "schema_version": 1,
                "status": "BLOCKED",
                "failure_code": "CAPABILITY_BLOCKED",
                "error": str(exc),
            }
            if output is not None:
                output.parent.mkdir(parents=True, exist_ok=True)
                _write_json(output, result)
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 2
    if args.command == "check":
        try:
            resolve_layout("check", target=args.target, output=args.output)
        except ControlPlaneBlocked as exc:
            result = {
                "schema_version": 1,
                "status": "BLOCKED_SCOPE",
                "failure_code": exc.failure_code,
                "error": str(exc),
            }
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 2
        return _check(args)
    if args.command == "repair":
        try:
            resolve_layout(
                "repair",
                target=args.target,
                output=args.output,
                candidate=args.candidate,
            )
        except ControlPlaneBlocked as exc:
            result = {
                "schema_version": 1,
                "status": "BLOCKED_SCOPE",
                "failure_code": exc.failure_code,
                "error": str(exc),
            }
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 2
        return _repair(args)
    raise AssertionError(f"unhandled command: {args.command}")
