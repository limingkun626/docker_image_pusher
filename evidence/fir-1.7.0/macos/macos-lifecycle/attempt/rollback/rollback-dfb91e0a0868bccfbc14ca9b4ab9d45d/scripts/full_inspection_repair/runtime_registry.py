from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

from .contracts import ContractError, canonical_digest

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "policies" / "runtime-registry-v3.json"
SCHEMA_PATH = ROOT / "contracts" / "runtime-registry-v3.schema.json"
TARGET_KINDS = ("SKILL",)
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
TERMINAL_STATES = frozenset(
    {
        "COVERED_BY_NATIVE_DETECTOR",
        "COVERED_BY_EXACT_ADAPTER",
        "COVERED_BY_INDEPENDENT_ORACLE",
        "MERGED_WITH_PRIMARY_CELL",
        "NOT_APPLICABLE_WITH_PROOF",
    }
)
BRANCH_KEYS = (
    "target_adapters",
    "source_census",
    "impact_scanners",
    "detectors",
    "oracles",
    "external_adapters",
    "repair_operations",
    "verification_cells",
    "sandbox_backends",
    "tool_closures",
)


class RegistryError(ContractError):
    """Raised when the code-frozen runtime registry is invalid."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class RegistrySnapshot(Mapping[str, Any]):
    _data: Mapping[str, Any]

    @property
    def registry_id(self) -> str:
        return str(self._data["registry_id"])

    @property
    def registry_version(self) -> str:
        return str(self._data["registry_version"])

    @property
    def registry_digest(self) -> str:
        return str(self._data["registry_digest"])

    @property
    def target_kinds(self) -> tuple[str, ...]:
        return tuple(str(item) for item in self._data["target_kinds"])

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def as_dict(self) -> dict[str, Any]:
        return _thaw(self._data)

    def required_cells(self, target_kind: str = "SKILL") -> tuple[str, ...]:
        rows = [
            str(row["cell_id"])
            for row in self._data["cell_bindings"]
            if row["target_kind"] == target_kind
        ]
        return tuple(sorted(rows))

    def cell_binding(self, cell_id: str) -> dict[str, Any]:
        matches = [
            row for row in self._data["cell_bindings"] if row["cell_id"] == cell_id
        ]
        if len(matches) != 1:
            code = "CELL_BINDING_DUPLICATE" if matches else "CELL_BINDING_MISSING"
            raise RegistryError(code, cell_id)
        return _thaw(matches[0])

    def binding(self, kind_or_id: str, binding_id: str | None = None) -> dict[str, Any]:
        if binding_id is None:
            binding_id = kind_or_id
            candidates = [
                row
                for key in BRANCH_KEYS
                for row in self._data[key]
                if str(row.get("binding_id") or row.get("adapter_id") or row.get("scanner_id") or row.get("tool_id") or row.get("operation_id") or row.get("backend_id") or row.get("producer_id")).split(":")[-1] == binding_id.split(":")[-1]
            ]
        else:
            branch = _branch_for_kind(kind_or_id)
            candidates = [
                row
                for row in self._data[branch]
                if str(row.get("binding_id") or row.get("adapter_id") or row.get("scanner_id") or row.get("tool_id") or row.get("operation_id") or row.get("backend_id") or row.get("producer_id")) == binding_id
            ]
        if len(candidates) != 1:
            raise RegistryError(
                "BINDING_AMBIGUOUS" if candidates else "BINDING_MISSING",
                str(binding_id),
            )
        return _thaw(candidates[0])

    def platform_capability(
        self, logical_tool_id: str, platform: str
    ) -> dict[str, Any]:
        row = self.binding("tool", logical_tool_id)
        platforms = {str(item).upper() for item in row.get("platforms", ())}
        available = platform.upper() in platforms
        return {
            "tool_id": logical_tool_id,
            "platform": platform.upper(),
            "status": "AVAILABLE" if available else "UNAVAILABLE",
            "failure_code": None if available else "TOOL_UNAVAILABLE",
            "unavailable_reason": None
            if available
            else f"{logical_tool_id} is not declared for {platform.upper()}",
        }

    def implementation_digest(self, module_name: str) -> str:
        try:
            spec = importlib.util.find_spec(module_name)
        except (ImportError, AttributeError, ValueError) as exc:
            raise RegistryError("EXACT_ADAPTER_MODULE_MISSING", module_name) from exc
        if spec is None or spec.origin is None:
            raise RegistryError("EXACT_ADAPTER_MODULE_MISSING", module_name)
        path = Path(spec.origin)
        if not path.is_file():
            raise RegistryError("EXACT_ADAPTER_MODULE_MISSING", module_name)
        return hashlib.sha256(path.read_bytes()).hexdigest()


def _branch_for_kind(kind: str) -> str:
    normalized = kind.casefold().replace("-", "_")
    mapping = {
        "target_adapter": "target_adapters",
        "source": "source_census",
        "source_producer": "source_census",
        "scanner": "impact_scanners",
        "detector": "detectors",
        "oracle": "oracles",
        "exact_adapter": "external_adapters",
        "adapter": "external_adapters",
        "repair_operation": "repair_operations",
        "verification_cell": "verification_cells",
        "verification_runner": "verification_cells",
        "sandbox_backend": "sandbox_backends",
        "tool": "tool_closures",
    }
    if normalized not in mapping:
        raise RegistryError("RUNTIME_REGISTRY_INVALID", f"unknown binding kind: {kind}")
    return mapping[normalized]


def _row_id(row: Mapping[str, Any]) -> str:
    for key in (
        "binding_id",
        "adapter_id",
        "scanner_id",
        "tool_id",
        "operation_id",
        "backend_id",
        "producer_id",
    ):
        value = row.get(key)
        if value is not None:
            return str(value)
    return ""


def _implementation_specs(row: Mapping[str, Any]) -> list[tuple[str, str]]:
    specs: list[tuple[str, str]] = []
    direct = row.get("implementation")
    if isinstance(direct, Mapping):
        module = str(direct.get("module", ""))
        callable_name = str(direct.get("callable", ""))
        if module and callable_name:
            specs.append((module, callable_name))
    for key in (
        "detector_binding",
        "oracle_binding",
        "exact_adapter_binding",
    ):
        binding = row.get(key)
        if isinstance(binding, Mapping):
            module = str(binding.get("module", ""))
            callable_name = str(binding.get("callable", ""))
            if module and callable_name:
                specs.append((module, callable_name))
    return specs


def _validate_package_relative(value: str, field: str) -> None:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ":" in path.parts[0] or ".." in path.parts:
        raise RegistryError(
            "RUNTIME_REGISTRY_INVALID",
            f"{field} must be package-relative: {value}",
        )


def _import_callable(module_name: str, callable_name: str) -> None:
    try:
        module = importlib.import_module(module_name)
    except (ImportError, ModuleNotFoundError) as exc:
        raise RegistryError("EXACT_ADAPTER_MODULE_MISSING", module_name) from exc
    target = module
    for part in callable_name.split("."):
        if not hasattr(target, part):
            raise RegistryError(
                "EXACT_ADAPTER_CALLABLE_MISSING",
                f"{module_name}:{callable_name}",
            )
        target = getattr(target, part)
    if not callable(target):
        raise RegistryError(
            "EXACT_ADAPTER_CALLABLE_MISSING",
            f"{module_name}:{callable_name} is not callable",
        )


def _validate_cells(rows: list[Mapping[str, Any]]) -> None:
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
    ids = [str(row.get("cell_id", "")) for row in rows]
    if len(rows) != 72 or set(ids) != expected or len(set(ids)) != 72:
        raise RegistryError("CELL_BINDING_MISSING", "required 72-cell denominator")
    by_id = {str(row["cell_id"]): row for row in rows}
    mechanisms: dict[str, str] = {}
    for row in rows:
        cell_id = str(row["cell_id"])
        terminal = str(row.get("terminal_state", ""))
        if terminal not in TERMINAL_STATES:
            raise RegistryError("RUNTIME_REGISTRY_INVALID", f"nonterminal cell: {cell_id}")
        detector = row.get("detector_binding")
        oracle = row.get("oracle_binding")
        exact = row.get("exact_adapter_binding")
        primary = row.get("primary_cell_id")
        proof = row.get("n_a_proof_ref")
        if terminal == "MERGED_WITH_PRIMARY_CELL":
            if detector or oracle or exact or proof:
                raise RegistryError("CELL_BINDING_DUPLICATE", cell_id)
            if primary not in by_id or primary == cell_id:
                raise RegistryError("CELL_BINDING_MISSING", f"{cell_id}->{primary}")
            continue
        if terminal == "NOT_APPLICABLE_WITH_PROOF":
            if detector or oracle or exact or not proof:
                raise RegistryError("RUNTIME_REGISTRY_INVALID", cell_id)
            continue
        if terminal == "COVERED_BY_INDEPENDENT_ORACLE":
            if detector or exact or not oracle:
                raise RegistryError("CELL_BINDING_DUPLICATE", cell_id)
        elif terminal == "COVERED_BY_EXACT_ADAPTER":
            if detector or not exact or not oracle:
                raise RegistryError("CELL_BINDING_DUPLICATE", cell_id)
        elif terminal == "COVERED_BY_NATIVE_DETECTOR":
            if not detector or not oracle or exact:
                raise RegistryError("CELL_BINDING_DUPLICATE", cell_id)
        else:
            raise RegistryError("RUNTIME_REGISTRY_INVALID", cell_id)
        primary_binding = detector or exact or oracle
        if isinstance(primary_binding, Mapping):
            mechanism = str(primary_binding.get("mechanism_id") or "")
        else:
            mechanism = str(primary_binding or "")
        if mechanism and mechanism in mechanisms:
            raise RegistryError(
                "CELL_BINDING_DUPLICATE",
                f"{cell_id} duplicates {mechanisms[mechanism]}",
            )
        if mechanism:
            mechanisms[mechanism] = cell_id
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(cell_id: str) -> None:
        if cell_id in visited:
            return
        if cell_id in visiting:
            raise RegistryError("RUNTIME_REGISTRY_INVALID", f"merge cycle: {cell_id}")
        visiting.add(cell_id)
        row = by_id[cell_id]
        if row["terminal_state"] == "MERGED_WITH_PRIMARY_CELL":
            visit(str(row["primary_cell_id"]))
        visiting.remove(cell_id)
        visited.add(cell_id)

    for cell_id in ids:
        visit(cell_id)


def validate_registry(data: Mapping[str, Any]) -> None:
    if data.get("schema_version") != 3:
        raise RegistryError("RUNTIME_REGISTRY_INVALID", "schema_version must be 3")
    if data.get("release_authority") is not False:
        raise RegistryError("RUNTIME_REGISTRY_INVALID", "release_authority must be false")
    declared = data.get("registry_digest")
    material = {key: value for key, value in data.items() if key != "registry_digest"}
    if declared != canonical_digest(material):
        raise RegistryError("RUNTIME_REGISTRY_DRIFT", "registry_digest mismatch")
    for key in BRANCH_KEYS:
        if not isinstance(data.get(key), list):
            raise RegistryError("RUNTIME_REGISTRY_INVALID", f"{key} must be an array")
    artifact_set = data.get("artifact_set")
    if not isinstance(artifact_set, list) or not artifact_set:
        raise RegistryError("RUNTIME_REGISTRY_INVALID", "artifact_set is empty")
    artifact_paths: set[str] = set()
    for artifact in artifact_set:
        if not isinstance(artifact, Mapping):
            raise RegistryError("RUNTIME_REGISTRY_INVALID", "artifact must be an object")
        path_value = str(artifact.get("path", ""))
        _validate_package_relative(path_value, "artifact_set.path")
        path = ROOT / path_value
        if not path.is_file():
            raise RegistryError("EXACT_ADAPTER_MODULE_MISSING", path_value)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if artifact.get("sha256") not in {None, "", digest}:
            raise RegistryError("RUNTIME_REGISTRY_DRIFT", f"{path_value} bytes changed")
        artifact_paths.add(path_value)

    binding_ids: set[str] = set()
    for branch in BRANCH_KEYS:
        for row in data[branch]:
            if not isinstance(row, Mapping):
                raise RegistryError("RUNTIME_REGISTRY_INVALID", f"{branch} row")
            binding_id = _row_id(row)
            if not binding_id:
                raise RegistryError("RUNTIME_REGISTRY_INVALID", f"{branch} row lacks ID")
            if binding_id in binding_ids:
                raise RegistryError("CELL_BINDING_DUPLICATE", binding_id)
            binding_ids.add(binding_id)
            for spec in _implementation_specs(row):
                _import_callable(*spec)
            for key in ("path", "module_path", "executable", "script", "rule_path"):
                if key in row and isinstance(row[key], str):
                    _validate_package_relative(row[key], f"{binding_id}.{key}")
                    if key in {"path", "module_path", "script", "rule_path"}:
                        if row[key] not in artifact_paths and not (ROOT / row[key]).is_file():
                            raise RegistryError("EXACT_ADAPTER_MODULE_MISSING", row[key])
            for spec in _implementation_specs(row):
                module_digest = hashlib.sha256(
                    Path(importlib.util.find_spec(spec[0]).origin).read_bytes()
                ).hexdigest()
                implementation_digest = row.get("implementation_digest")
                if implementation_digest not in {None, "", module_digest}:
                    raise RegistryError(
                        "RUNTIME_REGISTRY_DRIFT",
                        f"{binding_id} implementation digest mismatch",
                    )

    sources = data.get("source_census")
    source_types = {
        source_type
        for row in sources
        for source_type in row.get("source_types", ())
    }
    if set(SOURCE_TYPES) - source_types:
        raise RegistryError(
            "RUNTIME_REGISTRY_INVALID",
            "source census misses " + ", ".join(sorted(set(SOURCE_TYPES) - source_types)),
        )
    if set(data.get("target_kinds", ())) != set(TARGET_KINDS):
        raise RegistryError("RUNTIME_REGISTRY_INVALID", "target_kinds must be SKILL only")
    _validate_cells(data["cell_bindings"])


def load_registry(
    path: str | Path = REGISTRY_PATH,
    *,
    validate_implementations: bool = True,
    validate_schema: bool = True,
) -> RegistrySnapshot:
    registry_path = Path(path)
    try:
        data = json.loads(registry_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise RegistryError("RUNTIME_REGISTRY_INVALID", str(exc)) from exc
    if not isinstance(data, dict):
        raise RegistryError("RUNTIME_REGISTRY_INVALID", "registry must be an object")
    if validate_schema:
        try:
            import jsonschema

            schema = json.loads(SCHEMA_PATH.read_bytes())
            jsonschema.Draft202012Validator(schema).validate(data)
        except ImportError:
            pass
        except Exception as exc:
            raise RegistryError("RUNTIME_REGISTRY_INVALID", str(exc)) from exc
    declared = data.get("registry_digest")
    material = {key: value for key, value in data.items() if key != "registry_digest"}
    if declared != canonical_digest(material):
        raise RegistryError("RUNTIME_REGISTRY_DRIFT", "registry_digest mismatch")
    if validate_implementations:
        validate_registry(data)
    return RegistrySnapshot(_freeze(data))


def load_runtime_registry(
    path: str | Path = REGISTRY_PATH,
) -> RegistrySnapshot:
    return load_registry(path)


def freeze_registry(path: str | Path = REGISTRY_PATH) -> RegistrySnapshot:
    return load_registry(path)


def current_platform() -> str:
    if os.name == "nt":
        return "WINDOWS"
    if sys_platform() == "darwin":
        return "MACOS"
    return "LINUX"


def sys_platform() -> str:
    import sys

    return sys.platform
