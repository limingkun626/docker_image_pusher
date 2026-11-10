from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair import __version__
from full_inspection_repair.cli import _parser as inspection_parser
from release_skill import _parser as release_parser

DOCS = (
    ROOT / "SKILL.md",
    ROOT / "references" / "operations.md",
    ROOT / "references" / "architecture-v9.2.1.md",
)
TEXT_FILES = (
    *DOCS,
    ROOT / "agents" / "openai.yaml",
    ROOT / "requirements.txt",
    ROOT / "scripts" / "full_inspection_repair" / "__init__.py",
    Path(__file__),
)
FENCE_RE = re.compile(r"^```([^\r\n]*)\r?\n(.*?)^```\s*$", re.MULTILINE | re.DOTALL)
MARKER_RE = re.compile(
    r"^<!-- documented-json: (?:non-contract-example|contract:([a-z0-9-]+)) -->$"
)


def _fences(text: str, language: str) -> list[tuple[int, str]]:
    return [
        (match.start(), match.group(2))
        for match in FENCE_RE.finditer(text)
        if match.group(1).strip() == language
    ]


def _documented_commands() -> list[tuple[str, list[str]]]:
    commands: list[tuple[str, list[str]]] = []
    for path in DOCS:
        for _, block in _fences(path.read_text(encoding="utf-8"), "powershell"):
            command = re.sub(r"`\s*\r?\n", " ", block).strip()
            if not command.startswith("python "):
                continue
            tokens = command.split()
            script = tokens[1].replace("\\", "/")
            if script not in {
                "scripts/run_inspection.py",
                "scripts/release_skill.py",
            }:
                continue
            commands.append((script, tokens[2:]))
    return commands


def _release_command_parser(command: str) -> argparse.ArgumentParser:
    parser = release_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices[command]
    raise AssertionError("release parser has no subcommands")


def test_package_version_and_dependency_lock_are_current() -> None:
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    frontmatter = yaml.safe_load(skill.split("---", 2)[1])
    requirements = {
        line.split("==", 1)[0].casefold(): line.split("==", 1)[1]
        for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    assert frontmatter["version"] == "1.4.0"
    assert __version__ == "1.4.0"
    assert requirements == {
        "cryptography": "50.0.0",
        "jsonschema": "4.26.0",
        "pyyaml": "6.0.3",
        "pytest": "9.1.1",
    }


def test_exact_documented_powershell_commands_parse_with_final_parsers() -> None:
    commands = _documented_commands()
    parsed: set[tuple[str, str]] = set()
    release_commands: list[argparse.Namespace] = []

    for script, tokens in commands:
        parser = (
            inspection_parser()
            if script == "scripts/run_inspection.py"
            else release_parser()
        )
        args = parser.parse_args(tokens)
        parsed.add((script, args.command))
        if script == "scripts/release_skill.py":
            release_commands.append(args)

    assert parsed == {
        ("scripts/run_inspection.py", "build-taxonomy"),
        ("scripts/run_inspection.py", "check"),
        ("scripts/run_inspection.py", "repair"),
        ("scripts/release_skill.py", "package"),
        ("scripts/release_skill.py", "review"),
        ("scripts/release_skill.py", "claim"),
        ("scripts/release_skill.py", "install"),
    }

    for command in ("review", "claim", "install"):
        parser = _release_command_parser(command)
        action = next(item for item in parser._actions if item.dest == "verification_method")
        assert action.default == "sigstore-keyless"
        assert set(action.choices) == {"sigstore-keyless", "ed25519-detached"}

    for command in ("review", "claim", "install"):
        documented = next(
            item for item in release_commands if item.command == command
        )
        assert documented.verification_method == "sigstore-keyless"
        assert documented.attestation == "$attestation"
        assert documented.sigstore_bundle == "$sigstoreBundle"
        assert documented.sigstore_verifier == "$sigstoreVerifier"
        assert documented.cert_identity == "$certIdentity"
        assert documented.oidc_issuer == "$oidcIssuer"
        if command == "review":
            assert documented.reviewer == "$certIdentity"

    fallback = next(
        item
        for item in release_commands
        if item.command == "review"
        and item.verification_method == "ed25519-detached"
    )
    assert fallback.signature == "$signature"
    assert fallback.public_key == "$publicKey"
    assert fallback.trust_root == "$edTrustRoot"


def test_architecture_json_examples_are_valid_and_explicitly_non_contract() -> None:
    text = (ROOT / "references" / "architecture-v9.2.1.md").read_text(
        encoding="utf-8"
    )

    for start, body in _fences(text, "json"):
        previous = text[:start].rstrip().splitlines()[-1]
        marker = MARKER_RE.fullmatch(previous)
        assert marker, f"unmarked JSON example before offset {start}"
        payload = json.loads(body)
        schema_name = marker.group(1)
        if schema_name:
            schema = json.loads(
                (ROOT / "contracts" / f"{schema_name}.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            jsonschema.Draft202012Validator(schema).validate(payload)


def test_markdown_links_fences_and_encoding_are_clean() -> None:
    link_pattern = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")

    for path in TEXT_FILES:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
        assert raw.endswith(b"\n"), f"{path} lacks final newline"
        if path.suffix != ".md":
            continue
        assert text.count("\n```") % 2 == 0, f"unbalanced fences: {path}"
        for target in link_pattern.findall(text):
            parsed = urlparse(target)
            if parsed.scheme or target.startswith("#"):
                continue
            resolved = (path.parent / unquote(parsed.path)).resolve()
            assert resolved.exists(), f"broken link in {path}: {target}"


def test_json_and_yaml_contract_files_parse() -> None:
    for path in sorted((ROOT / "contracts").glob("*.json")):
        json.loads(path.read_text(encoding="utf-8"))
    for path in sorted((ROOT / "policies").glob("*.json")):
        json.loads(path.read_text(encoding="utf-8"))
    for path in sorted((ROOT / "agents").glob("*.yaml")):
        yaml.safe_load(path.read_text(encoding="utf-8"))


def test_documentation_contains_current_artifacts_statuses_and_release_contract() -> None:
    operations = (ROOT / "references" / "operations.md").read_text(encoding="utf-8")
    architecture = (ROOT / "references" / "architecture-v9.2.1.md").read_text(
        encoding="utf-8"
    )
    combined = operations + architecture
    combined_flat = " ".join(combined.split())

    inspection_artifacts = {
        "run-state.json",
        "subject-manifest.json",
        "required-sources.jsonl",
        "detections.json",
        "impact-graph.json",
        "risk-ledger.json",
        "taxonomy-coverage.json",
        "taxonomy-qualification.json",
        "character-coverage.json",
        "write-ahead-journal.jsonl",
        "write-ahead-journal-check.json",
        "observations.jsonl",
        "observation-journal-manifest.json",
        "summary.json",
    }
    release_artifacts = {
        "package-manifest.json",
        "review-packet.json",
        "independent-review.json",
        "release-claim.json",
        "install-receipt.json",
        "release-history.jsonl",
        "blocked-review.json",
        "blocked-claim.json",
        "blocked-install.json",
    }
    external_verification_inputs = {
        "reviewer-attestation.json",
        "reviewer-attestation.sigstore.json",
        "sigstore-verifier executable",
        "ed25519-detached",
    }
    statuses = {
        "CHECKED",
        "REPAIRED_CANDIDATE",
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
        "PASS",
        "RELEASE_READY",
        "INSTALLED",
        "VERIFIED",
    }

    for name in (
        inspection_artifacts
        | release_artifacts
        | external_verification_inputs
        | statuses
    ):
        assert f"`{name}`" in combined or name in combined
    assert (
        "package -> GitHub Actions OIDC + Sigstore bundle verification ->"
        in combined
    )
    assert "GitHub Actions OIDC" in combined_flat
    assert "`sigstore-keyless`" in combined_flat
    assert "exact certificate identity" in combined_flat
    assert "exact GitHub Actions OIDC issuer" in combined_flat
    assert "bundle_sha256" in combined_flat
    assert "verifier_command_digest" in combined_flat
    assert "not the verifier binary bytes" in combined_flat
    assert "runner image/toolchain digest" in combined_flat
    assert "id-token: write" in combined_flat
    assert "claim boundary" in combined_flat.casefold()
    assert "receipt_digest" in operations
    assert "append-only" in operations.casefold()
    assert "rollback tree" in operations
    assert "summary.md" not in architecture
    assert "13-issue-observations.jsonl" not in combined
    assert "14-observation-journal-manifest.json" not in combined


def test_docs_do_not_overclaim_platform_or_physical_power_safety() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in DOCS)
    assert re.search(r"required runtime scope is Windows, WSL Linux, and macOS", combined)
    assert re.search(r"all three platform installation results are `PASS`", combined)
    assert re.search(r"Physical\s+power-loss safety is not claimed", combined)
    assert not re.search(r"\bsupports?\s+macOS\b", combined, re.IGNORECASE)
    assert not re.search(r"physical power[- ]loss (?:is )?safe\b", combined, re.IGNORECASE)


def test_prose_punctuation_has_no_space_before_terminal_boundaries() -> None:
    bad_boundary = re.compile(r"[ \t]+[,.;:!?](?=\s|$)")
    bad_cjk_boundary = re.compile(r"[ \t]+[，。！？；：](?=\s|$)")

    for path in DOCS:
        prose = FENCE_RE.sub("", path.read_text(encoding="utf-8"))
        assert not bad_boundary.search(prose), f"punctuation spacing: {path}"
        assert not bad_cjk_boundary.search(prose), f"CJK punctuation spacing: {path}"
