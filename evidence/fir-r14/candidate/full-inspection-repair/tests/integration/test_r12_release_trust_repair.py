from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import full_inspection_repair.review as review_module
import release_skill
from full_inspection_repair.contracts import canonical_digest, canonical_json
from full_inspection_repair.release import ReleaseBlocked, replay_release_history
from full_inspection_repair.review import (
    ED25519_VERIFIER,
    REVIEWER_ATTESTATION_SCHEMA_VERSION,
    SIGSTORE_VERIFIER,
    ReviewBlocked,
    sigstore_trust_root_id,
    trust_root_id_for_public_key,
    verify_reviewer_attestation,
    verify_sigstore_attestation,
)

HISTORY_KEY = b"r12-release-history-anchor-key-0001"


def _anchor(
    registry: dict[str, object],
    *,
    evaluators: list[str] | None = None,
    history_key: bytes | None = None,
    trust_config: bytes | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "r12-test-external-authority",
        "reviewers": registry["reviewers"],
        "reviewer_registry_digest": canonical_digest(registry),
        "evaluator_artifacts": evaluators or [],
        "history_anchor_key_sha256": (
            [hashlib.sha256(history_key).hexdigest()] if history_key else []
        ),
        "sigstore_trust_config_sha256": (
            [hashlib.sha256(trust_config).hexdigest()] if trust_config else []
        ),
    }


def _ed25519_material(tmp_path: Path):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust_root = trust_root_id_for_public_key(public_key)
    registry = {
        "schema_version": 1,
        "reviewers": [
            {
                "reviewer": "reviewer-r12",
                "issuer": "issuer-r12",
                "verification_method": ED25519_VERIFIER,
                "trust_root_id": trust_root,
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "status": "ACTIVE",
            }
        ],
    }
    attestation = {
        "schema_version": REVIEWER_ATTESTATION_SCHEMA_VERSION,
        "reviewer": "reviewer-r12",
        "issuer": "issuer-r12",
        "trust_root_id": trust_root,
        "verification_method": ED25519_VERIFIER,
        "verdict": "PASS",
    }
    payload = canonical_json(attestation).encode("utf-8")
    return (
        registry,
        payload,
        private_key.sign(payload),
        public_key,
        trust_root,
    )


def test_caller_minted_reviewer_registry_cannot_use_implicit_default_anchor(
    tmp_path: Path,
) -> None:
    registry, attestation, signature, public_key, trust_root = (
        _ed25519_material(tmp_path)
    )

    with pytest.raises(ReviewBlocked, match="frozen registry"):
        verify_reviewer_attestation(
            attestation_bytes=attestation,
            signature_bytes=signature,
            public_key_bytes=public_key,
            expected_reviewer="reviewer-r12",
            expected_issuer="issuer-r12",
            expected_trust_root_id=trust_root,
            trust_registry=registry,
            trust_registry_digest=canonical_digest(registry),
        )


def test_evaluator_must_be_an_exact_anchor_approved_artifact() -> None:
    registry = {
        "schema_version": 1,
        "reviewers": [],
    }
    anchor = _anchor(registry, evaluators=["1" * 64])
    subject = {
        "evaluator_digest": canonical_digest({"caller": "text"}),
        "trust_anchor_digest": canonical_digest(anchor),
        "history_anchor_key_sha256": None,
    }
    packet = {
        "subject": subject,
        "subject_digest": canonical_digest(subject),
    }

    with pytest.raises(ReviewBlocked, match="evaluator artifact"):
        review_module.review_packet(
            producer="producer",
            reviewer="reviewer",
            packet=packet,
            trust_anchor=anchor,
            evaluator_artifact_bytes=None,
        )


def test_history_key_must_match_the_externally_frozen_identity(
    tmp_path: Path,
) -> None:
    output = tmp_path / "release"
    output.mkdir()
    key = tmp_path / "selected.key"
    key.write_bytes(HISTORY_KEY)
    anchor = _anchor(
        {"schema_version": 1, "reviewers": []},
        history_key=b"different-external-history-key-0001",
    )

    with pytest.raises(ReleaseBlocked, match="history anchor key"):
        release_skill._history_anchor_key(
            key,
            output,
            trust_anchor=anchor,
        )


def _sigstore_material(
    tmp_path: Path,
    *,
    include_helper: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    identity = "https://example.test/workflow"
    issuer = "https://issuer.example"
    verifier = tmp_path / "sigstore-verifier"
    verifier.write_bytes(b"pinned-verifier")
    files = [
        {
            "path": str(verifier),
            "sha256": hashlib.sha256(verifier.read_bytes()).hexdigest(),
            "role": "verifier",
        }
    ]
    if include_helper:
        helper = tmp_path / "sigstore_helper.py"
        helper.write_bytes(b"trusted-helper")
        files.append(
            {
                "path": str(helper),
                "sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
                "role": "helper",
            }
        )
    trust_config = b'{"trusted_root":"external"}'
    trust_config_path = tmp_path / "trust-config.json"
    trust_config_path.write_bytes(trust_config)
    trust_root = sigstore_trust_root_id(identity, issuer)
    registry = {
        "schema_version": 1,
        "reviewers": [
            {
                "reviewer": identity,
                "issuer": issuer,
                "verification_method": SIGSTORE_VERIFIER,
                "trust_root_id": trust_root,
                "verifier_sha256": hashlib.sha256(verifier.read_bytes()).hexdigest(),
                "verifier_version": "4.5.1",
                "verifier_closure": files,
                "status": "ACTIVE",
            }
        ],
    }
    anchor = _anchor(registry, trust_config=trust_config)
    attestation = tmp_path / "attestation.json"
    attestation.write_bytes(
        canonical_json(
            {
                "schema_version": REVIEWER_ATTESTATION_SCHEMA_VERSION,
                "reviewer": identity,
                "issuer": issuer,
                "trust_root_id": trust_root,
                "verification_method": SIGSTORE_VERIFIER,
                "verdict": "PASS",
            }
        ).encode("utf-8")
    )
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(b'{"bundle":"trusted"}')
    return {
        "registry": registry,
        "registry_digest": canonical_digest(registry),
        "trust_anchor": anchor,
        "identity": identity,
        "issuer": issuer,
        "attestation": attestation,
        "bundle": bundle,
        "verifier": verifier,
        "trust_config": trust_config_path,
    }, {"helper": tmp_path / "sigstore_helper.py"}


@lru_cache(maxsize=1)
def _real_venv_closure_template() -> tuple[Path, Path, Path, tuple[dict[str, object], ...]]:
    venv = Path(r"F:\Codex\runs\fir-full-closure-r5-20261110\.sigstore-venv")
    runtime = Path(
        r"C:\Users\Administrator\AppData\Local\Programs\Python\Python312"
    )
    launcher = venv / "Scripts" / "sigstore.exe"
    assert launcher.is_file()
    assert (runtime / "python312.dll").is_file()
    closure: list[dict[str, object]] = []
    for source in sorted(venv.rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(venv).as_posix()
        role = (
            "verifier"
            if source == launcher
            else "venv-config"
            if relative == "pyvenv.cfg"
            else "dependency"
        )
        closure.append(
            {
                "path": str(source),
                "relative_path": relative,
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "role": role,
            }
        )
    excluded = {
        "site-packages",
        "test",
        "idlelib",
        "tkinter",
        "turtledemo",
        "pydoc_data",
        "ensurepip",
    }
    runtime_sources = list(runtime.glob("*.dll")) + list(runtime.glob("*.exe"))
    runtime_sources += list((runtime / "DLLs").glob("*"))
    for child in (runtime / "Lib").iterdir():
        if child.name in excluded:
            continue
        runtime_sources.extend(
            item for item in child.rglob("*") if item.is_file()
        )
    for source in sorted(runtime_sources):
        if not source.is_file():
            continue
        relative = source.relative_to(runtime).as_posix()
        closure.append(
            {
                "path": str(source),
                "relative_path": "runtime/" + relative,
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "role": "runtime"
                if source.name in {"python.exe", "python312.dll"}
                else "dependency",
            }
        )
    return venv, runtime, launcher, tuple(closure)


def _real_verifier_material(
    tmp_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    venv, runtime, launcher, closure_template = _real_venv_closure_template()
    closure = [dict(item) for item in closure_template]
    identity = "https://example.test/real-venv"
    issuer = "https://issuer.example"
    trust_root = sigstore_trust_root_id(identity, issuer)
    trust_config = tmp_path / "trust-config.json"
    trust_config.write_bytes(b'{"trusted_root":"real-venv-probe"}')
    registry = {
        "schema_version": 1,
        "reviewers": [
            {
                "reviewer": identity,
                "issuer": issuer,
                "verification_method": SIGSTORE_VERIFIER,
                "trust_root_id": trust_root,
                "verifier_sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
                "verifier_version": "4.5.1",
                "verifier_root": str(venv),
                "verifier_executable_relative_path": "Scripts/sigstore.exe",
                "venv_config_relative_path": "pyvenv.cfg",
                "venv_runtime_relative_path": "runtime",
                "venv_runtime_executable_relative_path": "runtime/python.exe",
                "verifier_closure": closure,
                "status": "ACTIVE",
            }
        ],
    }
    anchor = _anchor(registry, trust_config=trust_config.read_bytes())
    attestation = tmp_path / "attestation.json"
    attestation.write_bytes(
        canonical_json(
            {
                "schema_version": REVIEWER_ATTESTATION_SCHEMA_VERSION,
                "reviewer": identity,
                "issuer": issuer,
                "trust_root_id": trust_root,
                "verification_method": SIGSTORE_VERIFIER,
                "verdict": "PASS",
            }
        ).encode("utf-8")
    )
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(b'{"bundle":"invalid-for-real-verifier"}')
    return {
        "venv": venv,
        "runtime": runtime,
        "launcher": launcher,
        "closure": closure,
        "registry": registry,
        "registry_digest": canonical_digest(registry),
        "trust_anchor": anchor,
        "identity": identity,
        "issuer": issuer,
        "attestation": attestation,
        "bundle": bundle,
        "trust_config": trust_config,
    }, {"closure": closure}


def test_sigstore_aba_replacement_of_executed_snapshot_blocks(
    tmp_path: Path,
) -> None:
    material, _ = _sigstore_material(tmp_path)

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, "sigstore 4.5.1", "")
        bundle = Path(command[command.index("--bundle") + 1])
        original = bundle.read_bytes()
        replacement = bundle.with_name("replacement")
        replacement.write_bytes(b'{"bundle":"replaced"}')
        os.replace(replacement, bundle)
        restore = bundle.with_name("restore")
        restore.write_bytes(original)
        os.replace(restore, bundle)
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(ReviewBlocked, match="Sigstore"):
        verify_sigstore_attestation(
            attestation_path=material["attestation"],
            bundle_path=material["bundle"],
            verifier_executable=material["verifier"],
            cert_identity=material["identity"],
            oidc_issuer=material["issuer"],
            trust_registry=material["registry"],
            trust_registry_digest=material["registry_digest"],
            trust_anchor=material["trust_anchor"],
            trust_config_path=material["trust_config"],
            snapshot_root=tmp_path / "snapshot",
            runner=runner,
        )


def test_sigstore_source_runtime_aba_replacement_blocks(
    tmp_path: Path,
) -> None:
    material, _ = _sigstore_material(tmp_path, include_helper=True)
    runtime = tmp_path / "runtime.bin"
    runtime.write_bytes(b"trusted-runtime")
    reviewer = material["registry"]["reviewers"][0]
    reviewer["verifier_closure"].append(
        {
            "path": str(runtime),
            "sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
            "role": "runtime",
        }
    )
    material["registry_digest"] = canonical_digest(material["registry"])
    material["trust_anchor"]["reviewer_registry_digest"] = material[
        "registry_digest"
    ]

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, "sigstore 4.5.1", "")
        original = runtime.read_bytes()
        backup = runtime.with_name("runtime.backup")
        replacement = runtime.with_name("runtime.replacement")
        os.replace(runtime, backup)
        replacement.write_bytes(b"substituted-runtime")
        os.replace(replacement, runtime)
        os.replace(backup, runtime)
        runtime.write_bytes(original)
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(ReviewBlocked, match="Sigstore input changed"):
        verify_sigstore_attestation(
            attestation_path=material["attestation"],
            bundle_path=material["bundle"],
            verifier_executable=material["verifier"],
            cert_identity=material["identity"],
            oidc_issuer=material["issuer"],
            trust_registry=material["registry"],
            trust_registry_digest=material["registry_digest"],
            trust_anchor=material["trust_anchor"],
            trust_config_path=material["trust_config"],
            snapshot_root=tmp_path / "snapshot",
            runner=runner,
        )


def test_sigstore_helper_substitution_blocks_before_execution(
    tmp_path: Path,
) -> None:
    material, paths = _sigstore_material(tmp_path, include_helper=True)
    paths["helper"].write_bytes(b"substituted-helper")
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "sigstore 4.5.1", "")

    with pytest.raises(ReviewBlocked, match="execution closure"):
        verify_sigstore_attestation(
            attestation_path=material["attestation"],
            bundle_path=material["bundle"],
            verifier_executable=material["verifier"],
            cert_identity=material["identity"],
            oidc_issuer=material["issuer"],
            trust_registry=material["registry"],
            trust_registry_digest=material["registry_digest"],
            trust_anchor=material["trust_anchor"],
            trust_config_path=material["trust_config"],
            snapshot_root=tmp_path / "snapshot",
            runner=runner,
        )
    assert calls == []


def test_sigstore_script_wrapper_requires_complete_runtime_closure(
    tmp_path: Path,
) -> None:
    material, _ = _sigstore_material(tmp_path)
    wrapper = tmp_path / "sigstore-verifier.cmd"
    wrapper.write_bytes(b"@echo off\r\npython sigstore_helper.py %*\r\n")
    reviewer = material["registry"]["reviewers"][0]
    reviewer["verifier_sha256"] = hashlib.sha256(wrapper.read_bytes()).hexdigest()
    reviewer["verifier_closure"] = [
        {
            "path": str(wrapper),
            "sha256": reviewer["verifier_sha256"],
            "role": "verifier",
        }
    ]
    material["registry_digest"] = canonical_digest(material["registry"])
    material["trust_anchor"]["reviewer_registry_digest"] = material[
        "registry_digest"
    ]
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "sigstore 4.5.1", "")

    with pytest.raises(ReviewBlocked, match="wrapper verifier"):
        verify_sigstore_attestation(
            attestation_path=material["attestation"],
            bundle_path=material["bundle"],
            verifier_executable=wrapper,
            cert_identity=material["identity"],
            oidc_issuer=material["issuer"],
            trust_registry=material["registry"],
            trust_registry_digest=material["registry_digest"],
            trust_anchor=material["trust_anchor"],
            trust_config_path=material["trust_config"],
            snapshot_root=tmp_path / "snapshot",
            runner=runner,
        )
    assert calls == []


def test_claim_write_failure_leaves_only_explicit_intent_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "release"
    output.mkdir()
    review = output / "independent-review.json"
    review.write_text(
        json.dumps(
            {
                "candidate_digest": "a" * 64,
                "review_digest": "b" * 64,
            }
        ),
        encoding="utf-8",
    )
    state = output / "run-state.json"
    state.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "run:claim",
                "current_state": "INDEPENDENT_REVIEW",
                "candidate_digest": "a" * 64,
                "history": [],
            }
        ),
        encoding="utf-8",
    )
    key = tmp_path / "history.key"
    key.write_bytes(HISTORY_KEY)
    anchor = _anchor(
        {"schema_version": 1, "reviewers": []},
        history_key=HISTORY_KEY,
    )
    monkeypatch.setattr(
        release_skill,
        "_load_release_trust_anchor",
        lambda: anchor,
    )
    monkeypatch.setattr(
        release_skill,
        "_verification_material",
        lambda args, **kwargs: {"trust_anchor": anchor},
    )
    monkeypatch.setattr(
        release_skill,
        "build_release_claim",
        lambda review, **kwargs: {
            "status": "RELEASE_READY",
            "claim_digest": "c" * 64,
            "candidate_digest": "a" * 64,
            "review_digest": "b" * 64,
            "trust_root_id": "sha256:" + "d" * 64,
            "trust_registry_digest": "e" * 64,
            "trust_anchor_digest": canonical_digest(anchor),
            "history_anchor_key_sha256": hashlib.sha256(HISTORY_KEY).hexdigest(),
        },
    )
    original_write = release_skill._write_json

    def fail_claim_write(path: Path, value: object) -> None:
        if path.name == "release-claim.json":
            raise OSError("injected claim receipt failure")
        original_write(path, value)

    monkeypatch.setattr(release_skill, "_write_json", fail_claim_write)
    args = SimpleNamespace(
        output=str(output),
        review=str(review),
        run_state=str(state),
        history_anchor_key=str(key),
    )

    with pytest.raises(OSError, match="injected"):
        release_skill._claim(args)

    assert not (output / "release-claim.json").exists()
    records = replay_release_history(
        output / "release-history.jsonl",
        anchor_key=HISTORY_KEY,
        expected_key_sha256=hashlib.sha256(HISTORY_KEY).hexdigest(),
    )
    assert [record["event"] for record in records] == ["CLAIM_INTENT"]
    assert records[0]["status"] == "PREPARED"
    assert all(record["status"] != "RELEASE_READY" for record in records)


def test_cli_blocked_output_file_is_structured_json_without_traceback(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{", encoding="utf-8")
    output = tmp_path / "output-is-file"
    output.write_text("not-a-directory", encoding="utf-8")
    evaluator = tmp_path / "evaluator.py"
    evaluator.write_text("pass\n", encoding="utf-8")
    command = [
        sys.executable,
        "-B",
        str(ROOT / "scripts" / "release_skill.py"),
        "review",
        "--manifest",
        str(manifest),
        "--source",
        str(source),
        "--verification",
        str(tmp_path / "verification.json"),
        "--ledger",
        str(tmp_path / "ledger.json"),
        "--review-evidence",
        str(tmp_path / "evidence.json"),
        "--attestation",
        str(tmp_path / "attestation.json"),
        "--signature",
        str(tmp_path / "signature.bin"),
        "--public-key",
        str(tmp_path / "reviewer.pub"),
        "--issuer",
        "issuer",
        "--trust-root",
        "sha256:" + "a" * 64,
        "--trust-registry",
        str(tmp_path / "trust.json"),
        "--trust-registry-digest",
        "0" * 64,
        "--run-state",
        str(output / "run-state.json"),
        "--evaluator-artifact",
        str(evaluator),
        "--producer",
        "producer",
        "--reviewer",
        "reviewer",
        "--output",
        str(output),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)

    assert completed.returncode == 2
    receipt = json.loads(completed.stdout)
    assert receipt["status"] == "BLOCKED_VERIFICATION"
    assert receipt["failure_code"] == "EVIDENCE_PARSE"
    assert "Traceback" not in completed.stderr


def test_validate_trust_anchor_binds_every_release_authority() -> None:
    anchor = {
        "schema_version": 1,
        "policy_id": "incomplete",
        "reviewers": [],
    }
    with pytest.raises(ReviewBlocked, match="trust anchor"):
        review_module.validate_trust_anchor(anchor)


@pytest.mark.skipif(os.name != "nt", reason="real Windows venv closure test")
def test_real_sigstore_launcher_runs_from_complete_private_venv_snapshot(
    tmp_path: Path,
) -> None:
    material, _ = _real_verifier_material(tmp_path)
    commands: list[list[str]] = []

    def real_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.run(command, capture_output=True, text=True, check=False)

    with pytest.raises(ReviewBlocked, match="Sigstore verification failed with rc="):
        verify_sigstore_attestation(
            attestation_path=material["attestation"],
            bundle_path=material["bundle"],
            verifier_executable=material["launcher"],
            cert_identity=material["identity"],
            oidc_issuer=material["issuer"],
            trust_registry=material["registry"],
            trust_registry_digest=material["registry_digest"],
            trust_anchor=material["trust_anchor"],
            trust_config_path=material["trust_config"],
            snapshot_root=tmp_path / "snapshot",
            runner=real_runner,
        )

    assert len(commands) == 2
    private_launcher = Path(commands[0][0])
    assert private_launcher.is_relative_to(tmp_path / "snapshot")
    assert private_launcher.name == "sigstore.exe"
    assert str(material["venv"]).lower() not in commands[0][0].lower()
    private_venv = private_launcher.parent.parent
    private_config = (private_venv / "pyvenv.cfg").read_text(encoding="utf-8")
    assert str(private_venv / "runtime") in private_config
    assert str(private_venv / "runtime" / "python.exe") in private_config
    assert str(material["venv"]) not in private_config
    assert str(material["runtime"]) not in private_config


@pytest.mark.skipif(os.name != "nt", reason="real Windows venv closure test")
def test_real_venv_closure_substitution_blocks_before_execution(
    tmp_path: Path,
) -> None:
    material, _ = _real_verifier_material(tmp_path)
    closure = material["closure"]
    reviewer = material["registry"]["reviewers"][0]
    targets = {
        "launcher": lambda item: item["role"] == "verifier",
        "python-runtime": lambda item: item["relative_path"] == "runtime/python.exe",
        "python-dll": lambda item: item["relative_path"] == "runtime/python312.dll",
        "package-file": lambda item: str(item["relative_path"]).startswith(
            "Lib/site-packages/sigstore/"
        ),
    }

    for name, predicate in targets.items():
        selected = next(item for item in closure if predicate(item))
        original_index = closure.index(selected)
        closure[original_index] = {
            **selected,
            "sha256": "0" * 64,
        }
        closure.insert(0, closure.pop(original_index))
        reviewer["verifier_closure"] = closure
        material["registry_digest"] = canonical_digest(material["registry"])
        material["trust_anchor"]["reviewer_registry_digest"] = material[
            "registry_digest"
        ]
        calls: list[list[str]] = []

        def forbidden_runner(
            command: list[str],
            _name: str = name,
            _calls: list[list[str]] = calls,
        ) -> subprocess.CompletedProcess[str]:
            _calls.append(command)
            raise AssertionError(f"runner executed for {_name}: {command}")

        with pytest.raises(ReviewBlocked, match="execution closure mismatch"):
            verify_sigstore_attestation(
                attestation_path=material["attestation"],
                bundle_path=material["bundle"],
                verifier_executable=material["launcher"],
                cert_identity=material["identity"],
                oidc_issuer=material["issuer"],
                trust_registry=material["registry"],
                trust_registry_digest=material["registry_digest"],
                trust_anchor=material["trust_anchor"],
                trust_config_path=material["trust_config"],
                snapshot_root=tmp_path / f"snapshot-{name}",
                runner=forbidden_runner,
            )
        assert calls == []


@pytest.mark.skipif(os.name != "nt", reason="real Windows venv closure test")
def test_missing_real_venv_runtime_blocks_before_execution(
    tmp_path: Path,
) -> None:
    material, _ = _real_verifier_material(tmp_path)
    closure = [
        item
        for item in material["closure"]
        if item["relative_path"] != "runtime/python.exe"
    ]
    reviewer = material["registry"]["reviewers"][0]
    reviewer["verifier_closure"] = closure
    material["registry_digest"] = canonical_digest(material["registry"])
    material["trust_anchor"]["reviewer_registry_digest"] = material[
        "registry_digest"
    ]
    calls: list[list[str]] = []

    def forbidden_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        raise AssertionError(f"runner executed: {command}")

    with pytest.raises(ReviewBlocked, match="runtime closure is incomplete"):
        verify_sigstore_attestation(
            attestation_path=material["attestation"],
            bundle_path=material["bundle"],
            verifier_executable=material["launcher"],
            cert_identity=material["identity"],
            oidc_issuer=material["issuer"],
            trust_registry=material["registry"],
            trust_registry_digest=material["registry_digest"],
            trust_anchor=material["trust_anchor"],
            trust_config_path=material["trust_config"],
            snapshot_root=tmp_path / "snapshot",
            runner=forbidden_runner,
        )
    assert calls == []
