from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from r16_identity import (
    CANDIDATE_DIGEST,
    FIXTURE_ARTIFACT,
    FIXTURE_ARTIFACT_SHA256,
    FIXTURE_BUNDLE,
    FIXTURE_BUNDLE_SHA256,
    FIXTURE_SAN,
    ISSUER,
    WRONG_ARTIFACT,
    WRONG_ARTIFACT_SHA256,
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bundle_digest(path: Path) -> str:
    value = json.loads(path.read_text(encoding="utf-8"))
    digest = value["messageSignature"]["messageDigest"]
    if digest["algorithm"] != "SHA2_256":
        raise RuntimeError("fixture bundle digest algorithm is not SHA2_256")
    raw = base64.b64decode(digest["digest"], validate=True)
    if len(raw) != 32:
        raise RuntimeError("fixture bundle digest is not 32 bytes")
    return raw.hex()


def workflow_errors(text: str) -> list[str]:
    errors: list[str] = []
    required = {
        "bundle": f"FIR_R8_SIGSTORE_BUNDLE: ${{{{ github.workspace }}}}/{FIXTURE_BUNDLE}",
        "artifact": f"FIR_R8_SIGSTORE_ARTIFACT: ${{{{ github.workspace }}}}/{FIXTURE_ARTIFACT}",
        "negative": f"--wrong-artifact {WRONG_ARTIFACT}",
        "identity": FIXTURE_SAN,
        "issuer": ISSUER,
    }
    for label, expected in required.items():
        if expected not in text:
            errors.append(f"workflow {label} binding is missing")
    for key in ("FIR_R8_SIGSTORE_BUNDLE", "FIR_R8_SIGSTORE_ARTIFACT"):
        lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip().startswith(key + ":")
        ]
        if len(lines) != 1 or "/fir-r16/sigstore/" not in lines[0]:
            errors.append(f"workflow {key} does not select the R16 R7 pair")
    return errors


def run_verifier(verifier: Path, bundle: Path, artifact: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(verifier),
            "verify",
            "identity",
            "--offline",
            "--bundle",
            str(bundle),
            "--cert-identity",
            FIXTURE_SAN,
            "--cert-oidc-issuer",
            ISSUER,
            str(artifact),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--workflow", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--wrong-artifact", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.output.exists():
        raise RuntimeError(f"output already exists: {args.output}")
    sys.path.insert(0, str(args.candidate.resolve() / "scripts"))
    from full_inspection_repair.package import build_package_manifest

    before = build_package_manifest(args.candidate.resolve())["tree_digest"]
    identity_errors = workflow_errors(args.workflow.read_text(encoding="utf-8"))
    bundle_sha256 = sha256(args.bundle)
    artifact_sha256 = sha256(args.artifact)
    signed_digest = bundle_digest(args.bundle)
    wrong_sha256 = sha256(args.wrong_artifact)
    positive = run_verifier(args.verifier, args.bundle, args.artifact)
    negative = run_verifier(args.verifier, args.bundle, args.wrong_artifact)
    after = build_package_manifest(args.candidate.resolve())["tree_digest"]
    negative_text = (negative.stdout + "\n" + negative.stderr).casefold()
    checks = {
        "workflow": not identity_errors,
        "bundle_digest": bundle_sha256 == FIXTURE_BUNDLE_SHA256,
        "artifact_digest": artifact_sha256 == FIXTURE_ARTIFACT_SHA256,
        "pair_digest": signed_digest == artifact_sha256,
        "wrong_digest": wrong_sha256 == WRONG_ARTIFACT_SHA256,
        "positive": positive.returncode == 0,
        "negative": (
            negative.returncode != 0
            and "bundle message digest mismatch" in negative_text
        ),
        "candidate_unchanged": before == after == CANDIDATE_DIGEST,
    }
    result = {
        "schema_version": 1,
        "status": "PASS" if all(checks.values()) else "BLOCKED",
        "checks": checks,
        "workflow_errors": identity_errors,
        "candidate_digest": before,
        "candidate_digest_after": after,
        "bundle_sha256": bundle_sha256,
        "bundle_message_digest": signed_digest,
        "artifact_sha256": artifact_sha256,
        "wrong_artifact_sha256": wrong_sha256,
        "positive_exit_code": positive.returncode,
        "negative_exit_code": negative.returncode,
        "negative_stderr": negative.stderr,
    }
    write_json(args.output / "mutation-result.json", result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)
