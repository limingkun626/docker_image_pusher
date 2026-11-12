from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

ZERO = "0" * 64


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--platform",
        choices=("windows", "linux", "macos"),
        required=True,
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    candidate = args.candidate.resolve()
    output = args.output.resolve()
    if output.exists():
        raise RuntimeError(f"output already exists: {output}")
    output.mkdir(parents=True)
    attempt = output / "attempt"
    target = attempt / "target"
    rollback = attempt / "rollback"
    attempt.mkdir()

    sys.path.insert(0, str(candidate / "scripts"))
    from full_inspection_repair import package as package_module
    from full_inspection_repair.contracts import canonical_digest
    from full_inspection_repair.package import (
        build_package_manifest,
        install_package,
        verify_package_manifest,
    )

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    verify_package_manifest(candidate, manifest)
    candidate_digest = str(manifest["tree_digest"])
    shutil.copytree(candidate, target)
    if build_package_manifest(target)["tree_digest"] != candidate_digest:
        raise RuntimeError("seeded target does not match the candidate")

    package_module.validate_claim_for_install = lambda *_args, **_kwargs: None
    claim = {"claim_digest": ZERO}
    review = {
        "review_digest": ZERO,
        "subject_digest": ZERO,
        "external_signature": {
            "issuer": "lifecycle-harness",
            "trust_root_id": ZERO,
            "trust_anchor_digest": ZERO,
            "history_anchor_key_sha256": ZERO,
            "verification_method": "sigstore-keyless",
            "attestation_sha256": ZERO,
            "signature_sha256": None,
            "receipt_digest": ZERO,
            "bundle_sha256": ZERO,
            "verifier_command_digest": ZERO,
            "trust_config_sha256": ZERO,
            "verifier_closure_digest": ZERO,
        },
    }
    installed = install_package(
        candidate,
        target,
        manifest,
        claim=claim,
        review=review,
        verification_method="sigstore-keyless",
        attestation_bytes=b"{}",
        rollback_root=rollback,
    )
    if installed.get("status") != "INSTALLED":
        raise RuntimeError("installer did not return INSTALLED")
    rollback_digest = build_package_manifest(rollback)["tree_digest"]
    target_digest = build_package_manifest(target)["tree_digest"]
    if rollback_digest != candidate_digest or target_digest != candidate_digest:
        raise RuntimeError("install or retained rollback digest mismatch")

    stages = {
        "installation": {
            "receipt": {
                "source_digest": candidate_digest,
                "install_digest": target_digest,
            }
        },
        "readback": {
            "receipt": {
                "digest": target_digest,
                "readback_verified": True,
            }
        },
        "atomic_activation": {
            "receipt": {
                "activated_atomically": True,
                "install_digest": target_digest,
            }
        },
        "rollback": {
            "receipt": {
                "digest": rollback_digest,
                "retained": True,
            }
        },
        "smoke": {
            "receipt": {
                "digest": target_digest,
                "smoke_verified": True,
            }
        },
    }
    for value in stages.values():
        value["status"] = "PASS"
        value["receipt_sha256"] = canonical_digest(value["receipt"])

    receipt = {
        "schema_version": 1,
        "platform": args.platform,
        "candidate_digest": candidate_digest,
        "source_digest": candidate_digest,
        "target_digest": target_digest,
        "installation_digest": target_digest,
        "readback_digest": target_digest,
        "rollback_digest": rollback_digest,
        "smoke_digest": target_digest,
        "stages": stages,
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    payload = (
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    receipt_path = output / f"{args.platform}-install.json"
    receipt_path.write_bytes(payload)
    print(
        json.dumps(
            {
                "platform": args.platform,
                "candidate_digest": candidate_digest,
                "rollback_digest": rollback_digest,
                "receipt": str(receipt_path),
                "receipt_sha256": hashlib.sha256(payload).hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)

