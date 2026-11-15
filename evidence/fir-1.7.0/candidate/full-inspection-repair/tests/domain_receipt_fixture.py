from __future__ import annotations

from full_inspection_repair.contracts import canonical_digest

TRUST_POLICY_DIGEST = "9" * 64
INSTALLER_DIGEST = "8" * 64
ENVIRONMENT_DIGEST = "7" * 64


def domain_entry(
    domain: str,
    *,
    scope_digest: str,
    candidate_digest: str,
    trust_policy_digest: str = TRUST_POLICY_DIGEST,
    installer_digest: str = INSTALLER_DIGEST,
    environment_digest: str = ENVIRONMENT_DIGEST,
) -> dict[str, object]:
    raw: dict[str, object] = {
        "domain": domain,
        "exit_code": 0,
    }
    if domain.startswith("platform_support."):
        platform = domain.rsplit(".", 1)[1].removesuffix("_install")
        raw.update(
            {
                "platform": platform,
                "readback_digest": candidate_digest,
                "rollback_digest": canonical_digest({"rollback": domain}),
                "smoke_exit_code": 0,
            }
        )
    elif domain == "durability.physical_power_loss":
        raw.update(
            {
                "power_loss_observed": True,
                "mid_swap": True,
                "boot_id_before": "boot-before",
                "boot_id_after": "boot-after",
                "recovered_tree_digest": candidate_digest,
            }
        )
    elif domain.startswith("lifecycle."):
        raw.update(
            {
                "installer_digest": installer_digest,
                "target_digest": candidate_digest,
                "readback_digest": candidate_digest,
                "smoke_exit_code": 0,
            }
        )
    elif domain.startswith("evaluator."):
        raw.update(
            {
                "case_count": 8,
                "failed_count": 0,
                "raw_result_sha256": canonical_digest({"domain": domain}),
            }
        )
    elif domain.startswith("trust."):
        raw.update(
            {
                "verifier_output_sha256": canonical_digest({"domain": domain}),
                "trust_root_digest": canonical_digest({"trust": domain}),
            }
        )
    else:
        raw.update(
            {
                "stage_digest": canonical_digest({"stage": domain}),
                "readback_digest": candidate_digest,
            }
        )
    command = ["domain-runner", domain]
    receipt: dict[str, object] = {
        "schema_version": 1,
        "kind": "domain-receipt",
        "domain": domain,
        "status": "VERIFIED",
        "trust_policy_digest": trust_policy_digest,
        "signer": {
            "id": "domain-signer",
            "verification_method": "external-attestation",
        },
        "runner": {
            "id": "domain-runner",
            "version": "1.0.0",
            "runner_sha256": canonical_digest({"runner": "domain-runner"}),
        },
        "scope_digest": scope_digest,
        "candidate_digest": candidate_digest,
        "installer_digest": installer_digest,
        "environment_digest": environment_digest,
        "command": command,
        "command_digest": canonical_digest(command),
        "started_at": "2026-11-10T00:00:00Z",
        "finished_at": "2026-11-10T00:01:00Z",
        "raw_evidence": raw,
        "raw_evidence_digest": canonical_digest(raw),
        "signature_receipt_digest": canonical_digest(
            {"domain": domain, "signature": "verified"}
        ),
        "verifier_digest": canonical_digest({"verifier": "domain"}),
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return {
        "status": "VERIFIED",
        "receipt": receipt,
        "receipt_sha256": receipt["receipt_digest"],
    }


def signed_domain_set(
    domains: dict[str, dict[str, object]],
    *,
    scope_digest: str,
    candidate_digest: str,
) -> dict[str, object]:
    import copy

    normalized = copy.deepcopy(domains)
    for group in normalized.values():
        for entry in group.values():
            entry.pop("receipt_sha256", None)
            entry["receipt"].pop("receipt_digest", None)
            entry["receipt"].pop("signature_receipt_digest", None)
    signature: dict[str, object] = {
        "schema_version": 1,
        "status": "VERIFIED",
        "verification_method": "sigstore-keyless",
        "reviewer": "reviewer",
        "issuer": "issuer",
        "trust_root_id": "trust-root",
        "subject_digest": canonical_digest(normalized),
        "candidate_digest": candidate_digest,
        "scope_digest": scope_digest,
        "bundle_sha256": canonical_digest({"bundle": "domain-set"}),
        "verifier_sha256": canonical_digest({"verifier": "domain-set"}),
        "verifier_closure_digest": canonical_digest(
            {"closure": "domain-set"}
        ),
        "verifier_exit_code": 0,
    }
    signature["receipt_digest"] = canonical_digest(signature)
    for group in domains.values():
        for entry in group.values():
            receipt = entry["receipt"]
            receipt["signature_receipt_digest"] = signature["receipt_digest"]
            receipt["receipt_digest"] = canonical_digest(
                {
                    key: value
                    for key, value in receipt.items()
                    if key != "receipt_digest"
                }
            )
            entry["receipt_sha256"] = receipt["receipt_digest"]
    return signature
