from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.release import (
    ReleaseBlocked,
    release_id_for,
    validate_release_lifecycle,
)
from full_inspection_repair.review import (
    ReviewBlocked,
    reviewer_identity_domain_id,
    sigstore_trust_root_id,
    validate_client_trust_config,
    validate_trust_anchor,
)
from full_inspection_repair.state_machine import advance
import release_skill


IDENTITY = (
    "https://github.com/limingkun626/docker_image_pusher/.github/workflows/"
    "codex-fir-r19-sign-20261111.yml@refs/heads/codex-fir-r19-sign-20261111"
)
ISSUER = "https://token.actions.githubusercontent.com"
OLD_ID = (
    "sigstore:6f708a5704bac698ca1de47bcec52e4d1"
    "bbc42b38e91171bca126d5a94255797"
)
EXPECTED_ID = (
    "sigstore:abaa28e5742590a89203105e5507525"
    "48daad953299b3bc66656bca0d1dd775c"
)


def _trust_config(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "mediaType": "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json",
        "trustedRoot": {
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [{"baseUrl": "https://rekor.invalid"}],
            "certificateAuthorities": [{"uri": "https://fulcio.invalid"}],
        },
        "signingConfig": {
            "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
            "caUrls": [{"url": "https://fulcio.invalid", "majorApiVersion": 1}],
            "rekorTlogUrls": [
                {"url": "https://rekor.invalid", "majorApiVersion": 1}
            ],
        },
    }
    value.update(overrides)
    return value


def test_reviewer_identity_domain_is_derived_not_copied() -> None:
    assert reviewer_identity_domain_id(IDENTITY, ISSUER) == EXPECTED_ID
    assert sigstore_trust_root_id(IDENTITY, ISSUER) == EXPECTED_ID


def test_trust_anchor_rejects_stale_identity_domain_id() -> None:
    reviewer = {
        "reviewer": IDENTITY,
        "issuer": ISSUER,
        "verification_method": "sigstore-keyless",
        "trust_root_id": OLD_ID,
        "reviewer_identity_domain_id": OLD_ID,
        "verifier_closure": [
            {"path": "sigstore", "sha256": "a" * 64, "role": "verifier"}
        ],
        "status": "ACTIVE",
    }
    registry = {"schema_version": 1, "reviewers": [reviewer]}
    with pytest.raises(ReviewBlocked, match="identity-domain"):
        validate_trust_anchor(
            {
                "schema_version": 1,
                "policy_id": "r22-test",
                "reviewers": [reviewer],
                "reviewer_registry_digest": canonical_digest(registry),
                "evaluator_artifacts": [],
                "history_anchor_key_sha256": [],
                "sigstore_trust_config_sha256": [],
            }
        )


def test_raw_trusted_root_is_not_a_client_trust_config() -> None:
    raw_root = {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [{"baseUrl": "https://rekor.invalid"}],
        "certificateAuthorities": [{"uri": "https://fulcio.invalid"}],
    }
    with pytest.raises(ReviewBlocked, match="ClientTrustConfig"):
        validate_client_trust_config(json.dumps(raw_root).encode("utf-8"))


@pytest.mark.parametrize("missing", ["trustedRoot", "signingConfig"])
def test_client_trust_config_requires_both_nested_components(missing: str) -> None:
    value = _trust_config()
    value.pop(missing)
    with pytest.raises(ReviewBlocked, match="missing"):
        validate_client_trust_config(json.dumps(value).encode("utf-8"))


def test_client_trust_config_accepts_official_envelope() -> None:
    parsed = validate_client_trust_config(json.dumps(_trust_config()).encode("utf-8"))
    assert parsed["mediaType"].endswith("clienttrustconfig.v0.1+json")


def _record(event: str, release_id: str, scope: str, candidate: str) -> dict[str, object]:
    return {
        "sequence": len(event),
        "event": event,
        "status": "TEST",
        "release_id": release_id,
        "scope_id": scope,
        "candidate_digest": candidate,
        "record_digest": event.lower(),
        "previous_record_digest": None,
    }


def test_release_lifecycle_selects_only_the_requested_release() -> None:
    scope = "r22-scope"
    candidate = "a" * 64
    release_id = release_id_for(scope, candidate)
    other_id = release_id_for("other-scope", "b" * 64)
    events = [
        "FREEZE",
        "FINAL_REVIEW",
        "CLAIM_INTENT",
        "CLAIM_COMMIT",
        "INSTALL",
        "POST_INSTALL_REPLAY",
    ]
    records = [
        _record("FREEZE", other_id, "other-scope", "b" * 64),
        *[_record(event, release_id, scope, candidate) for event in events],
        _record("POST_INSTALL_REPLAY", other_id, "other-scope", "b" * 64),
    ]
    selected = validate_release_lifecycle(
        records,
        release_id=release_id,
        scope_id=scope,
        candidate_digest=candidate,
        required_through="POST_INSTALL_REPLAY",
    )
    assert [record["event"] for record in selected] == events


def test_release_lifecycle_rejects_claim_before_final_review() -> None:
    scope = "r22-scope"
    candidate = "a" * 64
    release_id = release_id_for(scope, candidate)
    records = [
        _record("FREEZE", release_id, scope, candidate),
        _record("CLAIM_COMMIT", release_id, scope, candidate),
    ]
    with pytest.raises(ReleaseBlocked, match="not reached"):
        validate_release_lifecycle(
            records,
            release_id=release_id,
            scope_id=scope,
            candidate_digest=candidate,
            required_through="CLAIM_COMMIT",
        )


def test_release_state_machine_requires_post_install_replay() -> None:
    assert advance("FULL_VERIFICATION", "final_review") == "INDEPENDENT_REVIEW"
    assert advance("INDEPENDENT_REVIEW", "claim") == "RELEASE_CLAIMED"
    assert advance("RELEASE_CLAIMED", "install") == "INSTALLED"
    assert (
        advance("INSTALLED", "post_install")
        == "CLOSED_FOR_DECLARED_UNIVERSE"
    )


@pytest.mark.parametrize("review_kind", [None, "CANDIDATE_REVIEW"])
def test_claim_requires_an_explicit_final_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    review_kind: str | None,
) -> None:
    review = {"schema_version": 2, "scope_id": "r22-claim-test"}
    if review_kind is not None:
        review["review_kind"] = review_kind
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(review), encoding="utf-8")
    monkeypatch.setattr(release_skill, "_load_release_trust_anchor", lambda: {})
    monkeypatch.setattr(
        release_skill,
        "_verification_material",
        lambda args, **kwargs: {},
    )
    monkeypatch.setattr(
        release_skill,
        "_history_anchor_key",
        lambda *args, **kwargs: b"k" * 32,
    )
    args = SimpleNamespace(
        output=str(tmp_path),
        review=str(review_path),
        run_state=str(tmp_path / "state.json"),
        history_anchor_key=str(tmp_path / "history.key"),
    )

    with pytest.raises(ReleaseBlocked, match="final review"):
        release_skill._claim(args)
