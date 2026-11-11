from __future__ import annotations

from typing import Any

SCOPE_ID = "fir-full-r15-sigstore-fixture-20261111"
RUN_ID = f"{SCOPE_ID}-r1"
CANDIDATE_DIGEST = (
    "1fd66cdf76cc4477250ad53faf6e3363de0ef2122729a191d4714ba5ccfb2d35"
)
TARGET_DIGEST = (
    "132f4927a9ae633a39811a1846227cb20d7b2226adfe66fda47f2181bf386240"
)
FIXTURE_SAN = (
    "https://github.com/limingkun626/docker_image_pusher/.github/workflows/"
    "sign.yml@refs/heads/codex-fir-r7-sign-20261110"
)
WRONG_FIXTURE_SAN = (
    "https://github.com/limingkun626/docker_image_pusher/.github/workflows/"
    "codex-fir-r13-sign-20261111.yml@refs/heads/codex-fir-r13-sign-20261111"
)
ISSUER = "https://token.actions.githubusercontent.com"
MACOS_BRANCH = "codex-fir-r15-macos-20261111"
MACOS_WORKFLOW = ".github/workflows/codex-fir-r15-macos-20261111.yml"
MACOS_ARTIFACT = "fir-r15-macos-evidence"
SIGN_BRANCH = "codex-fir-r14-sign-20261111"
SIGN_WORKFLOW = ".github/workflows/codex-fir-r14-sign-20261111.yml"
SIGN_IDENTITY = (
    "https://github.com/limingkun626/docker_image_pusher/.github/workflows/"
    "codex-fir-r14-sign-20261111.yml@refs/heads/codex-fir-r14-sign-20261111"
)


def require_scope(record: dict[str, Any], label: str) -> None:
    if record.get("scope_id") != SCOPE_ID or record.get("run_id") != RUN_ID:
        raise ValueError(f"{label} is not R15 evidence")
    if record.get("candidate_digest") not in (None, CANDIDATE_DIGEST):
        raise ValueError(f"{label} binds a foreign candidate")
