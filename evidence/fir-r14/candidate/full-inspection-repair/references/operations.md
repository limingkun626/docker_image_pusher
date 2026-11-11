# Operations

Skill package version: `1.4.2`.

Run from the skill root with Python 3.12 or newer. Install the exact runtime
dependencies first:

```powershell
python -m pip install -r requirements.txt
```

`requirements.txt` pins `jsonschema`, `PyYAML`, `pytest`, and `cryptography`.
The inspection runtime checks the first three before taxonomy qualification;
the retained Ed25519 fallback uses `cryptography`. The default final release
path also requires a fixed-path external Sigstore verifier executable.

```powershell
$inspectionRoot = 'C:\inspection'
$targetSkill = 'F:\Codex\my-skill'
$candidateSkill = 'F:\Codex\my-skill-candidate'
```

## Build taxonomy

```powershell
python scripts\run_inspection.py build-taxonomy `
  --kind SKILL `
  --output $inspectionRoot\taxonomy-coverage.json
```

The default policy emits the complete 9-category by 8-plane matrix. Ten cells
have executable, distinct detector and oracle bindings; the remaining 62 are
covered only by digest-bound `NOT_APPLICABLE_WITH_PROOF` policy exclusions. A
check runs ten qualification controls per cell, for 720 controls total, and
writes `taxonomy-qualification.json`; incomplete or failed qualification
produces `BLOCKED_TAXONOMY`. The controls qualify evidence plumbing, not 72
independent semantic vulnerability analyzers. Generated evidence IDs do not
create synthetic detector coverage.

The released executable adapter accepts `SKILL` targets only. `PLAN`, `ARTICLE`,
`PROJECT`, and `OTHER` remain taxonomy vocabulary until target-specific adapter
coverage is implemented and independently verified.

## Check

```powershell
python scripts\run_inspection.py check `
  --target $targetSkill `
  --kind SKILL `
  --output $inspectionRoot\check
```

`check` is read-only with respect to the target. It writes the subject manifest,
required sources, detection evidence, impact graph, risk ledger, taxonomy
coverage and qualification, character coverage, write-ahead journal, append-only
observations, observation-journal manifest, run state, and `summary.json`.

The census includes every file, including runtime caches such as `__pycache__`,
`.pytest_cache`, and `.ruff_cache`. Text receives byte, codepoint, line, unit,
and punctuation evidence. Binary or cached content receives a raw-byte hash
projection and is not interpreted as text. Runtime cache content blocks package
creation later; it is not silently omitted from inspection.

Pass `--taxonomy $inspectionRoot\taxonomy-coverage.json` to use a frozen
taxonomy. Pass `--expected-tree-digest <sha256>` to reject a target that differs
from the frozen tree. Pass `--evaluation-evidence <json>` to add
`verification-matrix.json` to the run.

## Repair

```powershell
python scripts\run_inspection.py repair `
  --target $targetSkill `
  --kind SKILL `
  --output $inspectionRoot\repair `
  --taxonomy $inspectionRoot\taxonomy-coverage.json `
  --candidate $candidateSkill
```

`repair` applies only frozen safe operations to a new candidate tree. Manual
decisions block the complete batch before the candidate is created. The source
tree is never modified. A successful run additionally writes `repair-batch.json`,
`candidate-manifest.json`, and `final-risk-ledger.json`.

On macOS, `open_no_follow` treats `O_CREAT` without `O_EXCL` as create-or-open:
it first opens the existing final component, retries with `O_CREAT|O_EXCL` on
`ENOENT`, and retries the non-creating open on `EEXIST`. Every attempt stays
relative to the same parent directory descriptor and retains
`O_NOFOLLOW|O_CLOEXEC`; other errors propagate without a pathname fallback.

## Inspection artifacts

The current stable-local inspection outputs are:

```text
run-state.json
subject-manifest.json
required-sources.jsonl
detections.json
impact-graph.json
risk-ledger.json
taxonomy-coverage.json
taxonomy-qualification.json
character-coverage.json
punctuation-ledger.jsonl
whitespace-control-ledger.jsonl
byte-ledger.jsonl
codepoint-ledger.jsonl
line-ledger.jsonl
unit-ledger.jsonl
binary-structure-ledger.jsonl
projection-ledger.jsonl
uncovered-character-ranges.json
write-ahead-journal.jsonl
write-ahead-journal-checkpoint.json
write-ahead-journal-check.json
observations.jsonl
observation-journal-manifest.json
summary.json
```

Repair adds:

```text
repair-batch.json
candidate-manifest.json
final-risk-ledger.json
```

`verification-matrix.json` is present only when evaluation evidence is supplied.
The observation journal is `observations.jsonl`; its digest-chain checkpoint is
`observation-journal-manifest.json`.

## Atomic writes and crash recovery

CLI JSON and JSONL artifacts are written to a same-directory temporary file,
flushed to disk, atomically replaced, and followed by a parent-directory flush.
A failed replace leaves the previous artifact intact and removes the temporary
file. `observations.jsonl` is append-only: each record carries a sequence,
`previous_record_digest`, and `record_digest`, and the append is flushed before
run state advances.

State-changing work uses exact `INTENT` then `COMPLETION` records in
`write-ahead-journal.jsonl`. A completion references the intent digest and the
digest of the intent evidence; the checkpoint is stored in
`write-ahead-journal-checkpoint.json`. Verification rejects sequence or hash
chain gaps, truncation, substituted intent evidence, and incomplete pairs.
Recovery starts from the authenticated checkpoint and treats any of those
conditions as `BLOCKED_EVIDENCE`.

Discovery observations must be durable before the run advances to impact
analysis. Verification observations must be durable before a failed candidate
state is recorded. Review failures are journaled before `blocked-review.json`.
The observation status is one of `CONFIRMED`, `INCONCLUSIVE`, or
`FALSE_POSITIVE`; it is never collapsed to a boolean.

## Statuses

The current CLI success receipts are:

| Status | Meaning |
|---|---|
| `CHECKED` | Complete issue collection for the frozen detector/taxonomy input; not repair-approved. |
| `REPAIRED_CANDIDATE` | A frozen safe batch produced a candidate with no retained open finding; not installed or released. |

The stable-local blocked vocabulary is:

```text
BLOCKED_SCOPE
BLOCKED_ADAPTER
BLOCKED_TAXONOMY
BLOCKED_STALE_INPUT
BLOCKED_DETECTOR
BLOCKED_EVIDENCE
BLOCKED_REPAIR_PLAN
BLOCKED_REPAIR_CONFLICT
BLOCKED_VERIFICATION
BLOCKED_INDEPENDENT_REVIEW
```

Current `check` and `repair` failure receipts use `summary.json` with one of the
applicable blocked statuses. A release command that cannot validate its inputs
writes `blocked-<command>.json` with `status=BLOCKED_VERIFICATION`, a stable
`failure_code`, and the exact failure list.

Do not hand-edit a success receipt or delete a failed observation. Start a new
explicitly authorized run instead.

## Stable-local release lifecycle

The final release chain is:

```text
package -> GitHub Actions OIDC + Sigstore bundle verification ->
review -> claim -> install
```

The source tree must be clean of runtime caches because package manifest
construction rejects cache content. `package` records the exact file set,
per-file hashes, tree digest, and manifest digest in `package-manifest.json`.

Final publication uses GitHub Actions OIDC keyless signing and a Sigstore
bundle. The workflow requesting the release must declare `id-token: write` and
must produce both the reviewer attestation and its Sigstore bundle. Signing
identity comes from the workflow certificate, not a stored private key.

Release authority is the code-frozen `policies/trust-policy.json`. The
caller-supplied reviewer registry must exactly equal the anchor's reviewer
registry, and its canonical digest must equal `reviewer_registry_digest`.
`--evaluator-artifact` supplies exact bytes whose SHA-256 must appear in the
anchor's `evaluator_artifacts`; the optional `--evaluator` value must match the
same bytes. Review fails without the exact artifact. A caller cannot mint a
reviewer, evaluator, history key, trust root, or Sigstore configuration by
supplying a matching label or digest.

The attestation must contain schema version 1, `verdict=PASS`, the producer,
reviewer, issuer, `verification_method=sigstore-keyless`, `trust_root_id`, and
the exact scope, subject, candidate, verification, ledger, evaluator, matrix,
coverage, domains, and findings digests plus `reviewed_at`. The reviewer must
exactly match the certificate identity and the issuer must exactly match the
GitHub Actions OIDC issuer.
`trust_root_id` is derived as `sigstore:<canonical-digest>` from the verification
method, certificate identity, and OIDC issuer; it is not caller-asserted.

Pass the exact certificate identity expected by the workflow and the exact
GitHub Actions OIDC issuer. The CLI invokes the fixed-path verifier as:

```text
<sigstore-verifier> verify identity --offline --bundle <bundle>
  --cert-identity <exact-cert-identity>
  --cert-oidc-issuer <exact-oidc-issuer>
  <reviewer-attestation>
```

Wildcard identities, alternate issuers, interactive browser trust, and
unverified bundle claims do not satisfy the release boundary. `review` verifies
the bundle before accepting attestation claims, checks every claim against the
assembled review subject, and embeds the resulting `status=VERIFIED` receipt as
`external_signature` in `independent-review.json`. For keyless verification the
receipt binds `bundle_sha256`, `verifier_command_digest`, verifier exit code,
attestation bytes, cert identity, OIDC issuer, and a valid `receipt_digest`.
`verifier_command_digest` binds the argv, including the executable path, not the
verifier binary bytes; the release runner image/toolchain digest must be frozen
separately as environment evidence.

`--sigstore-trust-config` is required for `sigstore-keyless`. Its SHA-256 must
be listed in the anchor's `sigstore_trust_config_sha256`. Verification copies the
attestation, bundle, trust configuration, verifier, and every declared closure
file into a private snapshot, rewrites a copied virtual-environment configuration
to that snapshot, requires the registered verifier version, and rejects
incomplete runtime/helper closure or script-wrapper closure before execution.
The verified receipt binds `trust_config_sha256` and
`verifier_closure_digest`. Mock signatures and simulated verification receipts
are not accepted.

Set the release paths before running the lifecycle:

```powershell
$releaseRoot = 'C:\release'
$sourceSkill = 'F:\Codex\my-skill'
$targetSkill = 'C:\Users\Administrator\.codex\skills\my-skill'
$attestation = 'C:\release\reviewer-attestation.json'
$sigstoreBundle = 'C:\release\reviewer-attestation.sigstore.json'
$sigstoreVerifier = 'C:\tools\sigstore-verifier.exe'
$sigstoreTrustConfig = 'C:\release\sigstore-trust-config.json'
$certIdentity = 'https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/heads/main'
$oidcIssuer = 'https://token.actions.githubusercontent.com'
$trustRegistry = 'C:\release\trust-registry.json'
$trustRegistryDigest = 'replace-with-64-lowercase-hex'
$runState = 'C:\release\run-state.json'
$historyAnchorKey = 'C:\secure\release-history.key'
$evaluatorArtifact = 'C:\release\evaluator.json'
$evaluator = 'independent-evaluator-digest'
$producer = 'codex-primary'
$rollbackRoot = 'C:\Users\Administrator\.codex\skills\.my-skill.rollback'
```

Create the manifest:

```powershell
python scripts\release_skill.py package `
  --source $sourceSkill `
  --output $releaseRoot
```

Issue the digest-bound review:

```powershell
python scripts\release_skill.py review `
  --manifest $releaseRoot\package-manifest.json `
  --source $sourceSkill `
  --verification $releaseRoot\verification.json `
  --ledger $releaseRoot\risk-ledger.json `
  --review-evidence $releaseRoot\risk-gate-evidence.json `
  --attestation $attestation `
  --verification-method sigstore-keyless `
  --sigstore-bundle $sigstoreBundle `
  --sigstore-verifier $sigstoreVerifier `
  --sigstore-trust-config $sigstoreTrustConfig `
  --cert-identity $certIdentity `
  --oidc-issuer $oidcIssuer `
  --trust-registry $trustRegistry `
  --trust-registry-digest $trustRegistryDigest `
  --run-state $runState `
  --evaluator-artifact $evaluatorArtifact `
  --evaluator $evaluator `
  --producer $producer `
  --reviewer $certIdentity `
  --output $releaseRoot
```

`review` verifies the package, PASS verification, zero-open ledger, strict risk
gate, producer/reviewer separation, Sigstore bundle, exact cert identity and
OIDC issuer, and attestation claims. `sigstore-keyless` is the parser default,
but the explicit selector keeps the release contract visible. It writes
`review-packet.json` and `independent-review.json`. The risk-gate evidence must
use the same finding IDs as the ledger and must contain no limitations,
unverified claims, not-run items, non-blocking observations, residual risk,
incomplete coverage, or failed verification domain.

Issue the release claim:

```powershell
python scripts\release_skill.py claim `
  --review $releaseRoot\independent-review.json `
  --attestation $attestation `
  --verification-method sigstore-keyless `
  --sigstore-bundle $sigstoreBundle `
  --sigstore-verifier $sigstoreVerifier `
  --sigstore-trust-config $sigstoreTrustConfig `
  --cert-identity $certIdentity `
  --oidc-issuer $oidcIssuer `
  --trust-registry $trustRegistry `
  --trust-registry-digest $trustRegistryDigest `
  --run-state $runState `
  --output $releaseRoot `
  --history-anchor-key $historyAnchorKey
```

`claim` reverifies the same Sigstore bundle for the exact cert identity and OIDC
issuer, rechecks the review receipt, and appends `CLAIM_INTENT` with status
`PREPARED`. It then atomically writes `release-claim.json` with
`status=RELEASE_READY` and `state=CLOSED_FOR_DECLARED_UNIVERSE`, followed by a
matching `CLAIM_COMMIT` record. A lone intent is not a completed claim. For
keyless claims the claim also binds `bundle_sha256`,
`trust_config_sha256`, `verifier_closure_digest`, and
`verifier_command_digest`. If commit fails after the claim receipt is written,
the receipt is removed and a `CLAIM_ABORT` record is appended when possible.

Install only after explicit authorization:

```powershell
python scripts\release_skill.py install `
  --source $sourceSkill `
  --target $targetSkill `
  --manifest $releaseRoot\package-manifest.json `
  --claim $releaseRoot\release-claim.json `
  --review $releaseRoot\independent-review.json `
  --attestation $attestation `
  --verification-method sigstore-keyless `
  --sigstore-bundle $sigstoreBundle `
  --sigstore-verifier $sigstoreVerifier `
  --sigstore-trust-config $sigstoreTrustConfig `
  --cert-identity $certIdentity `
  --oidc-issuer $oidcIssuer `
  --trust-registry $trustRegistry `
  --trust-registry-digest $trustRegistryDigest `
  --run-state $runState `
  --output $releaseRoot `
  --rollback $rollbackRoot `
  --history-anchor-key $historyAnchorKey
```

Installation rechecks the current claim, review, attestation, Sigstore bundle,
exact cert identity and OIDC issuer, fixed-path verifier command, manifest, path
topology, and source tree. It requires source, target parent, and rollback root
to share one volume and rejects symbolic-link/reparse-point chains. An existing
target is moved to the rollback tree before activation. The installer verifies
the staged tree, flush-syncs every staged file and directory bottom-up, and
flush-syncs the moved tree plus both parent directories before and after each
directory rename. It then verifies read-back and
`SKILL.md`, then writes `install-receipt.json` with `status=INSTALLED`. The
receipt preserves the bundle digest and verifier-command digest used by the
claim.

If staging, activation, read-back, or smoke verification fails after activation,
the old target is restored and `blocked-install.json` is written. A successful
replacement retains the previous target at `--rollback`; the current CLI has no
automatic rollback command. Any later manual rollback is a separate destructive
operation and requires explicit authorization plus digest verification.

### Retained Ed25519 fallback

The CLI retains explicit detached Ed25519 verification for non-final local
recovery tests. It is not the final GitHub Actions publication path. The
independent reviewer signs the exact JSON attestation bytes, and the trust-root
identity is `sha256:<hex>` over the public key's DER SubjectPublicKeyInfo.

```powershell
$edAttestation = 'C:\release\reviewer-attestation.ed25519.json'
$signature = 'C:\release\reviewer-attestation.sig'
$publicKey = 'C:\release\reviewer-public-key.pem'
$edIssuer = 'external-review-service'
$edTrustRoot = 'sha256:replace-with-public-key-fingerprint'
$reviewer = 'independent-reviewer'
```

```powershell
python scripts\release_skill.py review `
  --manifest $releaseRoot\package-manifest.json `
  --source $sourceSkill `
  --verification $releaseRoot\verification.json `
  --ledger $releaseRoot\risk-ledger.json `
  --review-evidence $releaseRoot\risk-gate-evidence.json `
  --attestation $edAttestation `
  --verification-method ed25519-detached `
  --signature $signature `
  --public-key $publicKey `
  --issuer $edIssuer `
  --trust-root $edTrustRoot `
  --trust-registry $trustRegistry `
  --trust-registry-digest $trustRegistryDigest `
  --run-state $runState `
  --evaluator-artifact $evaluatorArtifact `
  --evaluator $evaluator `
  --producer $producer `
  --reviewer $reviewer `
  --output $releaseRoot
```

Pass the same method, attestation, signature, public key, issuer, trust-root,
trust-registry, and run-state arguments to `claim` and `install`; those commands
also require `--history-anchor-key`. The key file must remain outside the release
output, contain 32 to 4096 bytes, and not be reachable through a link. The Ed25519 receipt binds
`signature_sha256`, `public_key_fingerprint`, and `receipt_digest`.

## Append-only release history

`release-history.jsonl` is append-only. Each canonical JSON record carries a
1-based `sequence`, `previous_record_digest`, and `record_digest`; replay rejects
blank records, sequence gaps, chain mismatches, invalid JSON, and digest
mismatches. A separate authenticated high-water file protects against truncation
and history rewrites. Claims append `CLAIM_INTENT`, then `CLAIM_COMMIT`; failures
after commit append `CLAIM_ABORT`. Successful installs append `INSTALL`. Failed
install attempts append `INSTALL_BLOCKED`; `blocked-install.json` records the
resulting sequence and record digest.

CLI release output artifacts are:

```text
package-manifest.json
review-packet.json
independent-review.json
release-claim.json
install-receipt.json
release-history.jsonl
blocked-review.json
blocked-claim.json
blocked-install.json
```

External verification inputs are not CLI outputs:

```text
reviewer-attestation.json
reviewer-attestation.sigstore.json
sigstore-verifier executable
```

The Ed25519 fallback consumes `reviewer-attestation.ed25519.json`, a detached
signature, and a public key instead of the Sigstore bundle and verifier.

Review status is the verdict `PASS` at state `INDEPENDENT_REVIEW`; claim status
is `RELEASE_READY` at state `CLOSED_FOR_DECLARED_UNIVERSE`; install status is
`INSTALLED`; the embedded external-signature receipt status is `VERIFIED`.
Final keyless receipts use `verification_method=sigstore-keyless`; fallback
receipts use `verification_method=ed25519-detached`.

## Claim boundary

`release-claim.json` means the frozen review subject reached
`CLOSED_FOR_DECLARED_UNIVERSE` with no open risk and a current external
verification receipt. It does not mean universal certainty, installation
success beyond the verified platform receipts, or physical power-loss safety.

For the final Sigstore path, the claim is bounded by the exact cert identity,
exact OIDC issuer, attestation bytes, bundle bytes, verifier executable path,
verifier command digest, review digest, candidate tree digest, verification
digest, ledger digest, matrix digest, coverage digest, domains digest, findings
digest, and risk-gate digest. Any changed bundle, verifier, command, identity,
issuer, review subject, or candidate invalidates the claim.

`install-receipt.json` is the later statement that the exact claimed package
was staged, read back, smoke-checked, and activated. The retained rollback tree
is recovery evidence for the prior target, not proof of physical power-loss
safety.

## Verification ceiling

The required documentation checks cover Windows, WSL Linux, and macOS. A release
claim is invalid unless all three platform installation results are `PASS`.
The release gate also requires `durability.physical_power_loss=VERIFIED` with a
domain receipt bound to the current scope. Only a real physical mid-swap power
outage receipt, fresh for the final installer, can satisfy that domain;
simulated, mocked, reboot-only, or older-installer evidence cannot. Same-volume
staging, read-back, digest checks, and retained rollback trees are software
evidence only.
