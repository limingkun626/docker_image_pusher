---
name: full-inspection-repair
version: 1.4.2
description: Use for exhaustive target inspection, impact analysis, batch repair, and zero-open-risk verification; not for small single-edit fixes.
---

# Full Inspection Repair

Use this workflow when the requested outcome is one complete inspection and repair
pass, not an iterative find-fix-find loop.

## Purpose

Use this skill for whole-target defect discovery, global impact analysis,
one-batch repair, complete verification, and zero-open-risk release decisions.
The released executable adapter inspects `SKILL` targets. `PLAN`, `ARTICLE`,
`PROJECT`, and `OTHER` remain taxonomy vocabulary, not supported inspection
targets, until adapter-specific claim and lifecycle coverage is implemented.

## Required outcome

Produce:

```text
frozen scope
-> complete required-source and defect-taxonomy denominator
-> collect-all issue ledger
-> global impact graph
-> one conflict-checked repair batch
-> one isolated candidate
-> full verification matrix
-> zero-open-risk ledger
-> independent review and bounded release claim
```

Every discovered issue enters the issue ledger with its taxonomy category, root
lineage, evidence, and impact. Severity controls ordering only. Low, advisory,
non-blocking, accepted, deferred, residual, skipped, unknown, uncovered, and
inconclusive items cannot be used to bypass completion.

## Mandatory invariants

- Freeze and digest the target scope, policies, knowledge pack, detector pack,
  defect taxonomy, environment, and external dependencies before inspection.
- Census every target file, including runtime caches such as `__pycache__`,
  `.pytest_cache`, and `.ruff_cache`. Binary or opaque content is retained by
  path, size, and raw-byte hash; no census entry is silently skipped.
- Enumerate the complete denominator and run all applicable detectors in
  collect-all mode. A detector failure remains `UNCOVERED` or `BLOCKED`.
- Require every target-kind, defect-category, and evidence-plane cell to have a
  detector, independent oracle, or evidence-backed `NOT_APPLICABLE`.
- Bind detector and oracle evidence to executable taxonomy bindings. Cells
  without an executable detector use a digest-bound policy proof; generated
  detector names are not synthetic coverage.
- Base repair planning only on the complete frozen issue set. Use one conflict
  graph, one candidate tree, and one verification matrix.
- `FULL_VERIFICATION` failure ends at `BLOCKED_VERIFICATION`. There is no
  automatic return to discovery, planning, or repair.
- Input, environment, configuration, tool, or adapter drift ends at
  `BLOCKED_STALE_INPUT`. There is no automatic return to `SCOPE_FROZEN`.
- A missing taxonomy cell ends at `BLOCKED_TAXONOMY`.
- A blocked run requires a new user-authorized `scope_id` and a fresh complete
  census. Never disguise another iteration as the same run.
- Persist every check, verification, incident, and review finding to the
  append-only observation journal before advancing the risk ledger or candidate
  state. Observations use the explicit
  `CONFIRMED`/`INCONCLUSIVE`/`FALSE_POSITIVE` status vocabulary.
- Write CLI JSON and JSONL through a flushed temporary file plus atomic replace
  and directory durability. Journal state-changing work as exact `INTENT` then
  `COMPLETION` records; recover from the authenticated checkpoint and reject
  gaps, truncation, substituted intent evidence, or an incomplete pair.
- Promote knowledge only from executed mutation, historical-replay, and
  shadow-replay receipts with computed counters. Boolean flags or hashes alone
  cannot replace replay evidence.
- Load release authority from the code-frozen `policies/trust-policy.json`.
  Caller-supplied reviewer registries, evaluator digests, trust roots, or
  Sigstore configuration digests cannot mint authority.
- Never claim universal certainty. Release claims are limited to the frozen,
  verified universe.

## Workflow

1. Read [references/architecture-v9.2.1.md](references/architecture-v9.2.1.md)
   before designing, implementing, or running the workflow.
2. Read [references/operations.md](references/operations.md) for the executable
   entrypoint, required taxonomy input, output artifacts, and exit statuses.
3. Select the released `SKILL` adapter. Reject other target kinds before
   inspection until their target-specific adapters are qualified.
4. Freeze the scope and reject undeclared target kinds or stale inputs.
5. Build the required-source and defect-taxonomy coverage denominators.
6. Detect all issues without repairing.
7. Close the impact graph and cluster explicit root-cause lineages.
8. Produce one frozen repair batch and run preflight.
9. Build one isolated candidate and apply the complete batch transactionally.
10. Run the full verification matrix exactly once.
11. Compute the risk ledger and release claim from evidence, never from prose.
12. Run non-producer review. After closure or blocking, persist issue knowledge
    for a future explicitly authorized run.

## Safety and authorization

Inspection may be read-only. Any install, delete, release, migration, external
write, or irreversible action requires explicit authorization immediately before
that action. Preserve rollback evidence and never let a release token bypass the
risk ledger, verification matrix, or independent review.

## Available Scripts

| Script | Purpose | Arguments |
|---|---|---|
| `scripts/run_inspection.py` | Build the 72-cell taxonomy, inspect a target, or create a repaired candidate | `check`, `repair`, `build-taxonomy` |
| `scripts/release_skill.py` | Create an exact package, issue a digest-bound review receipt, validate the release claim, or install with rollback | `package`, `review`, `claim`, `install` |

When a `run_script` tool is available, invoke the entrypoint through it:

```text
run_script("scripts/run_inspection.py", ["check", "--target", "<path>", "--kind", "SKILL", "--output", "<run-dir>"])
```

Otherwise run:

```powershell
python scripts/run_inspection.py check --target <path> --kind SKILL --output <run-dir>
```

See [references/operations.md](references/operations.md) for all arguments and
artifacts.

## Requirements

- Python 3.12 or newer.
- Install the pinned `requirements.txt` dependencies before running the scripts:
  `jsonschema`, `PyYAML`, `pytest`, and `cryptography`.
- Final release verification also requires a fixed-path external Sigstore verifier
  executable.
- Read/write access to a separate run directory and, for repairs, a new candidate
  directory.

## Stable-local release lifecycle

The final release chain is `package -> GitHub Actions OIDC + Sigstore bundle
verification -> review -> claim -> install`. `sigstore-keyless` is the CLI
default; `ed25519-detached` remains an explicit local fallback.

`package` writes `package-manifest.json`; `review` writes `review-packet.json`
and `independent-review.json`; `claim` writes `release-claim.json`; and
`install` writes `install-receipt.json`. A claim first appends `CLAIM_INTENT`
with status `PREPARED`, writes the claim receipt, then appends `CLAIM_COMMIT`;
install records are appended to the authenticated hash chain. Review requires
the exact approved evaluator artifact, a frozen Sigstore trust configuration,
and a complete verifier execution closure.
Installation reverifies the exact Sigstore bundle, verifier command, certificate
identity, and OIDC issuer, stages a same-volume copy, reads the installed tree
back, and retains the previous target as a rollback tree. See
[references/operations.md](references/operations.md) for exact arguments,
statuses, artifact names, and the Ed25519 fallback.

The final claim is bounded to the frozen review universe and the exact workflow
certificate identity and GitHub Actions OIDC issuer. It does not imply
installation success beyond the verified platform receipts or physical
power-loss safety.

## Limitations

- The built-in detectors are a reference baseline, not a proof that unknown defect
  classes do not exist.
- Non-`SKILL` target kinds do not have released target-specific adapters.
- Non-canonical taxonomy combinations require the explicit policy proof recorded
  in the generated coverage file.
- Repair support is intentionally narrow: only evidence-backed safe operations are
  automated; other findings block for a human decision.
- Release claims are limited to the frozen target universe and completed evidence.
- The required runtime scope is Windows, WSL Linux, and macOS. A release claim
  is invalid unless all three platform installation results are `PASS`.
- Physical power-loss safety is not claimed unless a fresh physical mid-swap
  receipt is bound to the final installer. Same-volume staging and rollback are
  software evidence, not a physical durability guarantee. The release gate
  requires `durability.physical_power_loss=VERIFIED`; a simulated, mocked, or
  reboot-only probe cannot satisfy that domain.

## Troubleshooting

| Error | Cause | Solution |
|---|---|---|
| `BLOCKED_TAXONOMY` | A required taxonomy cell lacks a detector, oracle, or N/A proof | Run `build-taxonomy`; fix the reported uncovered cells |
| `BLOCKED_REPAIR_PLAN` | A finding needs human intent or an unsafe operation | Resolve the finding in a new complete run |
| `BLOCKED_VERIFICATION` | Candidate rerun still fails or a detector is blocked | Keep the candidate blocked; start a new authorized scope after repair |
| `BLOCKED_STALE_INPUT` | Target or policy digest changed during the run | Freeze the input and start a new run |

## Current implementation boundary

The default policy emits 72 taxonomy cells. Ten cells have executable, distinct
detector and oracle bindings; the other 62 are covered only by digest-bound
`NOT_APPLICABLE_WITH_PROOF` policy exclusions. A check runs ten qualification
controls per cell, for 720 controls total. These controls qualify evidence
plumbing; they are not a claim of 72 independent semantic vulnerability
analyzers. Source bytes and metadata come from one protected handle snapshot on
Windows and
descriptor-relative no-follow reads on POSIX. Each text file has continuous
byte, codepoint, line, syntax-unit, punctuation, and whitespace/control evidence;
opaque and cached files retain an explicit raw-byte projection. Discovery
observations are durable before the run advances to impact analysis; verification
observations are durable before a blocked state is recorded. Windows filesystem
audit can bind a mutation window to the USN journal identity and report
`AVAILABLE` or `UNAVAILABLE`; unavailable support fails closed. Repair
verification retains every new candidate finding. Release manifests use an exact
source file set, and installation uses a same-volume staged replacement with a
retained rollback tree. Staged files and directories are flush-synced before
activation, and both rename parents are flush-synced around each directory
replacement.

The built-in detectors remain a bounded baseline. Release claims are limited to
the frozen target universe and the recorded evidence; they are not a claim of
universal certainty about unknown defects.
