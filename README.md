# ascend-release-trust

**This repository contains no ASCEND source code, no build artifacts, no credentials, no database
and no production configuration. It contains the trusted release workflow and the code that makes
the release decision.**

## Why this repository exists

ASCEND's backend release verification was attempted four times inside the source repository and
rejected four times. The first three failed the same way in different disguises: the trust root was
something the release candidate's own author controlled. The fourth failed more usefully — its
verifier resolved an external program through the inherited `PATH`, and the digest meant to bind the
verifier covered five filenames rather than the directory it imported code from.

A fifth attempt moved the *workflow* here but left the **measuring code** in the candidate
repository. Independent review rejected it: the candidate's `tools/release/*` still created the
archive, created the manifest, reported the digests, and was imported again to verify its own
result. Moving the workflow while leaving the measurement behind changes the address of the problem,
not the problem.

So the trust boundary is now drawn around *code*, not around files:

- this repository is **public**, so branch protection is available and everything is auditable;
- `main` is **protected**, so the workflow and its tools cannot be changed unilaterally;
- callers reference the workflow by **immutable full commit SHA**, never a branch or tag;
- Sigstore records that SHA in the signing certificate, so the host policy pins the exact reviewed
  revision of the exact reviewed code.

## The trust boundary

Everything that measures, decides, or produces a signed byte lives in `trust_tools/` **here**:

| Concern | Trust-owned module |
|---|---|
| exact Git-object export, approved-path selection | `git_object_export.py` |
| deterministic archive creation, collision detection | `deterministic_archive.py` |
| complete lockfile parsing and validation | `lock_policy.py` |
| wheel filename / METADATA / WHEEL-tag parsing, arm64+cp311 policy, universal2 policy | `wheelhouse_policy.py` |
| filesystem manifests, safe extraction, pass comparison, independent digests | `manifest_policy.py` |
| input validation, provenance generation | `provenance.py` |
| the promotion decision itself | `attest.py` |

The candidate repository `VANTA2026/ASCEND-OS` supplies **payload only**: its Git objects. Its own
`tools/release/*` ships inside the artifact as content and is **never executed, imported, or
believed** by this workflow. A test proves it: sabotaging the candidate's working-tree copies leaves
the produced artifact bit-identical, because the tree is read from the Git object database.

Candidate-controlled code cannot generate a trusted artifact, generate a trusted manifest, report an
authoritative digest, validate its own output, decide compatibility, or influence promotion.

## What the workflow does

Given one input — an exact 40-character backend commit SHA, which must equal the approved release
commit — it:

1. validates every input through trust-owned validators before any value reaches a shell;
2. **enforces** that the commit is contained in `refs/heads/release/build-616-backend-d1f4`, and
   fails nonzero if it is not;
3. builds the source artifact **twice**, on two fresh runners, by exporting exact Git blobs for an
   allowlist of approved paths — not by checking out a worktree, whose bytes `.gitattributes`
   filters can silently change;
4. builds the macOS arm64 wheelhouse **twice**, on two fresh runners, from the hash-pinned lock;
5. in `compare-and-sign`, downloads **both passes of both artifacts** and re-measures every digest
   itself, re-exports the lockfile from Git objects, re-runs the wheel policy from scratch, and
   requires each artifact to be the **canonical encoding of its own verified content**;
6. signs exactly **six** objects with Cosign keyless signing through GitHub Actions OIDC.

It does not deploy, does not touch a production host, does not request production credentials, does
not read a production database, and does not publish artifacts publicly.

## The six signed objects

1. `ascend-backend-source.tar.gz`
2. `ascend-backend-source-manifest.json`
3. `ascend-wheelhouse-macos-arm64.tar.gz`
4. `ascend-wheelhouse-policy-manifest.json`
5. `requirements.macos-arm64-py311.lock.txt`
6. `provenance-metadata.json`

Every object's independently measured SHA-256 is recorded in the provenance document.

## Target runtime Python vs build driver Python

`TARGET_RUNTIME_PYTHON` is **3.11.15** — what the backend runs on, what the lock was generated
against, and the only interpreter whose runtime compatibility is claimed.

`actions/python-versions` publishes no Darwin/arm64 build of 3.11.15, so the wheelhouse job cannot
ask `setup-python` for it. Rather than silently substitute another production Python, a separately
recorded **driver Python (3.13.14, exact)** runs `pip download` with explicit `--platform`,
`--implementation`, `--python-version` and `--abi`, and every wheel must match a hash the lock
permits *for that distribution*. A wheelhouse built this way is **not** evidence that the runtime
works; that evidence comes from the offline installation gate on exact 3.11.15 and from the
production-host prepared-runtime gate.

## Public transparency log — read this before using it

Cosign keyless signing writes to the **public Rekor transparency log**. Using this workflow
publishes, permanently and irrevocably: the private repository's name, this workflow's path and
commit SHA, the backend commit SHA being built, and build timestamps. It does **not** publish source
code, artifact contents, credentials or athlete data. This trade is deliberate: it is what makes the
provenance verifiable by a third party without anyone holding a long-lived signing key.

## Permissions

| Permission | Why |
|---|---|
| `contents: read` | check out this repository and the private source at the approved commit |
| `id-token: write` | mint the short-lived OIDC token Cosign exchanges with Fulcio (signing job only) |

No packages, deployments, `actions: write`, or `attestations: write`. The top-level workflow declares
only `contents: read`; `id-token: write` is granted to the signing job alone.

## Changing this repository

Any change requires a pull request and review on the protected `main` branch. After merging, the
caller in the private repository must be re-pinned to the new commit SHA **and** the host
verification policy updated to the new identity — deliberately, so a change can never take effect
silently.

## Tests

`pytest tests` — the trust tools are unit-tested, including adversarial cases: command-injection
payloads against every input, falsified build output, pass mismatch, lock tampering, wheel metadata
mismatch, wrong architecture and ABI, universal2 false positives and false negatives, smuggled
archive members, and non-canonical artifact encodings.
