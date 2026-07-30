# Proof-of-concept plan

Subject: a harmless synthetic run of the trusted workflow against the approved backend commit
`50cbe173ea55fea6943c40765ab64dde99406c2e`, on GitHub-hosted runners. No production files, no
production credentials, no production database, no LaunchAgent change.

Every "refuses" case must fail with a **named** error. A case that fails for an unrelated reason has
proven nothing and must be re-run until the intended condition is the one that fires.

Cases marked **[T]** are already covered by the trust-tool suite and pass today (176 tests); the CI
run must confirm the same behaviour end to end. Cases marked **[CI]** require an actual workflow run
and are the reason this plan exists.

## A. Provenance and identity

| # | Case | Result required | State |
|---|---|---|---|
| 1 | Correct artifact verifies | all six blobs `Verified OK` | [CI] |
| 2 | Modified artifact refuses | append one byte to the source archive → signature fails | [CI] |
| 3 | Wrong commit refuses | `backend_commit` differs from the approved SHA → content check fails | [CI] |
| 4 | Wrong repository refuses | verify with a different `--certificate-github-workflow-repository` | [CI] |
| 5 | Wrong workflow refuses | `--certificate-identity` naming another workflow path | [CI] |
| 6 | Wrong issuer refuses | `--certificate-oidc-issuer https://accounts.google.com` | [CI] |
| 7 | Candidate-authored workflow cannot become trusted | add a local trust-shaped workflow in the PRIVATE repo and sign; certificate identity is the private repo's → pinned policy refuses | [CI] |
| 8 | Self-hosted runner refused | `RUNNER_ENVIRONMENT` guard exits nonzero | [CI] |
| 9 | Hand-made provenance ignored | a JSON file with no bundle cannot be verified at all | [CI] |
| 10 | Candidate-local "green" verdict ignored | in-repo preflight without `ASCEND_EXTERNAL_ATTESTATION` → `RP-EXT.attestation_required`, `deployable:false` | [CI] |
| 11 | `job_workflow_ref` is the anchor | the certificate claim, not the document field, decides identity | [CI] |
| 12 | Offline verification succeeds | `--offline` with a pinned trust root, network disabled | [CI] |
| 13 | Offline verification refuses after modification | modify bundle or artifact, retry `--offline` | [CI] |

## B. Trust boundary

| # | Case | Result required | State |
|---|---|---|---|
| 14 | Sabotaged candidate `tools/release/*` cannot change the artifact | working-tree sabotage leaves the archive bit-identical (blobs are read from the object database) | **[T] passes** |
| 15 | Candidate code is never executed or imported | no trust module references a candidate path; no workflow runs candidate code | **[T] passes** |
| 16 | Falsified build output refuses | build job's policy manifest ≠ independent re-derivation → refused | **[T] passes** |
| 17 | Reported digests are never authority | `compare-and-sign` measures both passes itself | **[T] passes** |

## C. Reproducibility

| # | Case | Result required | State |
|---|---|---|---|
| 18 | Two passes agree | source and wheelhouse identical across independent runners | [CI] |
| 19 | Pass-1/pass-2 mismatch refuses | perturb one pass → named "independent passes disagree" | **[T] passes** |
| 20 | Non-canonical artifact refuses | append bytes to **both** passes → "not the canonical encoding of its own content" | **[T] passes** |
| 21 | Smuggled archive member refuses | extra file inside both passes → manifest mismatch naming the file | **[T] passes** |
| 22 | GNU/BSD `tar` cannot affect output | no tar participates in producing bytes; writer unchanged with `PATH` emptied and with sabotaging `tar`/`gtar` first on `PATH` | **[T] passes** |
| 23 | `.gitattributes` cannot alter exported bytes | checkout yields CRLF, export yields the stored blob | **[T] passes** |
| 24 | Approved-path selection, not pruning | a file directly beneath a partially retained parent is not swept in | **[T] passes** |

## D. Lock integrity

| # | Case | Result required | State |
|---|---|---|---|
| 25 | Missing lockfile refuses | named error from the export step | **[T] passes** |
| 26 | Partially hashed lockfile refuses | names the unhashed requirement | **[T] passes** |
| 27 | Floating pin refuses | "not pinned with '=='" | **[T] passes** |
| 28 | Editable / VCS / URL / file / index / credential entry refuses | one named error each | **[T] passes** |
| 29 | Non-sha256 or truncated digest refuses | named | **[T] passes** |
| 30 | Unresolved environment marker refuses | named | **[T] passes** |
| 31 | Duplicate or conflicting entry refuses | named | **[T] passes** |
| 32 | Lock digest binding | a single altered byte breaks the expected-digest check | **[T] passes** |
| 33 | Lock generated on the wrong OS / wrong Python patch refuses | resolution cannot satisfy the arm64/cp311 target; hash gate fires | [CI] |
| 34 | Two lock generations disagreeing are never committed | generation procedure reports the differing lines and commits neither | **[T] passes** (procedure documented in `docs/DEPENDENCY_LOCK.md`) |
| 35 | The lock is one of the six signed objects | exactly six bundles, lock among them | **[T] passes** |

## E. Wheel policy

| # | Case | Result required | State |
|---|---|---|---|
| 36 | sdist refuses | `--only-binary=:all:` not honoured → named | **[T] passes** |
| 37 | Linux wheel refuses | named | **[T] passes** |
| 38 | Intel-only macOS wheel refuses, even fully pinned | "never be accepted as an arm64 substitute" | **[T] passes** |
| 39 | Altered wheel refuses | digest not permitted for that distribution | **[T] passes** |
| 40 | Extra / unlocked wheel refuses | "not a locked distribution" | **[T] passes** |
| 41 | Missing locked distribution refuses | "no compatible wheel" | **[T] passes** |
| 42 | Duplicate wheel for one distribution refuses | named | **[T] passes** |
| 43 | Wheel carrying another distribution's digest refuses | per-distribution hash association | **[T] passes** |
| 44 | METADATA name/version mismatch refuses | named | **[T] passes** |
| 45 | Internal WHEEL tags disagreeing with the filename refuses | named | **[T] passes** |
| 46 | Platform token in the project name or local version cannot impersonate a tag | tags read positionally | **[T] passes** |
| 47 | universal2 false negative | a valid `cp39-abi3` universal2 wheel is **accepted**, not removed | **[T] passes** |
| 48 | universal2 false positive | an x86_64-only wheel is never declared universal2 in provenance | **[T] passes** |
| 49 | universal2 unpinned refuses | never warning-only | **[T] passes** |
| 50 | Wrong ABI / non-CPython interpreter refuses | PyPy, GraalPy, miscased tags fail **closed** | **[T] passes** |

## F. Injection and input handling

| # | Case | Result required | State |
|---|---|---|---|
| 51 | Shell-injecting `release_name` refuses | 12 payloads, all rejected by the validator | **[T] passes** |
| 52 | JSON-injecting `release_name` refuses | cannot reach the signed document | **[T] passes** |
| 53 | Injecting `backend_sha` / `source_repository` refuses | same battery | **[T] passes** |
| 54 | Provenance built by a real serializer | never a shell heredoc | **[T] passes** |
| 55 | Directly-invoked nested workflow validates its own inputs | repository, SHA, pass label, arm64 architecture | [CI] |

## G. Runtime closure (host side)

| # | Case | Result required | State |
|---|---|---|---|
| 56 | Offline installation on exact 3.11.15 succeeds | closed runtime, zero seed packages | already demonstrated locally |
| 57 | Unexpected installed package refuses | installed-runtime manifest names it | already demonstrated locally |
| 58 | `.pth` / editable import escape refuses | closure check names it | already demonstrated locally |

## Adversarial review to run alongside

Attack, at minimum: workflow provenance; certificate identity binding; CI permission scope; artifact
determinism; the host verifier bootstrap (how Cosign itself is trusted); the Sigstore trust-root
cold-cache path; wheel/lock association; and extracted-runtime closure.

Treat "the reviewer could not reach it" as an open question, not a pass.
