# Host verification policy

Verification happens on the operator's Mac, before anything is promoted. The host trusts the
**Fulcio certificate identity**, not any field inside a downloaded document.

> **This document does not verify anything by itself.** Verification is performed by
> `trust_tools/verify_release.py` from this repository, which exits nonzero on any mismatch. A
> previous revision of this file described checks in prose that did not execute; both of those
> defects were found by a real proof-of-concept and are recorded in section 0.

## 0. What was wrong before, and why it matters

Run 30579291932 produced a genuine, fully attested release. Following the previous revision of this
document against that evidence **refused all six objects**, for two independent reasons:

1. **The expected identity was pinned to a mutable branch.** It was built as
   `...build-and-attest-backend.yml@refs/heads/main`, while the real certificate SAN ends in the
   immutable trust-workflow commit. Worse, `@refs/heads/main` is exactly the identity a
   candidate-authored caller obtains by writing `uses: <trust-repo>/<workflow>@main` — so the
   document pinned the one string an attacker can mint, and rejected the one the honest build
   produces.
2. **The step called "the trust anchor" could not fail.** It ran
   `cosign verify-blob ... | grep -i job_workflow_ref`. cosign prints `Verified OK` and nothing
   else, so the grep matched nothing, compared nothing, and always "passed".

A third, smaller defect: `--certificate-github-workflow-repository` was given the **trust**
repository. That OID records the **source** repository of the run. Passing the trust repo refuses a
genuine release.

The corrections below are executable and were exercised against the preserved evidence.

## 1. Authenticate the verifier

```sh
COSIGN=/Users/admin/ascend-ops/verifier/cosign     # absolute path, never resolved through $PATH
shasum -a 256 "$COSIGN"                            # must equal the digest recorded at install time
"$COSIGN" version                                  # must report v3.1.2
```

Always invoke Cosign by **absolute path**. A bare name is resolved through the inherited `PATH`,
which a candidate-adjacent process could influence — that exact defect sank an earlier candidate.

## 2. Verify a release — the only supported procedure

```sh
python3 trust_tools/verify_release.py \
  --evidence     /path/to/downloaded/artifact \
  --trust-sha    <TRUST_WORKFLOW_SHA_THAT_SIGNED_THIS_RELEASE> \
  --trusted-root /Users/admin/ascend-ops/verifier/trustroot/trusted_root.json \
  --cosign       /Users/admin/ascend-ops/verifier/cosign
echo "exit=$?"      # 0 = every object verified; anything else = REFUSED
```

**The exit status is the verdict.** Do not read the output and decide. Do not continue on nonzero.

`--trust-sha` is **release-specific**: it is the trust-workflow commit that signed *that* release,
which you take from the release record — never from the trust repository's current head. Verifying
old artifacts against today's head would silently accept or reject the wrong thing.

For the preserved run-30579291932 evidence the value is exactly:

```
dd32f6553de1d7a2f78c9e313f379e81bf9ee725
```

### What the verifier enforces

| Rule | Enforcement |
|---|---|
| Identity ends in an **immutable 40-hex commit** | refused before any artifact is opened; branches, tags, `HEAD`, symbolic refs, abbreviated and uppercase SHAs all fail closed |
| Exact certificate SAN | `cosign --certificate-identity` (an enforcing flag: nonzero on mismatch) **and** an independent certificate parse in the verifier |
| OIDC issuer | `https://token.actions.githubusercontent.com`, checked by cosign and independently |
| Source repository claim | `VANTA2026/ASCEND-OS` — the **caller**, which is what OID 1.3.6.1.4.1.57264.1.12 records |
| Build-signer URI | independently compared to the expected identity |
| Rekor inclusion | every bundle must carry a transparency-log entry with an inclusion proof and checkpoint |
| Artifact digests | each object measured and compared with the digest recorded in the signed provenance |
| Exactly six objects | a missing, extra or unbundled object is a refusal |

Two independent mechanisms must both agree: cosign's exit status, and the verifier's own parse of
the certificate. Neither is trusted alone, and no verdict is ever derived from tool stdout.

### Flags that are refused outright

`--certificate-identity-regexp`, `--certificate-oidc-issuer-regexp`, `--insecure-ignore-tlog`,
`--insecure-ignore-sct`, and `--offline`. The verifier raises rather than run any of them. (The
first two would loosen exact identity matching; the next two would discard transparency-log and SCT
evidence; `--offline` no longer exists in cosign v3 — see section 4.)

## 3. Cross-check the release against what you approved

```sh
python3 - <<'PY'
import json, pathlib
doc = json.loads(pathlib.Path("provenance-metadata.json").read_text())
print("backend_commit:", doc["backend_commit"])
print("release_ref:   ", doc["release_ref"])
PY
```

Compare `backend_commit` with the commit you approved. If it differs, stop. The verifier already
proved the document's own digests match the bytes; this step is about *which release* it is.

## 4. Cold-cache / air-gapped verification

`--offline` was removed in cosign v3 — passing it is an error, not a hardening step. Airgapped
verification uses a **pinned trusted root**:

```sh
# ONCE, on a network, then keep the file and record its digest:
env -i HOME="$TMP" PATH=/usr/bin:/bin "$COSIGN" initialize
cp "$TMP/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json" \
   /Users/admin/ascend-ops/verifier/trustroot/trusted_root.json
shasum -a 256 /Users/admin/ascend-ops/verifier/trustroot/trusted_root.json
```

Thereafter the section-2 command verifies with **no network at all**. This was exercised with an
empty `HOME`, no warmed Sigstore cache, and every proxy blackholed: 6/6 verified. A missing, empty,
malformed or altered trusted root is refused.

## 5. Build the runtime ON THE HOST — never copy a venv

```sh
RELEASE_ID="<substitute the content-addressed release id>"
REL="/Users/admin/ascend-releases/${RELEASE_ID}"
mkdir -p "$REL" && tar -xzf ascend-backend-source.tar.gz -C "$REL"
mkdir -p /tmp/wh && tar -xzf ascend-wheelhouse-macos-arm64.tar.gz -C /tmp/wh

# The interpreter MUST be exactly CPython 3.11.15 arm64 — the version the lock was generated
# against. A different patch version invalidates the lock.
PYBIN=/Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11
"$PYBIN" -c 'import sys,platform;v="%d.%d.%d"%sys.version_info[:3];\
assert v=="3.11.15" and platform.machine()=="arm64", f"refusing: {v} {platform.machine()}"'

# Created at its FINAL path (a venv records absolute paths) and WITHOUT pip, so the runtime holds
# exactly the locked closure and no unlocked seed packages.
/usr/bin/env -i HOME="$HOME" PYTHONNOUSERSITE=1 "$PYBIN" -m venv --without-pip "$REL/.venv"

env -i HOME="$HOME" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
  /path/to/bootstrap/python -m pip --python "$REL/.venv/bin/python" install \
    --no-index --find-links=/tmp/wh --require-hashes --no-compile \
    -r "$REL/requirements.macos-arm64-py311.lock.txt"
```

`--no-index` forbids network resolution, `--find-links` restricts installation to the attested
wheelhouse, and `--require-hashes` refuses any file whose hash is not in the attested lock.

Using `tar` to **extract** here is safe and is not the ambiguity the build side removed: the next
step recomputes the manifest from the extracted tree and requires equality, so a lossy extraction is
caught. What could not be tolerated was `tar` **producing** the bytes that get signed.

## 6. Extracted-tree and installed-runtime closure

1. Recompute the source manifest of the extracted tree and require equality with the **signed**
   manifest. Any difference is fatal.
2. Produce an installed-runtime manifest of `$REL/.venv`; require the installed set to equal the
   locked set exactly, with no unexpected distribution.
3. Require no `.pth` entry or `.pth` import to resolve outside the venv, and no editable install.
4. Set the source tree read-only; run with `-B` and `PYTHONDONTWRITEBYTECODE=1` so nothing writes
   `__pycache__` into a verified tree.
5. Attach the database only as a separately measured host attachment; require exactly one.
6. Retain the existing database identity and revision checks.

## 7. The lock is target-specific

`requirements.macos-arm64-py311.lock.txt` is valid for **macOS / arm64 / CPython 3.11.15 / cp311**
only. Never reuse it for Linux, Intel macOS, or another Python patch version. The workflow itself
refuses to install it on a Linux runner for this reason.
