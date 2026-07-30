# Host verification policy

Verification happens on the operator's Mac, before anything is promoted. The host trusts the
**Fulcio certificate identity**, not any field inside a downloaded document.

## 0. Bootstrap the verifier

The verifier itself must be trusted before it can vouch for anything.

```sh
# Cosign v3, obtained from the official release and checked against its published digest.
COSIGN=/usr/local/bin/cosign-v3.1.2          # absolute path, never resolved through $PATH
shasum -a 256 "$COSIGN"                       # compare with the checksum from the v3.1.2 release
"$COSIGN" version
```

Always invoke Cosign by **absolute path**. A bare name is resolved through the inherited `PATH`,
which a candidate-adjacent process could influence — that exact defect sank an earlier candidate.

## 1. Pin the certificate identity

```sh
TRUST_REPO=VANTA2026/ascend-release-trust
WORKFLOW=.github/workflows/build-and-attest-backend.yml
TRUST_SHA=<TRUST_WORKFLOW_SHA>               # the exact reviewed commit, never a branch or tag

IDENTITY="https://github.com/${TRUST_REPO}/${WORKFLOW}@refs/heads/main"
ISSUER="https://token.actions.githubusercontent.com"
```

Verify each object with the identity pinned:

```sh
for f in ascend-backend-source.tar.gz \
         ascend-backend-source-manifest.json \
         ascend-wheelhouse-macos-arm64.tar.gz \
         ascend-wheelhouse-policy-manifest.json \
         requirements.macos-arm64-py311.lock.txt \
         provenance-metadata.json; do
  "$COSIGN" verify-blob \
    --bundle "${f}.cosign.bundle" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-identity "$IDENTITY" \
    --certificate-github-workflow-repository "$TRUST_REPO" \
    "$f" || { echo "REFUSED: $f"; exit 1; }
done
```

**All six must verify.** Five verifying and one missing is a refusal, not a partial pass.

## 2. The workflow identity comes from the certificate, not from the document

`provenance-metadata.json` records a `trust_workflow_ref` field. It is **not** the trust anchor and
the document says so itself. The anchor is the `job_workflow_ref` claim Fulcio places in the signing
certificate. Read it from the certificate:

```sh
"$COSIGN" verify-blob --bundle provenance-metadata.json.cosign.bundle \
  --certificate-oidc-issuer "$ISSUER" --certificate-identity "$IDENTITY" \
  --certificate-github-workflow-repository "$TRUST_REPO" \
  provenance-metadata.json 2>&1 | grep -i 'job_workflow_ref'
```

Require the SHA embedded there to equal `$TRUST_SHA`. A caller pointed at a different workflow
produces a different claim, and this check refuses it.

## 3. Cross-check the documents against the bytes

```sh
python3 - <<'PY'
import hashlib, json, pathlib
doc = json.loads(pathlib.Path("provenance-metadata.json").read_text())
for name, recorded in doc["signed_objects"].items():
    if recorded == "self":
        continue
    measured = hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
    assert measured == recorded, f"{name}: measured {measured}, provenance says {recorded}"
print("all recorded digests match the bytes on disk")
PY
```

Then compare `doc["backend_commit"]` with the commit you approved. If it differs, stop.

## 4. Offline verification, cold cache

Sigstore bundles carry the certificate and the transparency-log inclusion proof, so verification
needs no network:

```sh
"$COSIGN" verify-blob --offline --bundle "${f}.cosign.bundle" ... "$f"
```

Cold-cache caveat, stated plainly: `--offline` validates the bundle's inclusion proof against the
**Rekor public key embedded in the trust root**. If the local Sigstore trust root has never been
initialised on this host, obtain it once, on a network, from the official TUF root, and record its
digest. After that, verification is genuinely offline. Do not treat a first-ever offline run as
proof of anything until that root is pinned.

## 5. Build the runtime ON THE HOST — never copy a venv

```sh
REL=/Users/admin/ascend-releases/<release-id>
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
