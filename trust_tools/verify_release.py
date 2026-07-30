"""Executable, fail-closed verification of a signed ASCEND release.

This exists because the previous procedure was a *document*, and the document was wrong in two
ways that a real proof-of-concept exposed:

  CRITICAL-1  it built the expected certificate identity as ``...@refs/heads/main``. A branch is
              mutable, and worse, ``@refs/heads/main`` is exactly the identity a candidate obtains
              by writing ``uses: <trust-repo>/<workflow>@main`` in its own caller. The policy that
              was supposed to make a candidate-authored caller unforgeable pinned the one string
              such a caller can produce — while refusing the genuine release, whose SAN ends in the
              immutable commit SHA.

  CRITICAL-2  its "trust anchor" step piped ``cosign verify-blob`` output through
              ``grep job_workflow_ref``. cosign prints ``Verified OK`` and nothing else, so the
              grep matched nothing, compared nothing, and could not fail. A security control that
              cannot fail is not a control.

The correction is to stop describing verification and start executing it. Two independent
mechanisms must BOTH agree before any object is accepted:

  1. ``cosign verify-blob`` with ``--certificate-identity`` (an *enforcing* flag: cosign exits
     nonzero when the SAN differs — verified against v3.1.2, including refusal of
     ``@refs/heads/main`` and of an abbreviated SHA);
  2. this module independently parsing the certificate out of the bundle and comparing the SAN,
     the OIDC issuer and the source-repository claim byte-for-byte.

Neither is trusted alone. Nothing depends on reading cosign's stdout, and nothing depends on a
human noticing a wrong value.

The signer SHA is **release-specific**. Historical artifacts must be verified against the trust
workflow commit that actually signed them, never against whatever the trust repository's head
happens to be today.

Trust-owned. Lives in the protected public trust repository.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "VerificationError", "ReleaseVerification",
    "TRUST_REPOSITORY", "TRUST_WORKFLOW_PATH", "SOURCE_REPOSITORY", "OIDC_ISSUER",
    "SIGNED_OBJECTS", "FORBIDDEN_COSIGN_FLAGS",
    "build_expected_identity", "validate_trust_sha", "verify_release",
]

TRUST_REPOSITORY = "VANTA2026/ascend-release-trust"
TRUST_WORKFLOW_PATH = ".github/workflows/build-and-attest-backend.yml"
# The certificate's GithubWorkflowRepository claim (OID 1.3.6.1.4.1.57264.1.12) records the
# SOURCE repository of the run — the caller — NOT the trust repository. Proven against the real
# run-30579291932 certificates; passing the trust repository here refuses a genuine release.
SOURCE_REPOSITORY = "VANTA2026/ASCEND-OS"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"

SIGNED_OBJECTS = (
    "ascend-backend-source.tar.gz",
    "ascend-backend-source-manifest.json",
    "ascend-wheelhouse-macos-arm64.tar.gz",
    "ascend-wheelhouse-policy-manifest.json",
    "requirements.macos-arm64-py311.lock.txt",
    "provenance-metadata.json",
)
PROVENANCE_NAME = "provenance-metadata.json"

# Flags that would hollow out the verification. Refused outright rather than documented against.
FORBIDDEN_COSIGN_FLAGS = (
    "--certificate-identity-regexp",
    "--certificate-oidc-issuer-regexp",
    "--insecure-ignore-tlog",
    "--insecure-ignore-sct",
    "--offline",  # removed in cosign v3; airgapped verification uses --trusted-root
)

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SAN_OID_URI = re.compile(r"URI:(\S+)")
# Fulcio X.509 extension OIDs
_OID_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8"
_OID_SOURCE_REPO = "1.3.6.1.4.1.57264.1.12"
_OID_BUILD_SIGNER_URI = "1.3.6.1.4.1.57264.1.9"


class VerificationError(RuntimeError):
    """Raised when a release cannot be verified. Always fail closed."""


@dataclass
class ReleaseVerification:
    trust_sha: str
    identity: str
    objects: dict[str, dict] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return len(self.objects) == len(SIGNED_OBJECTS) and all(o["verified"] for o in self.objects.values())


def validate_trust_sha(value: str) -> str:
    """The signer SHA must be an immutable 40-hex commit id.

    Branches, tags, symbolic refs and abbreviations are refused BEFORE any artifact is examined,
    so a mutable reference can never reach the identity string in the first place.
    """
    if not isinstance(value, str) or not value:
        raise VerificationError("trust workflow SHA is missing")
    lowered = value.strip()
    for mutable in ("refs/", "main", "master", "HEAD", "@", "/"):
        if mutable in lowered:
            raise VerificationError(
                f"trust workflow SHA must be an immutable 40-hex commit id, not a branch, tag or ref: {value!r:.60}"
            )
    if not _SHA_RE.match(lowered):
        raise VerificationError(
            f"trust workflow SHA must be exactly 40 lowercase hex characters "
            f"(abbreviated, uppercase and malformed values are refused): {value!r:.60}"
        )
    return lowered


def build_expected_identity(trust_sha: str) -> str:
    """The exact SAN the genuine signing run produces, terminating in the immutable commit."""
    sha = validate_trust_sha(trust_sha)
    return f"https://github.com/{TRUST_REPOSITORY}/{TRUST_WORKFLOW_PATH}@{sha}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _certificate_der(bundle_path: Path) -> bytes:
    try:
        doc = json.loads(bundle_path.read_text())
    except (OSError, ValueError) as exc:
        raise VerificationError(f"{bundle_path.name}: unreadable bundle ({type(exc).__name__})") from None
    material = doc.get("verificationMaterial") or {}
    cert = material.get("certificate")
    if cert is None:
        chain = (material.get("x509CertificateChain") or {}).get("certificates") or []
        cert = chain[0] if chain else None
    if not cert or "rawBytes" not in cert:
        raise VerificationError(f"{bundle_path.name}: bundle carries no certificate")
    try:
        return base64.b64decode(cert["rawBytes"])
    except Exception:
        raise VerificationError(f"{bundle_path.name}: certificate is not valid base64") from None


def _tlog_entry(bundle_path: Path) -> dict:
    doc = json.loads(bundle_path.read_text())
    entries = ((doc.get("verificationMaterial") or {}).get("tlogEntries")) or []
    if not entries:
        raise VerificationError(f"{bundle_path.name}: bundle carries no transparency-log entry")
    entry = entries[0]
    proof = entry.get("inclusionProof") or {}
    if not proof.get("checkpoint") or not proof.get("hashes"):
        raise VerificationError(f"{bundle_path.name}: transparency-log entry has no inclusion proof")
    return entry


def _certificate_text(der: bytes) -> str:
    result = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout", "-text"],
        input=der, capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise VerificationError("certificate could not be parsed by openssl")
    return result.stdout.decode("utf-8", "replace")


def _extension_value(text: str, oid: str) -> str:
    """Read a Fulcio extension value.

    The v2 extensions are DER-encoded UTF8Strings, and `openssl x509 -text` prints the raw bytes,
    so the payload is preceded by a tag/length prefix that renders as one or two stray characters
    (``+``, ``&``, ``(``, ``.``, ``k`` …). Stripping a fixed character set is fragile — the prefix
    is a *length*, so it varies with the value. Take everything from the first alphanumeric
    character instead, which is where every value of interest (a URL or a hex SHA) begins.
    """
    match = re.search(rf"{re.escape(oid)}:\s*\n\s*(.+)", text)
    if not match:
        return ""
    raw = match.group(1).strip()
    payload = re.search(r"[A-Za-z0-9].*$", raw)
    return payload.group(0).strip() if payload else ""


def _independent_certificate_check(bundle_path: Path, expected_identity: str) -> dict:
    """Parse the certificate ourselves. Never trust a single mechanism."""
    der = _certificate_der(bundle_path)
    text = _certificate_text(der)

    san_match = _SAN_OID_URI.search(text)
    if not san_match:
        raise VerificationError(f"{bundle_path.name}: certificate has no SAN URI identity")
    san = san_match.group(1)
    if san != expected_identity:
        raise VerificationError(
            f"{bundle_path.name}: certificate identity is {san!r}, expected {expected_identity!r}"
        )

    issuer = _extension_value(text, _OID_ISSUER_V2)
    if issuer and issuer != OIDC_ISSUER:
        raise VerificationError(f"{bundle_path.name}: OIDC issuer is {issuer!r}, expected {OIDC_ISSUER!r}")

    source_repo = _extension_value(text, _OID_SOURCE_REPO)
    expected_source = f"https://github.com/{SOURCE_REPOSITORY}"
    if source_repo and source_repo != expected_source:
        raise VerificationError(
            f"{bundle_path.name}: source repository claim is {source_repo!r}, expected {expected_source!r}"
        )

    signer = _extension_value(text, _OID_BUILD_SIGNER_URI)
    if signer and signer != expected_identity:
        raise VerificationError(
            f"{bundle_path.name}: build signer URI is {signer!r}, expected {expected_identity!r}"
        )

    entry = _tlog_entry(bundle_path)
    return {"san": san, "issuer": issuer or OIDC_ISSUER, "source_repository": source_repo,
            "rekor_log_index": entry.get("logIndex")}


def _run_cosign(cosign: str, args: list[str]) -> subprocess.CompletedProcess:
    if not os.path.isabs(cosign):
        raise VerificationError(f"cosign must be given as an absolute path, got {cosign!r}")
    if not os.path.isfile(cosign):
        raise VerificationError(f"cosign binary not found at {cosign}")
    for arg in args:
        if arg in FORBIDDEN_COSIGN_FLAGS:
            raise VerificationError(f"refusing to run cosign with {arg}")
    return subprocess.run([cosign, *args], capture_output=True, check=False)


def verify_release(
    evidence_dir: str | os.PathLike[str],
    trust_sha: str,
    trusted_root: str | os.PathLike[str],
    cosign: str,
    *,
    source_repository: str = SOURCE_REPOSITORY,
    issuer: str = OIDC_ISSUER,
) -> ReleaseVerification:
    """Verify all six signed objects. Raises VerificationError on ANY failure."""
    identity = build_expected_identity(trust_sha)
    evidence = Path(evidence_dir)
    root = Path(trusted_root)
    if not root.is_file():
        raise VerificationError(f"trusted root material is missing: {root}")
    if root.stat().st_size == 0:
        raise VerificationError(f"trusted root material is empty: {root}")
    try:
        json.loads(root.read_text())
    except ValueError:
        raise VerificationError(f"trusted root material is not valid JSON: {root}") from None

    result = ReleaseVerification(trust_sha=validate_trust_sha(trust_sha), identity=identity)

    for name in SIGNED_OBJECTS:
        obj, bundle = evidence / name, evidence / f"{name}.cosign.bundle"
        if not obj.is_file():
            raise VerificationError(f"signed object is missing: {name}")
        if not bundle.is_file():
            raise VerificationError(f"Sigstore bundle is missing: {name}.cosign.bundle")

        # Mechanism 1: cosign, whose EXIT STATUS is the control. Its stdout is never parsed.
        completed = _run_cosign(cosign, [
            "verify-blob",
            "--trusted-root", str(root),
            "--bundle", str(bundle),
            "--certificate-identity", identity,
            "--certificate-oidc-issuer", issuer,
            "--certificate-github-workflow-repository", source_repository,
            str(obj),
        ])
        if completed.returncode != 0:
            raise VerificationError(
                f"{name}: cosign refused (exit {completed.returncode}): "
                f"{completed.stderr.decode('utf-8','replace').strip()[:200]}"
            )

        # Mechanism 2: our own certificate parse, independent of cosign entirely.
        facts = _independent_certificate_check(bundle, identity)
        result.objects[name] = {"verified": True, "sha256": _sha256(obj), **facts}

    # Every recorded digest in the signed provenance must equal the bytes on disk.
    provenance = json.loads((evidence / PROVENANCE_NAME).read_text())
    recorded = provenance.get("signed_objects") or {}
    if len(recorded) != len(SIGNED_OBJECTS):
        raise VerificationError(f"provenance lists {len(recorded)} signed objects, expected {len(SIGNED_OBJECTS)}")
    for name, digest in recorded.items():
        if name == PROVENANCE_NAME:
            continue
        if name not in result.objects:
            raise VerificationError(f"provenance names an object that was not verified: {name}")
        measured = result.objects[name]["sha256"]
        if measured != digest:
            raise VerificationError(
                f"{name}: provenance records {digest}, measured {measured}"
            )
    if set(recorded) != set(SIGNED_OBJECTS):
        raise VerificationError("provenance signed_objects does not match the required six")

    if not result.ok:
        raise VerificationError("not every signed object verified")
    return result


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed verification of a signed ASCEND release.")
    parser.add_argument("--evidence", required=True, help="directory holding the six objects and bundles")
    parser.add_argument("--trust-sha", required=True,
                        help="the IMMUTABLE trust workflow commit that signed THIS release")
    parser.add_argument("--trusted-root", required=True, help="pinned Sigstore trusted_root.json")
    parser.add_argument("--cosign", required=True, help="absolute path to the authenticated cosign binary")
    parser.add_argument("--source-repository", default=SOURCE_REPOSITORY)
    parser.add_argument("--issuer", default=OIDC_ISSUER)
    args = parser.parse_args(argv[1:])
    try:
        result = verify_release(args.evidence, args.trust_sha, args.trusted_root, args.cosign,
                                source_repository=args.source_repository, issuer=args.issuer)
    except VerificationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print(f"identity={result.identity}")
    for name, info in result.objects.items():
        print(f"verified {name} sha256={info['sha256']} rekor={info['rekor_log_index']}")
    print(f"verified_objects={len(result.objects)}/{len(SIGNED_OBJECTS)}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(_main(sys.argv))
