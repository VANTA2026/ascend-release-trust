"""The operator verification procedure must be executable and fail closed.

Two CRITICAL defects in the previous published policy motivated this module, both confirmed against
a real signing run (30579291932):

  CRITICAL-1  the expected identity was built as ``...@refs/heads/main``. A branch is mutable, and
              ``@refs/heads/main`` is precisely the identity a candidate-authored caller produces by
              writing ``uses: <trust-repo>/<workflow>@main``. The published policy therefore pinned
              the one string an attacker can mint, while refusing the genuine release.

  CRITICAL-2  the step the document called the trust anchor was
              ``cosign verify-blob ... | grep -i job_workflow_ref``. cosign prints ``Verified OK``
              and nothing else, so the grep matched nothing and could never fail.

These tests pin the repaired behaviour. Where a test needs real signed material it uses the
preserved run-30579291932 evidence; where that is unavailable the test is reported as BLOCKED, never
silently skipped as passing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import verify_release as vr

EVIDENCE = Path("/Users/admin/ascend-evidence/poc-run-30579291932/artifact")
TRUSTED_ROOT = Path("/Users/admin/ascend-ops/verifier/trustroot/trusted_root.json")
COSIGN = Path("/Users/admin/ascend-ops/verifier/cosign")
THIRD_SHA = "dd32f6553de1d7a2f78c9e313f379e81bf9ee725"

_HAVE_EVIDENCE = EVIDENCE.is_dir() and TRUSTED_ROOT.is_file() and COSIGN.is_file()
requires_evidence = pytest.mark.skipif(
    not _HAVE_EVIDENCE,
    reason="BLOCKED (not passed): preserved run-30579291932 evidence, pinned trusted root, "
           "or authenticated cosign is unavailable on this host",
)


# ---------------------------------------------------------------- CRITICAL-1: immutable identity


@pytest.mark.parametrize("mutable", [
    "refs/heads/main", "refs/heads/master", "refs/tags/v1.0.0",
    "main", "master", "HEAD", "@main",
    "VANTA2026/ascend-release-trust@main",
])
def test_critical1_mutable_references_are_refused(mutable):
    """A branch, tag or symbolic ref must never reach the identity string."""
    with pytest.raises(vr.VerificationError, match="immutable 40-hex commit id|40 lowercase hex"):
        vr.validate_trust_sha(mutable)


@pytest.mark.parametrize("bad", [
    "", "   ", "dd32f655", "dd32f6553de1d7a2f78c9e313f379e81bf9ee72",       # abbreviated / short
    "dd32f6553de1d7a2f78c9e313f379e81bf9ee7255",                              # too long
    "DD32F6553DE1D7A2F78C9E313F379E81BF9EE725",                               # uppercase
    "zz32f6553de1d7a2f78c9e313f379e81bf9ee725",                               # non-hex
])
def test_critical1_malformed_shas_are_refused(bad):
    with pytest.raises(vr.VerificationError):
        vr.validate_trust_sha(bad)


def test_critical1_a_genuine_immutable_sha_is_accepted():
    assert vr.validate_trust_sha(THIRD_SHA) == THIRD_SHA


def test_critical1_expected_identity_terminates_in_the_immutable_sha():
    identity = vr.build_expected_identity(THIRD_SHA)
    assert identity.endswith("@" + THIRD_SHA)
    assert "refs/heads" not in identity
    assert identity == (
        "https://github.com/VANTA2026/ascend-release-trust/"
        ".github/workflows/build-and-attest-backend.yml@" + THIRD_SHA
    )


def test_critical1_identity_cannot_be_built_from_a_branch():
    for mutable in ("main", "refs/heads/main", "v1"):
        with pytest.raises(vr.VerificationError):
            vr.build_expected_identity(mutable)


def test_critical1_the_release_signer_sha_is_a_required_parameter():
    """The signer SHA is release-specific: there is no default, and no repository-head fallback."""
    import inspect

    sig = inspect.signature(vr.verify_release)
    assert sig.parameters["trust_sha"].default is inspect.Parameter.empty
    source = Path(vr.__file__).read_text()
    assert "refs/heads/main" not in source.split('"""', 2)[2], "no branch may appear in executable code"


# ---------------------------------------------------------------- CRITICAL-2: executable binding


def _executable_code() -> str:
    """Module source with docstrings and comments stripped.

    The module deliberately *describes* the old broken grep in its docstring — documenting a defect
    is not committing one — so these checks must look at executable code only.
    """
    import io
    import tokenize

    src = Path(vr.__file__).read_text()
    drop: set[int] = set()
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            drop.add(tok.start[0])
        elif tok.type == tokenize.STRING:
            stripped = tok.line.lstrip()
            if stripped[:3] in ('"""', "'''"):
                drop.update(range(tok.start[0], tok.end[0] + 1))
    return "\n".join(ln for i, ln in enumerate(src.splitlines(), 1) if i not in drop)


def test_critical2_no_output_grep_is_used_as_a_control():
    """The old anchor grepped cosign stdout. cosign prints only 'Verified OK', so it never failed."""
    code = _executable_code()
    assert "grep" not in code, "executable code must not grep tool output"
    assert "job_workflow_ref" not in code, "job_workflow_ref must not be a parsed-output control"
    assert "completed.returncode != 0" in code, "cosign's EXIT STATUS must be the control"


def test_critical2_cosign_stdout_is_never_parsed_for_a_verdict():
    """openssl stdout IS parsed (to read the certificate); cosign's stdout must never be."""
    code = _executable_code()
    assert "completed.stdout" not in code, "a verdict must never be derived from cosign stdout"
    assert "completed.returncode" in code, "the cosign verdict must come from its exit status"


def test_critical2_forbidden_flags_are_refused():
    for flag in vr.FORBIDDEN_COSIGN_FLAGS:
        with pytest.raises(vr.VerificationError, match="refusing to run cosign"):
            vr._run_cosign("/usr/bin/true", ["verify-blob", flag])


def test_critical2_offline_flag_is_forbidden_because_cosign_v3_removed_it():
    assert "--offline" in vr.FORBIDDEN_COSIGN_FLAGS


def test_critical2_regexp_identity_flags_are_forbidden():
    assert "--certificate-identity-regexp" in vr.FORBIDDEN_COSIGN_FLAGS
    assert "--certificate-oidc-issuer-regexp" in vr.FORBIDDEN_COSIGN_FLAGS


def test_critical2_tlog_and_sct_bypasses_are_forbidden():
    assert "--insecure-ignore-tlog" in vr.FORBIDDEN_COSIGN_FLAGS
    assert "--insecure-ignore-sct" in vr.FORBIDDEN_COSIGN_FLAGS


def test_cosign_must_be_an_absolute_path():
    with pytest.raises(vr.VerificationError, match="absolute path"):
        vr._run_cosign("cosign", ["version"])


# ---------------------------------------------------------------- repository semantics


def test_source_repository_constant_is_the_caller_not_the_trust_repo():
    """OID 1.12 records the SOURCE repo. Passing the trust repo refuses a genuine release."""
    assert vr.SOURCE_REPOSITORY == "VANTA2026/ASCEND-OS"
    assert vr.TRUST_REPOSITORY == "VANTA2026/ascend-release-trust"
    assert vr.SOURCE_REPOSITORY != vr.TRUST_REPOSITORY


# ---------------------------------------------------------------- trusted root


def test_missing_trusted_root_refuses(tmp_path):
    with pytest.raises(vr.VerificationError, match="trusted root material is missing"):
        vr.verify_release(tmp_path, THIRD_SHA, tmp_path / "absent.json", "/usr/bin/true")


def test_empty_trusted_root_refuses(tmp_path):
    root = tmp_path / "root.json"; root.write_text("")
    with pytest.raises(vr.VerificationError, match="empty"):
        vr.verify_release(tmp_path, THIRD_SHA, root, "/usr/bin/true")


def test_malformed_trusted_root_refuses(tmp_path):
    root = tmp_path / "root.json"; root.write_text("{not json")
    with pytest.raises(vr.VerificationError, match="not valid JSON"):
        vr.verify_release(tmp_path, THIRD_SHA, root, "/usr/bin/true")


# ---------------------------------------------------------------- against the real evidence


@requires_evidence
def test_preserved_third_run_verifies_with_its_own_signer_sha():
    result = vr.verify_release(EVIDENCE, THIRD_SHA, TRUSTED_ROOT, str(COSIGN))
    assert result.ok
    assert len(result.objects) == 6
    assert result.identity.endswith("@" + THIRD_SHA)
    for name, info in result.objects.items():
        assert info["verified"], name
        assert info["rekor_log_index"], f"{name} has no Rekor inclusion evidence"


@requires_evidence
def test_preserved_third_run_refuses_a_branch_identity():
    with pytest.raises(vr.VerificationError):
        vr.verify_release(EVIDENCE, "refs/heads/main", TRUSTED_ROOT, str(COSIGN))


@requires_evidence
def test_preserved_third_run_refuses_a_one_character_wrong_sha():
    wrong = "e" + THIRD_SHA[1:]
    assert len(wrong) == 40 and wrong != THIRD_SHA
    with pytest.raises(vr.VerificationError, match="cosign refused"):
        vr.verify_release(EVIDENCE, wrong, TRUSTED_ROOT, str(COSIGN))


@requires_evidence
def test_preserved_third_run_refuses_the_wrong_source_repository():
    with pytest.raises(vr.VerificationError, match="cosign refused"):
        vr.verify_release(EVIDENCE, THIRD_SHA, TRUSTED_ROOT, str(COSIGN),
                          source_repository="VANTA2026/ascend-release-trust")


@requires_evidence
def test_preserved_third_run_refuses_the_wrong_issuer():
    with pytest.raises(vr.VerificationError, match="cosign refused"):
        vr.verify_release(EVIDENCE, THIRD_SHA, TRUSTED_ROOT, str(COSIGN),
                          issuer="https://accounts.google.com")


@requires_evidence
@pytest.mark.parametrize("target", [
    "ascend-backend-source.tar.gz",
    "ascend-wheelhouse-macos-arm64.tar.gz",
    "requirements.macos-arm64-py311.lock.txt",
    "ascend-wheelhouse-policy-manifest.json",
    "ascend-backend-source-manifest.json",
])
def test_preserved_third_run_refuses_a_tampered_artifact(tmp_path, target):
    for f in EVIDENCE.iterdir():
        (tmp_path / f.name).write_bytes(f.read_bytes())
    with (tmp_path / target).open("ab") as fh:
        fh.write(b"x")
    with pytest.raises(vr.VerificationError):
        vr.verify_release(tmp_path, THIRD_SHA, TRUSTED_ROOT, str(COSIGN))


@requires_evidence
def test_preserved_third_run_refuses_a_tampered_bundle(tmp_path):
    for f in EVIDENCE.iterdir():
        (tmp_path / f.name).write_bytes(f.read_bytes())
    with (tmp_path / "ascend-backend-source.tar.gz.cosign.bundle").open("ab") as fh:
        fh.write(b"x")
    with pytest.raises(vr.VerificationError):
        vr.verify_release(tmp_path, THIRD_SHA, TRUSTED_ROOT, str(COSIGN))


@requires_evidence
def test_a_missing_object_or_bundle_refuses(tmp_path):
    for f in EVIDENCE.iterdir():
        (tmp_path / f.name).write_bytes(f.read_bytes())
    (tmp_path / "requirements.macos-arm64-py311.lock.txt.cosign.bundle").unlink()
    with pytest.raises(vr.VerificationError, match="bundle is missing"):
        vr.verify_release(tmp_path, THIRD_SHA, TRUSTED_ROOT, str(COSIGN))


@requires_evidence
def test_cold_cache_offline_verification_succeeds(tmp_path):
    """Empty HOME, no warmed Sigstore cache, network blackholed."""
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin",
           "http_proxy": "http://127.0.0.1:1", "https_proxy": "http://127.0.0.1:1",
           "ALL_PROXY": "http://127.0.0.1:1"}
    completed = subprocess.run(
        [sys.executable, str(Path(vr.__file__)), "--evidence", str(EVIDENCE),
         "--trust-sha", THIRD_SHA, "--trusted-root", str(TRUSTED_ROOT), "--cosign", str(COSIGN)],
        env=env, capture_output=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")[:400]
    assert b"verified_objects=6/6" in completed.stdout


@requires_evidence
def test_the_cli_returns_nonzero_on_refusal(tmp_path):
    completed = subprocess.run(
        [sys.executable, str(Path(vr.__file__)), "--evidence", str(EVIDENCE),
         "--trust-sha", "refs/heads/main", "--trusted-root", str(TRUSTED_ROOT), "--cosign", str(COSIGN)],
        capture_output=True, check=False,
    )
    assert completed.returncode != 0
    assert b"REFUSED" in completed.stderr


@requires_evidence
def test_provenance_digest_mismatch_refuses(tmp_path):
    for f in EVIDENCE.iterdir():
        (tmp_path / f.name).write_bytes(f.read_bytes())
    doc = json.loads((tmp_path / "provenance-metadata.json").read_text())
    doc["signed_objects"]["ascend-backend-source.tar.gz"] = "0" * 64
    (tmp_path / "provenance-metadata.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    with pytest.raises(vr.VerificationError):
        vr.verify_release(tmp_path, THIRD_SHA, TRUSTED_ROOT, str(COSIGN))
