"""The signed artifact must be the canonical encoding of its own verified content.

Content equality alone is insufficient: gzip tolerates trailing bytes and tar ignores them, so an
attacker controlling both build runners could append arbitrary data to an artifact, satisfy an
extract-and-compare-the-manifest check, and have the appended data signed. This was found by
adversarial testing of an earlier revision, which accepted exactly that.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import attest
import deterministic_archive as da


def _tree(root: Path) -> Path:
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "mod.py").write_text("x = 1\n")
    (root / "README.md").write_text("# hi\n")
    return root


def test_canonical_check_accepts_an_untouched_artifact(tmp_path):
    root = _tree(tmp_path / "t")
    archive = tmp_path / "a.tar.gz"
    da.write_deterministic_targz(root, archive)
    attest._require_canonical(archive, root, "test artifact")  # must not raise


def test_appended_bytes_are_refused_even_though_content_is_unchanged(tmp_path):
    root = _tree(tmp_path / "t")
    archive = tmp_path / "a.tar.gz"
    da.write_deterministic_targz(root, archive)
    with archive.open("ab") as fh:
        fh.write(b"smuggled trailer")
    with pytest.raises(attest.AttestationError, match="canonical encoding"):
        attest._require_canonical(archive, root, "test artifact")


def test_a_recompressed_artifact_is_refused(tmp_path):
    """Same members, different encoding: still not the canonical bytes."""
    import gzip
    import io
    import tarfile

    root = _tree(tmp_path / "t")
    archive = tmp_path / "a.tar.gz"
    da.write_deterministic_targz(root, archive)

    raw = gzip.decompress(archive.read_bytes())
    repacked = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=repacked, compresslevel=1, mtime=0) as gz:
        gz.write(raw)
    archive.write_bytes(repacked.getvalue())
    with pytest.raises(attest.AttestationError, match="canonical encoding"):
        attest._require_canonical(archive, root, "test artifact")


def test_env_helper_requires_what_it_says_it_requires(monkeypatch):
    monkeypatch.delenv("ASCEND_TEST_VAR", raising=False)
    with pytest.raises(attest.AttestationError, match="ASCEND_TEST_VAR"):
        attest._env("ASCEND_TEST_VAR")
    assert attest._env("ASCEND_TEST_VAR", required=False, default="fallback") == "fallback"


def test_the_six_signed_object_names_are_fixed():
    names = {
        attest.SOURCE_ARCHIVE,
        attest.SOURCE_MANIFEST,
        attest.WHEELHOUSE_ARCHIVE,
        attest.WHEELHOUSE_POLICY_MANIFEST,
        attest.LOCKFILE_NAME,
        attest.PROVENANCE_NAME,
    }
    assert len(names) == 6
    assert attest.LOCKFILE_NAME == "requirements.macos-arm64-py311.lock.txt"
