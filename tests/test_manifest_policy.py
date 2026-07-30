"""Digests must be measured, extraction must be safe, and passes must be compared by bytes."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

import deterministic_archive as da
import manifest_policy as mp


def _tree(root: Path) -> Path:
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "mod.py").write_text("x = 1\n")
    (root / "README.md").write_text("# hi\n")
    return root


def test_sha256_file_matches_hashlib(tmp_path):
    f = tmp_path / "f.bin"
    f.write_bytes(b"abc" * 10_000)
    assert mp.sha256_file(f) == hashlib.sha256(f.read_bytes()).hexdigest()


def test_verify_archive_against_manifest_accepts_a_faithful_pair(tmp_path):
    root = _tree(tmp_path / "t")
    archive = tmp_path / "a.tar.gz"
    manifest = tmp_path / "m.json"
    mp.write_manifest(root, manifest)
    da.write_deterministic_targz(root, archive)
    result = mp.verify_archive_against_manifest(archive, manifest, tmp_path / "wd")
    assert result["entry_count"] == 2


def test_a_modified_artifact_is_refused(tmp_path):
    root = _tree(tmp_path / "t")
    archive = tmp_path / "a.tar.gz"
    manifest = tmp_path / "m.json"
    mp.write_manifest(root, manifest)
    da.write_deterministic_targz(root, archive)
    (root / "README.md").write_text("# tampered\n")          # rebuild from a changed tree
    da.write_deterministic_targz(root, archive)
    with pytest.raises(mp.ManifestError, match="does not match the manifest"):
        mp.verify_archive_against_manifest(archive, manifest, tmp_path / "wd")


def test_an_unsigned_extra_file_in_the_archive_is_refused(tmp_path):
    root = _tree(tmp_path / "t")
    manifest = tmp_path / "m.json"
    mp.write_manifest(root, manifest)
    (root / "EXTRA.txt").write_text("smuggled\n")
    archive = tmp_path / "a.tar.gz"
    da.write_deterministic_targz(root, archive)
    with pytest.raises(mp.ManifestError, match="added="):
        mp.verify_archive_against_manifest(archive, manifest, tmp_path / "wd")


def test_a_missing_file_is_refused(tmp_path):
    root = _tree(tmp_path / "t")
    manifest = tmp_path / "m.json"
    mp.write_manifest(root, manifest)
    (root / "README.md").unlink()
    archive = tmp_path / "a.tar.gz"
    da.write_deterministic_targz(root, archive)
    with pytest.raises(mp.ManifestError, match="missing="):
        mp.verify_archive_against_manifest(archive, manifest, tmp_path / "wd")


# ---------------------------------------------------------------- safe extraction


def _tar_with(members: list[tarfile.TarInfo], payloads: dict[str, bytes], dest: Path) -> Path:
    with tarfile.open(dest, "w:gz") as tar:
        for info in members:
            data = payloads.get(info.name)
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return dest


def test_absolute_member_path_is_refused(tmp_path):
    info = tarfile.TarInfo("/etc/evil")
    info.size = 3
    archive = _tar_with([info], {"/etc/evil": b"bad"}, tmp_path / "a.tar.gz")
    with pytest.raises(mp.ManifestError, match="absolute path"):
        mp.safe_extract(archive, tmp_path / "out")


def test_traversing_member_path_is_refused(tmp_path):
    info = tarfile.TarInfo("../escape.txt")
    info.size = 3
    archive = _tar_with([info], {"../escape.txt": b"bad"}, tmp_path / "a.tar.gz")
    with pytest.raises(mp.ManifestError, match="escapes with"):
        mp.safe_extract(archive, tmp_path / "out")


def test_absolute_link_target_is_refused(tmp_path):
    info = tarfile.TarInfo("link")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    archive = _tar_with([info], {}, tmp_path / "a.tar.gz")
    with pytest.raises(mp.ManifestError, match="link target is absolute"):
        mp.safe_extract(archive, tmp_path / "out")


def test_escaping_link_target_is_refused(tmp_path):
    info = tarfile.TarInfo("dir/link")
    info.type = tarfile.SYMTYPE
    info.linkname = "../../outside"
    archive = _tar_with([info], {}, tmp_path / "a.tar.gz")
    with pytest.raises(mp.ManifestError, match="escapes the destination"):
        mp.safe_extract(archive, tmp_path / "out")


def test_non_regular_member_is_refused(tmp_path):
    info = tarfile.TarInfo("dev")
    info.type = tarfile.CHRTYPE
    archive = _tar_with([info], {}, tmp_path / "a.tar.gz")
    with pytest.raises(mp.ManifestError, match="non-regular member"):
        mp.safe_extract(archive, tmp_path / "out")


# ---------------------------------------------------------------- pass comparison


def test_agreeing_passes_are_accepted(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"identical")
    b.write_bytes(b"identical")
    comparison = mp.compare_passes("source", a, b)
    assert comparison.agree
    assert comparison.pass1_sha256 == hashlib.sha256(b"identical").hexdigest()


def test_disagreeing_passes_are_refused_by_measurement(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"pass one")
    b.write_bytes(b"pass two")
    with pytest.raises(mp.ManifestError, match="independent passes disagree"):
        mp.compare_passes("source", a, b)


def test_a_one_byte_difference_is_caught(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"x" * 1000)
    b.write_bytes(b"x" * 999 + b"y")
    with pytest.raises(mp.ManifestError, match="disagree"):
        mp.compare_passes("wheelhouse", a, b)


def test_a_missing_pass_artifact_is_refused(tmp_path):
    a = tmp_path / "a"
    a.write_bytes(b"x")
    with pytest.raises(mp.ManifestError, match="missing"):
        mp.compare_passes("source", a, tmp_path / "absent")


def test_reported_values_are_never_trusted_only_measured_bytes(tmp_path):
    """A build job could print anything; compare_passes reads the files instead."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"real content")
    b.write_bytes(b"DIFFERENT content")
    claimed = hashlib.sha256(b"real content").hexdigest()
    with pytest.raises(mp.ManifestError) as exc:
        mp.compare_passes("source", a, b)
    assert claimed in str(exc.value)                     # pass 1 measured honestly
    assert hashlib.sha256(b"DIFFERENT content").hexdigest() in str(exc.value)


def test_write_manifest_is_canonical_and_stable(tmp_path):
    a, b = _tree(tmp_path / "a"), _tree(tmp_path / "b")
    da_ = mp.write_manifest(a, tmp_path / "ma.json")
    db_ = mp.write_manifest(b, tmp_path / "mb.json")
    assert da_ == db_
    assert json.loads((tmp_path / "ma.json").read_text()) == json.loads((tmp_path / "mb.json").read_text())
