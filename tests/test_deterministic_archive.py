"""The release archive writer must be a function of file contents alone.

Two independent build passes are compared byte-for-byte, so anything that varies between passes —
which `tar` implementation is on PATH, the clock, the umask, directory iteration order — must not
reach the artifact. These tests pin that property, and in particular prove that a GNU/BSD `tar`
difference cannot change the artifact bytes, because no `tar` binary is consulted at all.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import stat
import tarfile
from pathlib import Path

import pytest

import deterministic_archive as da


def _tree(root: Path) -> Path:
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("x = 1\n")
    (root / "pkg" / "mod.py").write_text("def f():\n    return 2\n")
    (root / "README.md").write_text("# hi\n")
    script = root / "run.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o755)
    return root


def _digest(root: Path, out: Path) -> str:
    return da.write_deterministic_targz(root, out)


def test_same_tree_produces_identical_bytes(tmp_path):
    a, b = _tree(tmp_path / "a"), _tree(tmp_path / "b")
    da_a = _digest(a, tmp_path / "a.tar.gz")
    da_b = _digest(b, tmp_path / "b.tar.gz")
    assert da_a == da_b
    assert (tmp_path / "a.tar.gz").read_bytes() == (tmp_path / "b.tar.gz").read_bytes()


def test_repeated_runs_are_byte_identical(tmp_path):
    root = _tree(tmp_path / "t")
    first = _digest(root, tmp_path / "1.tar.gz")
    second = _digest(root, tmp_path / "2.tar.gz")
    assert first == second


def test_mtime_and_mode_noise_do_not_change_the_artifact(tmp_path):
    a, b = _tree(tmp_path / "a"), _tree(tmp_path / "b")
    # Give b wildly different timestamps and a different (still non-executable) permission set.
    for path in sorted(b.rglob("*")):
        os.utime(path, (10_000_000, 10_000_000))
    (b / "README.md").chmod(0o600)
    assert _digest(a, tmp_path / "a.tgz") == _digest(b, tmp_path / "b.tgz")


def test_no_tar_binary_is_required(tmp_path, monkeypatch):
    """With PATH emptied there is no `tar` at all; the artifact must be unchanged."""
    root = _tree(tmp_path / "t")
    expected = _digest(root, tmp_path / "ref.tar.gz")
    monkeypatch.setenv("PATH", "")
    assert _digest(root, tmp_path / "nopath.tar.gz") == expected


def test_a_sabotaged_tar_and_gtar_on_path_cannot_change_the_artifact(tmp_path, monkeypatch):
    """GNU vs BSD tar is the exact ambiguity this writer exists to remove.

    Put executables named `tar` and `gtar` first on PATH that would corrupt any archive they were
    asked to build. If the writer shelled out, the bytes would change; it must not.
    """
    root = _tree(tmp_path / "t")
    expected = _digest(root, tmp_path / "ref.tar.gz")

    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    for name in ("tar", "gtar"):
        binary = fake_bin / name
        binary.write_text("#!/bin/sh\necho SABOTAGED\nexit 0\n")
        binary.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ.get('PATH', '')}")

    assert _digest(root, tmp_path / "sabotaged.tar.gz") == expected
    assert b"SABOTAGED" not in (tmp_path / "sabotaged.tar.gz").read_bytes()


def test_archive_metadata_is_fully_pinned(tmp_path):
    root = _tree(tmp_path / "t")
    _digest(root, tmp_path / "t.tar.gz")
    with tarfile.open(tmp_path / "t.tar.gz", "r:gz") as tar:
        members = tar.getmembers()
        assert members, "archive must not be empty"
        for member in members:
            assert member.mtime == da.FIXED_MTIME
            assert member.uid == 0 and member.gid == 0
            assert member.uname == "" and member.gname == ""
        modes = {m.name: m.mode for m in members if m.isfile()}
        assert modes["./run.sh"] == 0o755, "executable bit is preserved by policy"
        assert modes["./README.md"] == 0o644, "non-executable files are normalised to 0644"


def test_member_order_is_sorted_and_stable(tmp_path):
    root = _tree(tmp_path / "t")
    _digest(root, tmp_path / "t.tar.gz")
    with tarfile.open(tmp_path / "t.tar.gz", "r:gz") as tar:
        names = [m.name for m in tar.getmembers()]
    assert names == sorted(names, key=lambda n: n.encode("utf-8"))


def test_gzip_header_carries_no_timestamp_or_filename(tmp_path):
    root = _tree(tmp_path / "t")
    _digest(root, tmp_path / "t.tar.gz")
    raw = (tmp_path / "t.tar.gz").read_bytes()
    # RFC 1952: bytes 4..8 are MTIME; FNAME is flag bit 3 of byte 3.
    assert raw[4:8] == b"\x00\x00\x00\x00", "gzip mtime must be zero"
    assert not (raw[3] & 0x08), "gzip must not record an original filename"


def test_archive_uses_ustar_with_no_extension_records(tmp_path):
    root = _tree(tmp_path / "t")
    _digest(root, tmp_path / "t.tar.gz")
    with gzip.open(tmp_path / "t.tar.gz", "rb") as fh:
        payload = fh.read()
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tar:
        for member in tar.getmembers():
            assert member.type not in (tarfile.XHDTYPE, tarfile.XGLTYPE), "no PAX extension records"


def test_bytecode_and_vcs_directories_are_excluded(tmp_path):
    root = _tree(tmp_path / "t")
    (root / "pkg" / "__pycache__").mkdir()
    (root / "pkg" / "__pycache__" / "mod.cpython-311.pyc").write_bytes(b"\x00\x01")
    (root / "pkg" / "stray.pyc").write_bytes(b"\x00\x02")
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    _digest(root, tmp_path / "t.tar.gz")
    with tarfile.open(tmp_path / "t.tar.gz", "r:gz") as tar:
        names = [m.name for m in tar.getmembers()]
    assert not [n for n in names if "__pycache__" in n or n.endswith(".pyc") or ".git" in n]


def _walk_yielding(root: Path, filenames: list[str]):
    """Return an os.walk stand-in that reports `filenames` as the contents of `root`.

    macOS volumes are case-insensitive and normalisation-collapsing, so a colliding pair usually
    cannot be created on disk here. The collision guards still have to be proven — a guard that
    never fires under test is indistinguishable from one that does not work — so drive the walk
    directly and exercise the refusal on any filesystem.
    """

    def fake_walk(top, followlinks=False):
        yield str(root), [], list(filenames)

    return fake_walk


def test_case_collision_is_refused(tmp_path, monkeypatch):
    root = tmp_path / "t"
    root.mkdir()
    (root / "Thing.py").write_text("a\n")  # one real file; both spellings resolve to it on macOS
    monkeypatch.setattr(da.os, "walk", _walk_yielding(root, ["Thing.py", "thing.py"]))
    with pytest.raises(da.ArchiveError, match="case collision"):
        da.collect_entries(root)


def test_collision_guards_do_not_fire_on_an_ordinary_tree(tmp_path):
    """Negative control: the guards must not reject a normal tree."""
    root = _tree(tmp_path / "t")
    (root / "pkg" / "Thing.py").write_text("a\n")
    (root / "pkg" / "other.py").write_text("b\n")
    assert len(da.collect_entries(root)) > 0


def test_unicode_normalisation_collision_is_refused(tmp_path, monkeypatch):
    import unicodedata

    root = tmp_path / "t"
    root.mkdir()
    # Build the two forms programmatically: a source literal would be normalised by the editor.
    nfc = unicodedata.normalize("NFC", "caf\u00e9.py")
    nfd = unicodedata.normalize("NFD", "caf\u00e9.py")
    assert nfc != nfd, "the two Unicode forms must actually differ"
    (root / nfc).write_text("a\n")
    monkeypatch.setattr(da.os, "walk", _walk_yielding(root, [nfd, nfc]))
    with pytest.raises(da.ArchiveError, match="normalisation collision"):
        da.collect_entries(root)


def test_symlink_escaping_the_root_is_refused(tmp_path):
    """A RELATIVE target that climbs out of the tree. It must hit the escape guard specifically —
    an absolute target is refused earlier, for a different reason (see the reproducibility test)."""
    root = tmp_path / "t"
    root.mkdir()
    (root / "ok.py").write_text("x\n")
    os.symlink("../outside.txt", str(root / "escape"))
    with pytest.raises(da.ArchiveError, match="escapes the archive root"):
        da.collect_entries(root)


def test_internal_symlink_is_preserved(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "real.py").write_text("x\n")
    os.symlink("real.py", str(root / "alias.py"))
    _digest(root, tmp_path / "t.tar.gz")
    with tarfile.open(tmp_path / "t.tar.gz", "r:gz") as tar:
        link = tar.getmember("./alias.py")
    assert link.issym() and link.linkname == "real.py"


def test_manifest_is_deterministic_and_content_addressed(tmp_path):
    a, b = _tree(tmp_path / "a"), _tree(tmp_path / "b")
    assert da.build_manifest(a) == da.build_manifest(b)
    manifest = da.build_manifest(a)
    assert manifest["entries"]["README.md"]["sha256"] == hashlib.sha256(b"# hi\n").hexdigest()
    assert manifest["entry_count"] == len(manifest["entries"])


def test_content_change_changes_the_artifact(tmp_path):
    """The writer normalises metadata — it must still be sensitive to actual content."""
    a, b = _tree(tmp_path / "a"), _tree(tmp_path / "b")
    (b / "README.md").write_text("# hi there\n")
    assert _digest(a, tmp_path / "a.tgz") != _digest(b, tmp_path / "b.tgz")


def test_non_regular_entries_are_refused(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "ok.py").write_text("x\n")
    os.mkfifo(str(root / "pipe"))
    with pytest.raises(da.ArchiveError, match="non-regular"):
        da.collect_entries(root)


def test_executable_policy_is_owner_execute_only(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    plain, exe = root / "a.py", root / "b.sh"
    plain.write_text("x\n")
    exe.write_text("y\n")
    exe.chmod(0o700)
    modes = {e["path"]: e["mode"] for e in da.collect_entries(root) if e["type"] == "file"}
    assert modes["a.py"] == 0o644
    assert modes["b.sh"] == 0o755
    assert stat.S_IMODE(modes["b.sh"]) == 0o755


# --------------------------------------------------------------------------------------------
# regressions for defects found by adversarial review of this module


def test_absolute_symlink_target_is_refused(tmp_path):
    """An absolute target embeds the build root in the artifact.

    Two independent passes rooted at different directories would then produce different bytes,
    silently defeating the byte-for-byte comparison the whole release gate rests on. The target
    stays inside the tree, so the escape guard does not catch it — this needs its own refusal.
    """
    root = tmp_path / "t"
    root.mkdir()
    (root / "real.txt").write_text("x\n")
    os.symlink(str(root / "real.txt"), str(root / "alias"))  # absolute, but in-tree
    with pytest.raises(da.ArchiveError, match="absolute symlink target"):
        da.collect_entries(root)


def test_two_passes_at_different_roots_agree(tmp_path):
    """The property the absolute-symlink refusal exists to protect."""
    digests = []
    for label in ("passA", "passB_longer_name"):
        root = tmp_path / label
        root.mkdir()
        (root / "real.txt").write_text("x\n")
        os.symlink("real.txt", str(root / "alias"))  # relative target
        digests.append(da.write_deterministic_targz(root, tmp_path / f"{label}.tar.gz"))
    assert digests[0] == digests[1], "artifact bytes must not depend on the build directory"


def test_directory_case_collision_is_refused(tmp_path, monkeypatch):
    """`Foo/` and `foo/` hold distinct members on a case-sensitive volume but merge into one
    directory when extracted on a case-insensitive one, silently changing the tree."""
    root = tmp_path / "t"
    (root / "Foo").mkdir(parents=True)
    (root / "Foo" / "alpha.py").write_text("a\n")

    real_walk = os.walk

    def fake_walk(top, followlinks=False):
        # Report the same on-disk directory under two spellings, as a case-sensitive volume would.
        yield str(root), ["Foo", "foo"], []
        yield str(root / "Foo"), [], ["alpha.py"]
        yield str(root / "foo"), [], ["beta.py"]

    monkeypatch.setattr(da.os, "walk", fake_walk)
    with pytest.raises(da.ArchiveError, match="case collision"):
        da.collect_entries(root)
