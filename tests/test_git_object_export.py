"""Exact Git-object export must be faithful, allowlisted, and unforgeable by checkout behaviour."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import git_object_export as ge


def _run(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout


def test_exports_exact_blob_bytes(git_repo: Path, head_sha: str, tmp_path: Path):
    dest = tmp_path / "export"
    entries = ge.export_approved_paths(git_repo, head_sha, ["src", "lock.txt"], dest)
    assert (dest / "src" / "app.py").read_bytes() == b"x = 1\n"
    assert {e.path for e in entries} == {"src/app.py", "src/notes.txt", "lock.txt"}


def test_only_approved_paths_are_exported(git_repo: Path, head_sha: str, tmp_path: Path):
    """Allowlist selection, not checkout-everything-then-prune: nothing unapproved can survive."""
    dest = tmp_path / "export"
    ge.export_approved_paths(git_repo, head_sha, ["src"], dest)
    assert (dest / "src" / "app.py").exists()
    assert not (dest / "excluded").exists()
    assert not (dest / "lock.txt").exists()


def test_a_file_directly_beneath_a_partially_retained_parent_is_not_swept_in(
    git_repo: Path, head_sha: str, tmp_path: Path
):
    """A pruning implementation that filters directories but not sibling files leaks this file."""
    _run(git_repo, "config", "user.email", "t@example.invalid")
    (git_repo / "src" / "STRAY.txt").write_text("leak\n")
    _run(git_repo, "add", "-A")
    _run(git_repo, "commit", "-q", "-m", "add stray")
    sha = _run(git_repo, "rev-parse", "HEAD").strip()

    dest = tmp_path / "export"
    ge.export_approved_paths(git_repo, sha, ["src/app.py"], dest)
    assert (dest / "src" / "app.py").exists()
    assert not (dest / "src" / "STRAY.txt").exists()
    assert not (dest / "src" / "notes.txt").exists()


def test_an_approved_path_matching_nothing_is_refused(git_repo: Path, head_sha: str):
    with pytest.raises(ge.ExportError, match="matched nothing"):
        ge.list_approved_entries(git_repo, head_sha, ["src", "does/not/exist"])


def test_gitattributes_text_conversion_cannot_alter_exported_bytes(git_repo: Path, tmp_path: Path):
    """A checkout would apply eol conversion here; cat-file does not. This is the whole point."""
    (git_repo / ".gitattributes").write_text("*.py text eol=crlf\n")
    (git_repo / "src" / "app.py").write_text("x = 1\n")
    _run(git_repo, "add", "-A")
    _run(git_repo, "commit", "-q", "-m", "crlf attribute")
    sha = _run(git_repo, "rev-parse", "HEAD").strip()

    dest = tmp_path / "export"
    ge.export_approved_paths(git_repo, sha, ["src/app.py"], dest)
    assert (dest / "src" / "app.py").read_bytes() == b"x = 1\n", "exported bytes must be the stored blob"

    worktree = tmp_path / "worktree"
    _run(git_repo, "worktree", "add", "--detach", str(worktree), sha)
    checked_out = (worktree / "src" / "app.py").read_bytes()
    assert checked_out == b"x = 1\r\n", "checkout is expected to transform; that is why it is not used"
    assert checked_out != (dest / "src" / "app.py").read_bytes()


def test_rev_must_be_a_full_object_id(git_repo: Path):
    with pytest.raises(ge.ExportError, match="full object id"):
        ge.list_approved_entries(git_repo, "HEAD", ["src"])
    with pytest.raises(ge.ExportError, match="full object id"):
        ge.list_approved_entries(git_repo, "50cbe17", ["src"])


def test_absolute_or_traversing_approved_paths_are_refused(git_repo: Path, head_sha: str):
    for bad in ["/etc/passwd", "../outside", "src/../../x"]:
        with pytest.raises(ge.ExportError, match="repo-relative"):
            ge.list_approved_entries(git_repo, head_sha, [bad])


def test_submodule_gitlink_is_refused(git_repo: Path, tmp_path: Path):
    """A gitlink names a commit in another repository; its content is not in this object database."""
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["git", "-C", str(other), "init", "-q", "-b", "main"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(other), "config", "user.email", "t@example.invalid"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(other), "config", "user.name", "T"], check=True, capture_output=True)
    (other / "f.txt").write_text("hi\n")
    subprocess.run(["git", "-C", str(other), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(other), "commit", "-q", "-m", "x"], check=True, capture_output=True)
    sub_sha = subprocess.run(
        ["git", "-C", str(other), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    # Write a gitlink entry directly into the index, avoiding submodule config entirely.
    subprocess.run(
        ["git", "-C", str(git_repo), "update-index", "--add", "--cacheinfo", f"160000,{sub_sha},vendor"],
        check=True, capture_output=True,
    )
    _run(git_repo, "commit", "-q", "-m", "gitlink")
    sha = _run(git_repo, "rev-parse", "HEAD").strip()
    with pytest.raises(ge.ExportError, match="submodule/gitlink"):
        ge.list_approved_entries(git_repo, sha, ["vendor"])


def test_absolute_symlink_is_refused(git_repo: Path, tmp_path: Path):
    import os

    os.symlink("/etc/passwd", str(git_repo / "src" / "evil"))
    _run(git_repo, "add", "-A")
    _run(git_repo, "commit", "-q", "-m", "abs symlink")
    sha = _run(git_repo, "rev-parse", "HEAD").strip()
    with pytest.raises(ge.ExportError, match="absolute symlink target"):
        ge.export_approved_paths(git_repo, sha, ["src"], tmp_path / "export")


def test_symlink_escaping_the_export_root_is_refused(git_repo: Path, tmp_path: Path):
    import os

    os.symlink("../../outside.txt", str(git_repo / "src" / "escape"))
    _run(git_repo, "add", "-A")
    _run(git_repo, "commit", "-q", "-m", "escaping symlink")
    sha = _run(git_repo, "rev-parse", "HEAD").strip()
    with pytest.raises(ge.ExportError, match="escapes the export root"):
        ge.export_approved_paths(git_repo, sha, ["src"], tmp_path / "export")


def test_export_destination_must_be_empty(git_repo: Path, head_sha: str, tmp_path: Path):
    dest = tmp_path / "export"
    dest.mkdir()
    (dest / "preexisting").write_text("x")
    with pytest.raises(ge.ExportError, match="must be empty"):
        ge.export_approved_paths(git_repo, head_sha, ["src"], dest)


def test_executable_bit_is_preserved_from_the_git_mode(git_repo: Path, tmp_path: Path):
    import os
    import stat

    script = git_repo / "src" / "run.sh"
    script.write_text("#!/bin/sh\n")
    os.chmod(script, 0o755)
    _run(git_repo, "add", "-A")
    _run(git_repo, "commit", "-q", "-m", "exec")
    sha = _run(git_repo, "rev-parse", "HEAD").strip()
    dest = tmp_path / "export"
    ge.export_approved_paths(git_repo, sha, ["src"], dest)
    assert stat.S_IMODE((dest / "src" / "run.sh").stat().st_mode) == 0o755
    assert stat.S_IMODE((dest / "src" / "app.py").stat().st_mode) == 0o644


def test_read_blob_refuses_a_malformed_object_id(git_repo: Path):
    with pytest.raises(ge.ExportError, match="malformed object id"):
        ge.read_blob(git_repo, "not-an-oid; rm -rf /")
