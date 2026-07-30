"""Export exact Git blob bytes for an approved path set.

A `git checkout` (or `git worktree add`) is not a faithful reproduction of what a commit contains.
Checkout runs clean/smudge filters, `.gitattributes` `text`/`eol` conversion, and on some platforms
normalises names — so the bytes on disk can differ from the bytes Git stores. Signing a worktree
therefore signs a *transformation of* the approved commit, not the approved commit.

This module reads blobs straight out of the object database with `git cat-file`, which applies no
filters at all, and selects exactly the approved paths rather than checking out everything and
pruning afterwards. Pruning is the weaker construction: it is a denylist wearing an allowlist's
clothes, and anything the pruner forgets ships.

Trust-owned. Lives in the protected public trust repository; never imported from candidate code.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

__all__ = ["ExportError", "TreeEntry", "list_approved_entries", "export_approved_paths", "read_blob"]

MODE_FILE = "100644"
MODE_EXEC = "100755"
MODE_SYMLINK = "120000"
MODE_GITLINK = "160000"
_ALLOWED_MODES = {MODE_FILE, MODE_EXEC, MODE_SYMLINK}


class ExportError(RuntimeError):
    """Raised when a commit cannot be exported faithfully."""


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    object_id: str
    path: str  # repository-relative, POSIX, exactly as Git stores it

    @property
    def is_symlink(self) -> bool:
        return self.mode == MODE_SYMLINK

    @property
    def is_executable(self) -> bool:
        return self.mode == MODE_EXEC


def _git(repo: str | os.PathLike[str], *args: str, binary: bool = False):
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ExportError(f"git {' '.join(args[:3])} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout if binary else result.stdout.decode("utf-8")


def resolve_commit(repo: str | os.PathLike[str], rev: str) -> tuple[str, str]:
    """Confirm ``rev`` names an existing COMMIT object and return ``(commit_sha, tree_sha)``.

    A missing object, a shallow clone that lacks it, or an id that resolves to something other than
    a commit must fail closed here rather than surface later as an empty export.
    """
    if not _is_hex_oid(rev):
        raise ExportError(f"commit id must be a full 40-hex object id, got {rev!r:.60}")
    kind = _git(repo, "cat-file", "-t", rev).strip()
    if kind != "commit":
        raise ExportError(f"{rev} is a {kind!r} object, expected a commit")
    resolved = _git(repo, "rev-parse", f"{rev}^{{commit}}").strip()
    if resolved != rev:
        raise ExportError(f"{rev} resolved to a different commit {resolved}")
    tree = _git(repo, "rev-parse", f"{rev}^{{tree}}").strip()
    if not _is_hex_oid(tree):
        raise ExportError(f"{rev} has no resolvable tree object")
    return resolved, tree


def read_blob(repo: str | os.PathLike[str], object_id: str) -> bytes:
    """Return a blob's exact stored bytes. No filters, no EOL conversion."""
    if not _is_hex_oid(object_id):
        raise ExportError(f"refusing a malformed object id: {object_id!r}")
    return _git(repo, "cat-file", "blob", object_id, binary=True)


def _is_hex_oid(value: str) -> bool:
    return len(value) in (40, 64) and all(c in "0123456789abcdef" for c in value)


def list_approved_entries(
    repo: str | os.PathLike[str],
    rev: str,
    approved_paths: list[str],
) -> list[TreeEntry]:
    """List every blob under ``approved_paths`` at ``rev``, refusing anything unrepresentable.

    ``approved_paths`` is an allowlist of exact repository-relative paths (files or directories).
    Every one must match at least one entry; a silently-empty approved path means the release no
    longer contains something it is supposed to, and that must fail loudly.
    """
    if not _is_hex_oid(rev):
        raise ExportError(f"rev must be a full object id, got {rev!r}")
    if not approved_paths:
        raise ExportError("the approved path set is empty")
    for p in approved_paths:
        if p.startswith("/") or ".." in PurePosixPath(p).parts:
            raise ExportError(f"approved path must be repo-relative and free of '..': {p!r}")

    raw = _git(repo, "ls-tree", "-r", "-z", "--full-tree", rev, "--", *approved_paths, binary=True)
    entries: list[TreeEntry] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, _, path_bytes = record.partition(b"\t")
        try:
            path = path_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ExportError(f"path is not valid UTF-8: {path_bytes!r}") from exc
        mode, obj_type, object_id = meta.decode("utf-8").split()
        if mode == MODE_GITLINK or obj_type == "commit":
            raise ExportError(f"refusing a submodule/gitlink in the release tree: {path!r}")
        if mode not in _ALLOWED_MODES:
            raise ExportError(f"refusing an unsupported Git mode {mode} for {path!r}")
        if obj_type != "blob":
            raise ExportError(f"refusing a non-blob entry ({obj_type}) for {path!r}")
        entries.append(TreeEntry(mode=mode, object_id=object_id, path=path))

    covered = {e.path for e in entries}
    unmatched = [
        p for p in approved_paths
        if not any(c == p or c.startswith(p.rstrip("/") + "/") for c in covered)
    ]
    if unmatched:
        raise ExportError(f"approved paths matched nothing at {rev}: {unmatched}")

    entries.sort(key=lambda e: e.path.encode("utf-8"))
    return entries


def export_approved_paths(
    repo: str | os.PathLike[str],
    rev: str,
    approved_paths: list[str],
    destination: str | os.PathLike[str],
) -> list[TreeEntry]:
    """Materialise exact blob bytes for the approved path set under ``destination``."""
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise ExportError(f"export destination must be empty: {dest}")

    entries = list_approved_entries(repo, rev, approved_paths)
    dest_real = os.path.realpath(dest)

    for entry in entries:
        target = dest / entry.path
        # Defence in depth: Git paths cannot normally escape, but never write outside the export.
        if not os.path.realpath(target.parent).startswith(dest_real):
            raise ExportError(f"entry would escape the export root: {entry.path!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = read_blob(repo, entry.object_id)
        if entry.is_symlink:
            link_target = payload.decode("utf-8")
            if os.path.isabs(link_target):
                raise ExportError(f"absolute symlink target is not reproducible: {entry.path!r} -> {link_target!r}")
            resolved = os.path.realpath(os.path.join(os.path.dirname(str(target)), link_target))
            if not (resolved == dest_real or resolved.startswith(dest_real + os.sep)):
                raise ExportError(f"symlink escapes the export root: {entry.path!r} -> {link_target!r}")
            os.symlink(link_target, target)
        else:
            target.write_bytes(payload)
            os.chmod(target, 0o755 if entry.is_executable else 0o644)
    return entries


def _main(argv: list[str]) -> int:
    if len(argv) < 5:
        print("usage: git_object_export.py <repo> <rev> <destination> <approved-path>...", flush=True)
        return 2
    entries = export_approved_paths(argv[1], argv[2], argv[4:], argv[3])
    print(f"exported_entries={len(entries)}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    import sys

    raise SystemExit(_main(sys.argv))
