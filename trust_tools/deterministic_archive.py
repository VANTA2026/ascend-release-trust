"""Deterministic .tar.gz writer for ASCEND release artifacts.

Release artifacts are compared byte-for-byte across two independent build passes, so the archive
writer must be a *function of the file contents alone*. Shelling out to `tar` cannot provide that:
GNU tar and BSD tar disagree about extended headers, sparse-file encoding, the meaning of
``--format``, and which metadata they emit at all — and macOS ships BSD tar as ``tar`` while GNU tar
is ``gtar`` only if Homebrew installed it. A build that falls back from one to the other silently
changes the artifact bytes.

This module therefore writes the archive itself, with every varying field pinned:

===================  ========================================================================
path order           byte-wise sort of the NFC-normalised archive-relative path
Unicode path form    NFC; a tree containing two paths that differ only by normalisation, or
                     only by case, is REFUSED (macOS filesystems are typically case-insensitive
                     and normalisation-preserving, so such a tree cannot round-trip)
mtime                fixed FIXED_MTIME (0) for every member
uid / gid            0 / 0
uname / gname        empty strings
file mode            0o755 if the source file is executable by its owner, else 0o644;
                     directories 0o755; symlinks 0o777 (ignored by tar on extract)
archive format       USTAR — the narrowest common format, no PAX/GNU extension records
symlinks             stored as symlinks; the target must stay inside the tree
gzip                 mtime=0, no filename field, fixed compression level
===================  ========================================================================

Nothing here consults ``$PATH``, the clock, the environment, or the umask.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
import unicodedata
from pathlib import Path, PurePosixPath

__all__ = [
    "ArchiveError",
    "FIXED_MTIME",
    "GZIP_COMPRESS_LEVEL",
    "build_manifest",
    "collect_entries",
    "write_deterministic_targz",
]

FIXED_MTIME = 0
GZIP_COMPRESS_LEVEL = 9
DIR_MODE = 0o755
FILE_MODE = 0o644
EXEC_MODE = 0o755
SYMLINK_MODE = 0o777

# Directories that must never enter a release artifact. Bytecode is machine- and run-dependent and
# would break byte-for-byte agreement between passes; VCS metadata is not part of the runtime.
EXCLUDED_DIR_NAMES = frozenset({"__pycache__", ".git", ".pytest_cache", ".mypy_cache", ".ruff_cache"})
EXCLUDED_SUFFIXES = (".pyc", ".pyo")


class ArchiveError(RuntimeError):
    """Raised when a tree cannot be archived deterministically."""


def _normalise(rel: str) -> str:
    """Return the NFC form of an archive-relative POSIX path."""
    return unicodedata.normalize("NFC", rel)


def _is_excluded(rel_parts: tuple[str, ...], name: str) -> bool:
    if any(part in EXCLUDED_DIR_NAMES for part in rel_parts):
        return True
    if name in EXCLUDED_DIR_NAMES:
        return True
    return name.endswith(EXCLUDED_SUFFIXES)


def collect_entries(root: str | os.PathLike[str]) -> list[dict]:
    """Walk ``root`` and return sorted, normalised entry descriptors.

    Raises ``ArchiveError`` if the tree cannot round-trip on a case-insensitive or
    normalisation-sensitive filesystem, or if a symlink escapes the tree.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise ArchiveError(f"archive root is not a directory: {root_path}")

    entries: list[dict] = []
    seen_exact: dict[str, str] = {}
    seen_folded: dict[str, str] = {}

    def claim(rel: str, abs_path: str) -> None:
        """Reserve an archive-relative path, refusing anything that cannot round-trip.

        Two distinct on-disk paths that collide once normalised, or once case-folded, cannot both
        survive extraction on a typical macOS volume. Directories are checked too: ``Foo/`` and
        ``foo/`` hold distinct members on a case-sensitive volume but merge into one directory on
        extraction, silently changing the tree.
        """
        folded = rel.casefold()
        if rel in seen_exact:
            raise ArchiveError(f"Unicode normalisation collision: {seen_exact[rel]!r} and {abs_path!r} both normalise to {rel!r}")
        if folded in seen_folded:
            raise ArchiveError(f"case collision: {seen_folded[folded]!r} and {abs_path!r} differ only by case ({rel!r})")
        seen_exact[rel] = abs_path
        seen_folded[folded] = abs_path

    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIR_NAMES)
        rel_dir = os.path.relpath(dirpath, root_path)
        rel_parts = () if rel_dir == "." else tuple(rel_dir.split(os.sep))

        if rel_parts and not _is_excluded(rel_parts[:-1], rel_parts[-1]):
            rel = _normalise(PurePosixPath(*rel_parts).as_posix())
            claim(rel, dirpath)
            entries.append({"type": "dir", "path": rel})

        for name in sorted(filenames):
            if _is_excluded(rel_parts, name):
                continue
            abs_path = os.path.join(dirpath, name)
            rel = _normalise(PurePosixPath(*rel_parts, name).as_posix())
            claim(rel, abs_path)

            st = os.lstat(abs_path)
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(abs_path)
                # An absolute target embeds the build directory in the artifact, so two independent
                # passes rooted at different paths would produce different bytes. Refuse it: the
                # tree must describe itself relatively to be reproducible.
                if os.path.isabs(target):
                    raise ArchiveError(
                        f"absolute symlink target is not reproducible: {abs_path!r} -> {target!r}; "
                        "use a relative target"
                    )
                resolved = os.path.realpath(os.path.join(dirpath, target))
                if not (resolved == str(root_path) or resolved.startswith(str(root_path) + os.sep)):
                    raise ArchiveError(f"symlink escapes the archive root: {abs_path!r} -> {target!r}")
                entries.append({"type": "symlink", "path": rel, "target": target})
            elif stat.S_ISREG(st.st_mode):
                mode = EXEC_MODE if st.st_mode & stat.S_IXUSR else FILE_MODE
                entries.append({"type": "file", "path": rel, "mode": mode, "size": st.st_size, "source": abs_path})
            else:
                raise ArchiveError(f"refusing to archive non-regular, non-symlink entry: {abs_path!r}")

    entries.sort(key=lambda e: (e["path"].encode("utf-8"), e["type"]))
    return entries


def build_manifest(root: str | os.PathLike[str]) -> dict:
    """Return a content manifest: per-file sha256, mode and symlink targets."""
    manifest: dict[str, dict] = {}
    for entry in collect_entries(root):
        if entry["type"] == "file":
            digest = hashlib.sha256(Path(entry["source"]).read_bytes()).hexdigest()
            manifest[entry["path"]] = {"type": "file", "sha256": digest, "mode": oct(entry["mode"])}
        elif entry["type"] == "symlink":
            manifest[entry["path"]] = {"type": "symlink", "target": entry["target"]}
    return {"entry_count": len(manifest), "entries": dict(sorted(manifest.items()))}


def write_deterministic_targz(root: str | os.PathLike[str], output_path: str | os.PathLike[str]) -> str:
    """Write ``root`` to ``output_path`` as a deterministic .tar.gz. Returns its sha256."""
    entries = collect_entries(root)

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for entry in entries:
            info = tarfile.TarInfo(name="./" + entry["path"])
            info.mtime = FIXED_MTIME
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            if entry["type"] == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = DIR_MODE
                tar.addfile(info)
            elif entry["type"] == "symlink":
                info.type = tarfile.SYMTYPE
                info.mode = SYMLINK_MODE
                info.linkname = entry["target"]
                tar.addfile(info)
            else:
                info.type = tarfile.REGTYPE
                info.mode = entry["mode"]
                info.size = entry["size"]
                with open(entry["source"], "rb") as handle:
                    tar.addfile(info, handle)

    # mtime=0 and an empty filename field keep the gzip header constant.
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, compresslevel=GZIP_COMPRESS_LEVEL, mtime=0) as gz:
        gz.write(raw.getvalue())

    payload = compressed.getvalue()
    Path(output_path).write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: deterministic_archive.py <root> <output.tar.gz> <manifest.json>", flush=True)
        return 2
    root, out, manifest_path = argv[1], argv[2], argv[3]
    manifest = build_manifest(root)
    Path(manifest_path).write_text(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    digest = write_deterministic_targz(root, out)
    print(f"archive_sha256={digest}")
    print(f"manifest_sha256={hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest()}")
    print(f"entry_count={manifest['entry_count']}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    import sys

    raise SystemExit(_main(sys.argv))
