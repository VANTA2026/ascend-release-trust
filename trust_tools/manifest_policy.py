"""Manifest generation, safe extraction verification, and pass-to-pass comparison.

Two build passes are only meaningful if something independent measures them. These helpers are that
something: they recompute digests from bytes on disk rather than believing a value a build job
printed, and they compare the two passes byte-for-byte rather than comparing two reported strings.

Extraction is deliberately paranoid. A tar member can name an absolute path, climb out with `..`,
or be a link pointing anywhere; extracting an artifact in order to verify it must not be the thing
that compromises the verifier.

Trust-owned. Lives in the protected public trust repository; never imported from candidate code.
"""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path

from deterministic_archive import ArchiveError, build_manifest

__all__ = [
    "ManifestError", "PassComparison",
    "sha256_file", "safe_extract", "verify_archive_against_manifest",
    "compare_passes", "write_manifest",
]


class ManifestError(RuntimeError):
    """Raised when an artifact does not match its manifest, or two passes disagree."""


def sha256_file(path: str | os.PathLike[str]) -> str:
    """Independently measure a file's sha256 in fixed-size chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(root: str | os.PathLike[str], destination: str | os.PathLike[str]) -> str:
    """Write a canonical JSON manifest of ``root``. Returns its sha256."""
    manifest = build_manifest(root)
    payload = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    Path(destination).write_text(payload, encoding="utf-8")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def safe_extract(archive: str | os.PathLike[str], destination: str | os.PathLike[str]) -> int:
    """Extract a .tar.gz, refusing any member that could write outside ``destination``."""
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    dest_real = os.path.realpath(dest)
    count = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            name = member.name
            if name.startswith("/") or os.path.isabs(name):
                raise ManifestError(f"archive member has an absolute path: {name!r}")
            if ".." in Path(name).parts:
                raise ManifestError(f"archive member escapes with '..': {name!r}")
            if member.islnk() or member.issym():
                target = member.linkname
                if os.path.isabs(target):
                    raise ManifestError(f"archive link target is absolute: {name!r} -> {target!r}")
                resolved = os.path.realpath(os.path.join(dest_real, os.path.dirname(name), target))
                if not (resolved == dest_real or resolved.startswith(dest_real + os.sep)):
                    raise ManifestError(f"archive link escapes the destination: {name!r} -> {target!r}")
            elif not (member.isfile() or member.isdir()):
                raise ManifestError(f"archive contains a non-regular member: {name!r} (type {member.type!r})")
            count += 1
        # `filter="data"` is the interpreter's own hardening; the explicit checks above run first so
        # the failure names the offending member rather than surfacing a generic tar error.
        tar.extractall(dest, filter="data")
    return count


def verify_archive_against_manifest(
    archive: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    workdir: str | os.PathLike[str],
) -> dict:
    """Extract ``archive`` and require the recomputed manifest to equal the recorded one."""
    recorded = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    extract_root = Path(workdir) / "extracted"
    safe_extract(archive, extract_root)
    try:
        recomputed = build_manifest(extract_root)
    except ArchiveError as exc:
        raise ManifestError(f"extracted tree cannot be measured: {exc}") from exc

    if recomputed != recorded:
        added = sorted(set(recomputed.get("entries", {})) - set(recorded.get("entries", {})))
        missing = sorted(set(recorded.get("entries", {})) - set(recomputed.get("entries", {})))
        changed = sorted(
            k for k in set(recomputed.get("entries", {})) & set(recorded.get("entries", {}))
            if recomputed["entries"][k] != recorded["entries"][k]
        )
        raise ManifestError(
            "extracted tree does not match the manifest "
            f"(added={added[:5]} missing={missing[:5]} changed={changed[:5]})"
        )
    return recomputed


@dataclass(frozen=True)
class PassComparison:
    label: str
    pass1_sha256: str
    pass2_sha256: str

    @property
    def agree(self) -> bool:
        return self.pass1_sha256 == self.pass2_sha256


def compare_passes(label: str, path1: str | os.PathLike[str], path2: str | os.PathLike[str]) -> PassComparison:
    """Compare two independently produced artifacts by measuring both, not by trusting reports."""
    for p in (path1, path2):
        if not Path(p).is_file():
            raise ManifestError(f"{label}: expected artifact is missing: {p}")
    comparison = PassComparison(label, sha256_file(path1), sha256_file(path2))
    if not comparison.agree:
        raise ManifestError(
            f"{label}: independent passes disagree — "
            f"pass1={comparison.pass1_sha256} pass2={comparison.pass2_sha256}"
        )
    return comparison


def _main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: manifest_policy.py sha256 <file> | compare <label> <a> <b> | verify <archive> <manifest> <workdir>")
        return 2
    if argv[1] == "sha256":
        print(f"sha256={sha256_file(argv[2])}")
        return 0
    if argv[1] == "compare":
        c = compare_passes(argv[2], argv[3], argv[4])
        print(f"{c.label}_sha256={c.pass1_sha256}")
        return 0
    if argv[1] == "verify":
        manifest = verify_archive_against_manifest(argv[2], argv[3], argv[4])
        print(f"verified_entries={manifest['entry_count']}")
        return 0
    print(f"unknown subcommand {argv[1]!r}")
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    import sys

    raise SystemExit(_main(sys.argv))
