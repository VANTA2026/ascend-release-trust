"""Complete parsing and validation of the hash-pinned production lockfile.

The lockfile is the only thing binding the release's transitive dependency closure to specific
bytes, so a partial validator is worse than none: it produces confidence without coverage. This
module parses the whole file and enforces every property, and — critically — records which hashes
belong to WHICH distribution. A wheelhouse check that merely asks "is this digest somewhere in the
lock?" would accept a wheel for package A carrying package B's digest.

The lock is target-specific (macOS / arm64 / CPython 3.11.15 / cp311) and is not portable.

Trust-owned. Lives in the protected public trust repository; never imported from candidate code.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["LockError", "LockedDistribution", "Lock", "normalize_project", "parse_lock", "validate_lock", "load_validated_lock"]

_HASH_RE = re.compile(r"--hash=(?P<alg>[a-z0-9_]+):(?P<digest>[0-9a-fA-F]+)")
_REQ_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<op>[=<>!~]+)\s*(?P<version>[^\s;#\\]+)")

_FORBIDDEN_LINE_PATTERNS = {
    "editable install": re.compile(r"(^|\s)-e(\s|=)"),
    "VCS reference": re.compile(r"\b(git|hg|svn|bzr)\+"),
    "direct URL": re.compile(r"\bhttps?://"),
    "local file URL": re.compile(r"\bfile://"),
    "index directive": re.compile(r"--(index-url|extra-index-url|find-links|trusted-host)\b"),
    "credential-bearing URL": re.compile(r"://[^/@\s]+:[^/@\s]+@"),
}


class LockError(RuntimeError):
    """Raised when a lockfile violates the release policy."""


def normalize_project(name: str) -> str:
    """PEP 503 normalisation: the only safe way to compare distribution names."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class LockedDistribution:
    project: str          # normalized
    raw_name: str         # as written in the lock
    version: str
    hashes: frozenset[str]  # sha256 hex digests permitted FOR THIS DISTRIBUTION
    via: tuple[str, ...] = ()


@dataclass
class Lock:
    path: str
    sha256: str
    distributions: dict[str, LockedDistribution] = field(default_factory=dict)

    @property
    def project_names(self) -> list[str]:
        return sorted(self.distributions)

    def permitted_hashes(self, project: str) -> frozenset[str]:
        dist = self.distributions.get(normalize_project(project))
        return dist.hashes if dist else frozenset()

    @property
    def all_hashes(self) -> frozenset[str]:
        out: set[str] = set()
        for d in self.distributions.values():
            out |= d.hashes
        return frozenset(out)


def parse_lock(text: str, path: str = "<lock>") -> tuple[list[dict], list[str]]:
    """Split a lockfile into requirement blocks. Returns (blocks, non-comment directive lines)."""
    blocks: list[dict] = []
    directives: list[str] = []
    current: dict | None = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        if raw[0].isspace() or stripped.startswith("#"):
            if current is None:
                if stripped.startswith("-"):
                    directives.append(stripped)
                continue
            # Continuation lines carry a trailing " \" as well as optional leading escapes.
            body = stripped.lstrip("\\").strip().rstrip("\\").strip()
            if body.startswith("--hash="):
                current["hash_lines"].append((lineno, body))
            elif body.startswith("#"):
                current["comments"].append(body.lstrip("#").strip())
            elif body.startswith("-"):
                directives.append(body)
            continue
        # a new top-level line
        if stripped.startswith("-"):
            directives.append(stripped)
            continue
        if current is not None:
            blocks.append(current)
        current = {"lineno": lineno, "spec": stripped.split("\\")[0].strip(), "hash_lines": [], "comments": []}
    if current is not None:
        blocks.append(current)
    return blocks, directives


def validate_lock(text: str, path: str = "<lock>", *, expected_sha256: str | None = None) -> Lock:
    """Validate a lockfile against the complete release policy, returning the parsed Lock."""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise LockError(f"lockfile digest mismatch: measured {digest}, expected {expected_sha256}")

    problems: list[str] = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        if raw.strip().startswith("#"):
            continue
        for label, pattern in _FORBIDDEN_LINE_PATTERNS.items():
            if pattern.search(raw):
                problems.append(f"line {lineno}: {label} is forbidden in a production lock: {raw.strip()[:70]}")

    blocks, directives = parse_lock(text, path)
    if not blocks:
        raise LockError(f"{path}: contains no pinned requirements")
    for directive in directives:
        problems.append(f"unexpected directive in a production lock: {directive[:70]}")

    distributions: dict[str, LockedDistribution] = {}
    for block in blocks:
        spec = block["spec"]
        lineno = block["lineno"]
        if ";" in spec:
            problems.append(f"line {lineno}: unresolved environment marker: {spec[:70]}")
        match = _REQ_RE.match(spec)
        if not match:
            problems.append(f"line {lineno}: unparseable requirement: {spec[:70]}")
            continue
        if match.group("op") != "==":
            problems.append(f"line {lineno}: not pinned with '==': {spec[:70]}")
            continue
        version = match.group("version")
        if any(ch in version for ch in "*<>!~ "):
            problems.append(f"line {lineno}: floating version specifier: {spec[:70]}")

        hashes: set[str] = set()
        if not block["hash_lines"]:
            problems.append(f"line {lineno}: no sha256 hashes for {match.group('name')}")
        for hl_no, body in block["hash_lines"]:
            m = _HASH_RE.fullmatch(body)
            if not m:
                problems.append(f"line {hl_no}: malformed hash entry: {body[:70]}")
                continue
            if m.group("alg") != "sha256":
                problems.append(f"line {hl_no}: non-sha256 hash algorithm '{m.group('alg')}'")
                continue
            hexd = m.group("digest").lower()
            if len(hexd) != 64:
                problems.append(f"line {hl_no}: truncated sha256 digest ({len(hexd)} chars)")
                continue
            hashes.add(hexd)

        project = normalize_project(match.group("name"))
        via = tuple(
            c.replace("via", "").strip()
            for c in block["comments"]
            if c.strip() and c.strip() != "via" and not c.strip().startswith("-r")
        )
        if project in distributions:
            existing = distributions[project]
            if existing.version != version:
                problems.append(f"line {lineno}: duplicate {project} with conflicting versions {existing.version} and {version}")
            else:
                problems.append(f"line {lineno}: duplicate entry for {project}")
            continue
        distributions[project] = LockedDistribution(
            project=project, raw_name=match.group("name"), version=version,
            hashes=frozenset(hashes), via=tuple(v for v in via if v),
        )

    if problems:
        raise LockError(f"{path}: lockfile policy violations:\n  - " + "\n  - ".join(problems))

    return Lock(path=path, sha256=digest, distributions=distributions)


def load_validated_lock(path: str | Path, *, expected_sha256: str | None = None) -> Lock:
    p = Path(path)
    return validate_lock(p.read_text(encoding="utf-8"), str(p), expected_sha256=expected_sha256)


def _main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: lock_policy.py <lockfile> [expected_sha256]", flush=True)
        return 2
    expected = argv[2] if len(argv) > 2 else None
    lock = load_validated_lock(argv[1], expected_sha256=expected)
    print(f"lock_sha256={lock.sha256}")
    print(f"distributions={len(lock.distributions)}")
    print(f"total_hashes={len(lock.all_hashes)}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    import sys

    raise SystemExit(_main(sys.argv))
