"""Wheelhouse acceptance policy for macOS arm64 / CPython 3.11.

A filename is a claim, not evidence. This module therefore checks three independent things and
requires them to agree:

1. the **filename** tags, read positionally per PEP 427 (never by substring search — a distribution
   name or a PEP 440 local version segment can otherwise impersonate a platform tag);
2. the wheel's **internal `.dist-info/METADATA`** Name and Version;
3. the wheel's **internal `.dist-info/WHEEL`** ``Tag:`` lines.

and then binds the result to the lock: the wheel's sha256 must be permitted **for that specific
distribution**, and the version must be the locked version. Finally it requires exactly one
compatible wheel per locked distribution — no missing, no duplicates, no extras.

universal2 is accepted and verified, never waved through as a warning: it is a fat binary that
genuinely contains an arm64 slice, so refusing it would force a lock-required wheel out of the
wheelhouse. An x86_64-only wheel is refused unconditionally and can never substitute for arm64.

Runtime properties — that installation on exact CPython 3.11.15 succeeds offline, that imports
work, that focused tests pass — are proven by the installation gate, not by inspecting files. This
module does not pretend to prove them.

Trust-owned. Lives in the protected public trust repository; never imported from candidate code.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from lock_policy import Lock, normalize_project

__all__ = [
    "PlatformClass", "WheelFacts", "WheelDecision", "WheelhouseVerdict",
    "split_wheel_tags", "classify_platform_tag", "classify_wheel",
    "read_wheel_facts", "evaluate_wheelhouse",
]

TARGET_PYTHON_TAG = "cp311"
TARGET_ABI = "cp311"
TARGET_PYTHON_VERSION = (3, 11)
TARGET_ARCHITECTURE = "arm64"


class PlatformClass:
    PURE = "pure"
    MACOS_ARM64 = "macos_arm64"
    MACOS_UNIVERSAL2 = "macos_universal2"
    MACOS_X86_64 = "macos_x86_64"
    LINUX = "linux"
    WINDOWS = "windows"
    SDIST = "sdist"
    UNKNOWN = "unknown"


_ACCEPTABLE = (PlatformClass.PURE, PlatformClass.MACOS_ARM64, PlatformClass.MACOS_UNIVERSAL2)


@dataclass(frozen=True)
class WheelFacts:
    """What the wheel says about itself, read from inside the archive."""
    metadata_name: str
    metadata_version: str
    wheel_tags: tuple[str, ...]


@dataclass(frozen=True)
class WheelDecision:
    filename: str
    platform_class: str
    accepted: bool
    reason: str
    sha256: str | None = None
    project: str | None = None
    version: str | None = None


@dataclass
class WheelhouseVerdict:
    decisions: list[WheelDecision] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> list[WheelDecision]:
        return [d for d in self.decisions if d.accepted]

    @property
    def refused(self) -> list[WheelDecision]:
        return [d for d in self.decisions if not d.accepted]

    @property
    def universal2(self) -> list[str]:
        """Filenames the signed provenance must declare as universal2."""
        return sorted(d.filename for d in self.accepted if d.platform_class == PlatformClass.MACOS_UNIVERSAL2)

    @property
    def ok(self) -> bool:
        return not self.refused and not self.problems


def split_wheel_tags(filename: str) -> tuple[str, str, str] | None:
    """Return (python tag, abi tag, platform tag) — the LAST three hyphen fields of a wheel name."""
    if not filename.endswith(".whl"):
        return None
    parts = filename[: -len(".whl")].split("-")
    if len(parts) < 5:  # distribution, version, python, abi, platform
        return None
    return parts[-3], parts[-2], parts[-1]


def wheel_name_version(filename: str) -> tuple[str, str] | None:
    if not filename.endswith(".whl"):
        return None
    parts = filename[: -len(".whl")].split("-")
    if len(parts) < 5:
        return None
    return parts[0], parts[1]


def classify_platform_tag(tag: str) -> str:
    t = tag.lower()
    if t == "any":
        return PlatformClass.PURE
    if t.startswith("macosx"):
        # universal2 first: a fat wheel legitimately contains an x86_64 slice.
        if "universal2" in t:
            return PlatformClass.MACOS_UNIVERSAL2
        if "arm64" in t:
            return PlatformClass.MACOS_ARM64
        if any(k in t for k in ("x86_64", "intel", "i386", "fat", "ppc")):
            return PlatformClass.MACOS_X86_64
        return PlatformClass.UNKNOWN
    if "manylinux" in t or "musllinux" in t or t.startswith("linux"):
        return PlatformClass.LINUX
    if t.startswith("win"):
        return PlatformClass.WINDOWS
    return PlatformClass.UNKNOWN


def _best_of(kinds: list[str]) -> str:
    for preferred in (
        PlatformClass.MACOS_UNIVERSAL2, PlatformClass.MACOS_ARM64, PlatformClass.PURE,
        PlatformClass.MACOS_X86_64, PlatformClass.LINUX, PlatformClass.WINDOWS,
    ):
        if preferred in kinds:
            return preferred
    return PlatformClass.UNKNOWN


def classify_wheel(filename: str) -> str:
    name = filename.strip()
    if name.endswith((".tar.gz", ".zip")):
        return PlatformClass.SDIST
    tags = split_wheel_tags(name)
    if tags is None:
        return PlatformClass.UNKNOWN
    return _best_of([classify_platform_tag(t) for t in tags[2].split(".")])


def abi_is_target_compatible(python_tag: str, abi_tag: str) -> bool:
    """Fail CLOSED: an unrecognised or non-CPython interpreter is refused, never waved through."""
    pythons = [p.lower() for p in python_tag.split(".")]
    abis = [a.lower() for a in abi_tag.split(".")]
    if "none" in abis and all(p.startswith("py") for p in pythons):
        return True
    if "abi3" in abis:
        # abi3 wheels are tagged with the MINIMUM CPython supported, not the target's version.
        for p in pythons:
            m = re.fullmatch(r"cp(\d)(\d+)", p)
            if m and (int(m.group(1)), int(m.group(2))) <= TARGET_PYTHON_VERSION:
                return True
        return False
    return TARGET_ABI in abis and TARGET_PYTHON_TAG in pythons


def read_wheel_facts(path: Path) -> WheelFacts:
    """Read Name/Version from .dist-info/METADATA and Tag: lines from .dist-info/WHEEL."""
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        meta_names = [n for n in names if n.endswith(".dist-info/METADATA")]
        wheel_names = [n for n in names if n.endswith(".dist-info/WHEEL")]
        if len(meta_names) != 1:
            raise ValueError(f"expected exactly one .dist-info/METADATA, found {len(meta_names)}")
        if len(wheel_names) != 1:
            raise ValueError(f"expected exactly one .dist-info/WHEEL, found {len(wheel_names)}")
        meta = zf.read(meta_names[0]).decode("utf-8", "replace")
        wheel = zf.read(wheel_names[0]).decode("utf-8", "replace")

    def header(text: str, key: str) -> str:
        m = re.search(rf"(?mi)^{re.escape(key)}:\s*(.+?)\s*$", text)
        return m.group(1) if m else ""

    tags = tuple(m.group(1).strip() for m in re.finditer(r"(?mi)^Tag:\s*(.+?)\s*$", wheel))
    return WheelFacts(
        metadata_name=header(meta, "Name"),
        metadata_version=header(meta, "Version"),
        wheel_tags=tags,
    )


def _wheel_tag_platforms(tags: tuple[str, ...]) -> list[str]:
    kinds: list[str] = []
    for tag in tags:
        parts = tag.split("-")
        if len(parts) != 3:
            continue
        kinds.extend(classify_platform_tag(t) for t in parts[2].split("."))
    return kinds


def evaluate_wheelhouse(wheel_paths: list[str] | list[Path], lock: Lock) -> WheelhouseVerdict:
    """Decide, file by file, whether a wheelhouse satisfies the release policy for this lock."""
    verdict = WheelhouseVerdict()
    seen_projects: dict[str, str] = {}

    for raw in sorted(str(p) for p in wheel_paths):
        path = Path(raw)
        filename = path.name
        cls = classify_wheel(filename)
        digest: str | None = None
        project: str | None = None
        version: str | None = None

        def refuse(reason: str) -> None:
            verdict.decisions.append(WheelDecision(filename, cls, False, reason, digest, project, version))

        if not path.is_file():
            refuse("not a regular file")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()

        if cls == PlatformClass.SDIST:
            refuse("sdist present — --only-binary=:all: was not honoured"); continue
        if cls == PlatformClass.LINUX:
            refuse("Linux wheel is not installable on the macOS arm64 target"); continue
        if cls == PlatformClass.WINDOWS:
            refuse("Windows wheel is not installable on the macOS arm64 target"); continue
        if cls == PlatformClass.MACOS_X86_64:
            refuse("x86_64-only macOS wheel must never be accepted as an arm64 substitute"); continue
        if cls == PlatformClass.UNKNOWN:
            refuse("unrecognised distribution filename"); continue

        tags = split_wheel_tags(filename)
        namever = wheel_name_version(filename)
        if tags is None or namever is None:
            refuse("wheel filename does not carry a PEP 427 tag triple"); continue
        python_tag, abi_tag, _plat = tags
        if not abi_is_target_compatible(python_tag, abi_tag):
            refuse(f"wheel declares an ABI other than {TARGET_ABI}"); continue

        project = normalize_project(namever[0])
        version = namever[1]

        # --- internal metadata must agree with the filename -------------------------------
        try:
            facts = read_wheel_facts(path)
        except (zipfile.BadZipFile, ValueError, KeyError) as exc:
            refuse(f"wheel could not be read as a valid wheel: {exc}"); continue
        if normalize_project(facts.metadata_name) != project:
            refuse(f"METADATA Name {facts.metadata_name!r} disagrees with the filename project {project!r}"); continue
        if facts.metadata_version != version:
            refuse(f"METADATA Version {facts.metadata_version!r} disagrees with the filename version {version!r}"); continue
        if not facts.wheel_tags:
            refuse("WHEEL carries no Tag: line"); continue
        internal_kinds = _wheel_tag_platforms(facts.wheel_tags)
        if internal_kinds and not any(k in _ACCEPTABLE for k in internal_kinds):
            refuse(f"internal WHEEL tags target no acceptable platform: {facts.wheel_tags}"); continue
        if cls == PlatformClass.MACOS_UNIVERSAL2 and PlatformClass.MACOS_UNIVERSAL2 not in internal_kinds:
            refuse("filename claims universal2 but the internal WHEEL tags do not"); continue

        # --- bind to the lock, per distribution --------------------------------------------
        locked = lock.distributions.get(project)
        if locked is None:
            refuse(f"{project} is not a locked distribution"); continue
        if locked.version != version:
            refuse(f"version {version} is not the locked version {locked.version}"); continue
        if digest not in locked.hashes:
            refuse(f"sha256 is not permitted for {project} by the lock"); continue

        if project in seen_projects:
            refuse(f"duplicate wheel for {project} (already selected {seen_projects[project]})"); continue
        seen_projects[project] = filename

        verdict.decisions.append(
            WheelDecision(filename, cls, True, "accepted under the macOS arm64 / cp311 policy", digest, project, version)
        )

    # --- exactly one compatible wheel per locked distribution ------------------------------
    missing = sorted(set(lock.distributions) - set(seen_projects))
    if missing:
        verdict.problems.append(f"locked distributions with no compatible wheel: {missing}")
    extra = sorted(set(seen_projects) - set(lock.distributions))
    if extra:
        verdict.problems.append(f"wheels for distributions absent from the lock: {extra}")
    return verdict


def policy_manifest(verdict: WheelhouseVerdict, lock: Lock) -> dict:
    """The signed record of WHY each wheel was accepted, not merely that it was.

    This is one of the six signed objects. It states, per wheel, the project, the locked version,
    the measured digest and the platform class — so a verifier can re-derive the decision instead of
    taking the build's word for it.
    """
    if not verdict.ok:
        raise ValueError("refusing to build a policy manifest for a wheelhouse that did not pass")
    return {
        "schema": "ascend-wheelhouse-policy/1",
        "target": {
            "os": "macos",
            "architecture": TARGET_ARCHITECTURE,
            "python_tag": TARGET_PYTHON_TAG,
            "abi": TARGET_ABI,
        },
        "lockfile_sha256": lock.sha256,
        "locked_distributions": len(lock.distributions),
        "accepted_wheels": len(verdict.accepted),
        "universal2_wheels": verdict.universal2,
        "wheels": [
            {
                "filename": d.filename,
                "project": d.project,
                "version": d.version,
                "sha256": d.sha256,
                "platform_class": d.platform_class,
            }
            for d in sorted(verdict.accepted, key=lambda x: x.filename)
        ],
    }


def _main(argv: list[str]) -> int:
    if len(argv) not in (3, 4):
        print("usage: wheelhouse_policy.py <lockfile> <wheelhouse-dir> [policy-manifest-out]", flush=True)
        return 2
    import hashlib as _hashlib
    import json as _json

    from lock_policy import load_validated_lock

    lock = load_validated_lock(argv[1])
    paths = sorted(p for p in Path(argv[2]).iterdir() if p.is_file())
    verdict = evaluate_wheelhouse(paths, lock)
    for d in verdict.refused:
        print(f"REFUSED {d.filename}: {d.reason}")
    for p in verdict.problems:
        print(f"PROBLEM {p}")
    if not verdict.ok:
        return 1
    if len(argv) == 4:
        payload = _json.dumps(policy_manifest(verdict, lock), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        Path(argv[3]).write_text(payload, encoding="utf-8")
        print(f"policy_manifest_sha256={_hashlib.sha256(payload.encode('utf-8')).hexdigest()}")
    print(f"accepted_wheels={len(verdict.accepted)}")
    print(f"locked_distributions={len(lock.distributions)}")
    print("universal2=" + (",".join(verdict.universal2) if verdict.universal2 else ""))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    import sys

    raise SystemExit(_main(sys.argv))
