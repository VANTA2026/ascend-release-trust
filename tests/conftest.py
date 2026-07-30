"""Shared fixtures for the trust-tool suite.

`trust_tools/` is placed on `sys.path` so the modules are imported exactly as the workflows import
them — by name, from the protected trust repository, never from a candidate checkout.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

TRUST_TOOLS = Path(__file__).resolve().parents[1] / "trust_tools"
if str(TRUST_TOOLS) not in sys.path:
    sys.path.insert(0, str(TRUST_TOOLS))


def make_wheel(
    directory: Path,
    *,
    project: str,
    version: str,
    python_tag: str = "cp311",
    abi_tag: str = "cp311",
    platform_tag: str = "macosx_11_0_arm64",
    metadata_name: str | None = None,
    metadata_version: str | None = None,
    wheel_tags: list[str] | None = None,
    payload: bytes = b"payload",
    omit_metadata: bool = False,
    omit_wheel: bool = False,
) -> tuple[Path, str]:
    """Build a real .whl zip with genuine .dist-info/METADATA and .dist-info/WHEEL."""
    filename = f"{project}-{version}-{python_tag}-{abi_tag}-{platform_tag}.whl"
    path = directory / filename
    dist_info = f"{project}-{version}.dist-info"
    tags = wheel_tags if wheel_tags is not None else [f"{python_tag}-{abi_tag}-{platform_tag}"]
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{project}/__init__.py", payload.decode("latin-1"))
        if not omit_metadata:
            zf.writestr(
                f"{dist_info}/METADATA",
                f"Metadata-Version: 2.1\nName: {metadata_name or project}\n"
                f"Version: {metadata_version or version}\n\nbody\n",
            )
        if not omit_wheel:
            body = "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: false\n"
            body += "".join(f"Tag: {t}\n" for t in tags)
            zf.writestr(f"{dist_info}/WHEEL", body)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def make_lock_text(entries: list[tuple[str, str, list[str]]]) -> str:
    """Render a pip-compile-style hash-pinned lock from (project, version, [sha256...])."""
    lines = []
    for project, version, hashes in entries:
        lines.append(f"{project}=={version} \\")
        for i, h in enumerate(hashes):
            suffix = " \\" if i < len(hashes) - 1 else ""
            lines.append(f"    --hash=sha256:{h}{suffix}")
        lines.append("    # via -r requirements.txt")
    return "\n".join(lines) + "\n"


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A real git repository with one commit, for exact-object-export tests."""
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)
    run("init", "-q", "-b", "main")
    run("config", "user.email", "t@example.invalid")
    run("config", "user.name", "Trust Test")
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x = 1\n")
    (repo / "src" / "notes.txt").write_text("keep\n")
    (repo / "excluded").mkdir()
    (repo / "excluded" / "secret.txt").write_text("must not ship\n")
    (repo / "lock.txt").write_text("pkg==1.0\n")
    run("add", "-A")
    run("commit", "-q", "-m", "initial")
    return repo


@pytest.fixture
def head_sha(git_repo: Path) -> str:
    out = subprocess.run(
        ["git", "-C", str(git_repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    return out.stdout.strip()
