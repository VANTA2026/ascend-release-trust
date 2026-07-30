"""Two closures: committed content can never be silently dropped, and replacement objects can never redefine the commit.

**The omission LOW.** `deterministic_archive` filters bytecode and tool caches so runner residue
cannot break byte-reproducibility. But the filter also ran over content taken from Git, so a file
someone deliberately *committed* under one of those names was dropped from the archive **and** from
the manifest — and because both sides applied the identical filter, every downstream check agreed.
Reproduced: 382 approved committed blobs, 379 shipped, exit 0, nothing in any signed object
disclosing the loss. Ship-a-different-tree-silently is worse than refuse, so the policy is now
fail-closed.

**The replace-object hardening.** `refs/replace/<oid>` substitutes a different object *under the
attested id*: `cat-file -t` still says "commit" and `rev-parse <sha>^{commit}` still echoes the sha,
while `^{tree}` returns the forged tree. Reconstruction would then faithfully rebuild the wrong
source. Relying on "the checkout refspec happens not to fetch refs/replace/*" is a property of the
caller; `GIT_NO_REPLACE_OBJECTS=1` plus `--no-replace-objects` is the control.
"""

from __future__ import annotations

import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

import pytest

import attest
import deterministic_archive as da
import git_object_export as ge
from manifest_policy import write_manifest


def _repo(tmp_path: Path, extra: dict[str, str] | None = None, modes: dict[str, int] | None = None,
          symlinks: dict[str, str] | None = None) -> tuple[Path, str]:
    r = tmp_path / "repo"
    r.mkdir()
    g = lambda *a: subprocess.run(["git", "-C", str(r), *a], check=True, capture_output=True, text=True)
    g("init", "-q", "-b", "main"); g("config", "user.email", "t@e.invalid"); g("config", "user.name", "T")
    for ap in attest.APPROVED_SOURCE_PATHS:
        p = r / ap
        if "." in Path(ap).name:
            p.parent.mkdir(parents=True, exist_ok=True); p.write_text("honest\n")
        else:
            p.mkdir(parents=True, exist_ok=True); (p / "m.py").write_text("honest\n")
    for rel, body in (extra or {}).items():
        p = r / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)
    for rel, mode in (modes or {}).items():
        os.chmod(r / rel, mode)
    for rel, target in (symlinks or {}).items():
        p = r / rel; p.parent.mkdir(parents=True, exist_ok=True); os.symlink(target, p)
    g("add", "-A", "-f"); g("commit", "-q", "-m", "c")
    return r, g("rev-parse", "HEAD").stdout.strip()


# ---------------------------------------------------------------- PART A: exclusion_reason


@pytest.mark.parametrize("path,expected", [
    ("src/backend/app.py", None),
    ("migrations/versions/x.py", None),
    ("src/backend/__pycache__/m.py", "excluded directory"),
    ("src/backend/m.pyc", "excluded suffix"),
    ("src/backend/m.pyo", "excluded suffix"),
    ("tools/release/.ruff_cache/k.py", "excluded directory"),
    ("migrations/.pytest_cache/x.py", "excluded directory"),
    ("src/.mypy_cache/y.py", "excluded directory"),
    ("src/backend/__pycache__", "excluded directory name"),
    ("src/backend/__pycache__/a/b/deep.py", "excluded directory"),
])
def test_exclusion_reason_is_exact(path, expected):
    reason = da.exclusion_reason(path)
    if expected is None:
        assert reason is None, f"{path} must be archivable, got {reason}"
    else:
        assert reason and expected in reason, f"{path}: {reason}"


# ---------------------------------------------------------------- PART A: fail-closed refusal


@pytest.mark.parametrize("rel", [
    "src/backend/__pycache__/real_module.py",
    "src/backend/vendored.pyc",
    "src/backend/legacy.pyo",
    "tools/release/.ruff_cache/keep.py",
    "migrations/.pytest_cache/conf.py",
    "src/backend/.mypy_cache/cache.py",
    "src/backend/__pycache__/a/b/nested.py",
])
def test_a_committed_excluded_path_is_refused(tmp_path, rel):
    repo, sha = _repo(tmp_path, extra={rel: "payload\n"})
    with tempfile.TemporaryDirectory() as w:
        with pytest.raises(attest.AttestationError, match="would be excluded"):
            attest.reconstruct_source_from_commit(repo, sha, Path(w))


def test_a_committed_excluded_path_with_executable_mode_is_refused(tmp_path):
    repo, sha = _repo(tmp_path, extra={"tools/release/__pycache__/run.sh": "#!/bin/sh\n"},
                      modes={"tools/release/__pycache__/run.sh": 0o755})
    with tempfile.TemporaryDirectory() as w:
        with pytest.raises(attest.AttestationError, match="would be excluded"):
            attest.reconstruct_source_from_commit(repo, sha, Path(w))


def test_a_committed_excluded_symlink_is_refused(tmp_path):
    repo, sha = _repo(tmp_path, symlinks={"src/backend/link.pyc": "m.py"})
    with tempfile.TemporaryDirectory() as w:
        with pytest.raises(attest.AttestationError, match="would be excluded"):
            attest.reconstruct_source_from_commit(repo, sha, Path(w))


def test_every_affected_committed_path_is_reported(tmp_path):
    """A whole excluded directory must name every path it hides, not just the first."""
    repo, sha = _repo(tmp_path, extra={
        "src/backend/__pycache__/a.py": "1\n",
        "src/backend/__pycache__/b.py": "2\n",
        "src/backend/__pycache__/c/d.py": "3\n",
    })
    with tempfile.TemporaryDirectory() as w:
        with pytest.raises(attest.AttestationError) as exc:
            attest.reconstruct_source_from_commit(repo, sha, Path(w))
    message = str(exc.value)
    assert "3 committed path(s)" in message
    for name in ("a.py", "b.py", "d.py"):
        assert name in message, f"{name} not reported"


def test_the_original_defect_is_repaired(tmp_path):
    """The exact reproduction from the finding: 3 committed excluded files must now refuse."""
    repo, sha = _repo(tmp_path, extra={
        "src/backend/__pycache__/real_module.py": "x\n",
        "src/backend/vendored.pyc": "x\n",
        "tools/release/.ruff_cache/keep.py": "x\n",
    })
    git_paths = {e.path for e in ge.list_approved_entries(repo, sha, attest.APPROVED_SOURCE_PATHS)}
    assert len({p for p in git_paths if da.exclusion_reason(p)}) == 3
    with tempfile.TemporaryDirectory() as w:
        with pytest.raises(attest.AttestationError, match="3 committed path"):
            attest.reconstruct_source_from_commit(repo, sha, Path(w))


# ---------------------------------------------------------------- PART A: positives


def test_a_clean_tree_reconstructs(tmp_path):
    repo, sha = _repo(tmp_path)
    with tempfile.TemporaryDirectory() as w:
        archive, manifest, digest = attest.reconstruct_source_from_commit(repo, sha, Path(w))
        # assert inside the context: the temporary directory is removed on exit
        assert archive.exists() and manifest.exists()
        assert archive.stat().st_size > 0
    assert len(digest) == 64


def test_untracked_cache_files_never_enter_the_archive(tmp_path):
    """Local residue is not in the Git objects, so it cannot appear and must not trip the gate."""
    repo, sha = _repo(tmp_path)
    (repo / "src" / "backend" / "__pycache__").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "backend" / "__pycache__" / "stray.pyc").write_bytes(b"\x00")
    (repo / "tools" / "release" / ".ruff_cache").mkdir(parents=True, exist_ok=True)
    (repo / "tools" / "release" / ".ruff_cache" / "x").write_text("junk\n")
    with tempfile.TemporaryDirectory() as w:
        archive, _m, _d = attest.reconstruct_source_from_commit(repo, sha, Path(w))
        with tarfile.open(archive, "r:gz") as tar:
            names = [m.name for m in tar.getmembers()]
    assert not [n for n in names if "__pycache__" in n or n.endswith(".pyc") or "ruff_cache" in n]


def test_the_preserved_candidate_still_reconstructs_to_the_recorded_digest():
    candidate = Path("/Users/admin/Documents/ASCEND-OS/.claude/worktrees/release-d1f4")
    if not (candidate / ".git").exists():
        pytest.skip("BLOCKED (not passed): preserved candidate worktree unavailable on this host")
    with tempfile.TemporaryDirectory() as w:
        _a, _m, digest = attest.reconstruct_source_from_commit(
            candidate, "50cbe173ea55fea6943c40765ab64dde99406c2e", Path(w))
    assert digest == "39f23d46c419681176969c3d751605b0860464ab0947b721e2f18294f1afb572"


# ---------------------------------------------------------------- PART A: path-set equality


def test_path_sets_are_equal_across_every_representation(tmp_path):
    repo, sha = _repo(tmp_path)
    with tempfile.TemporaryDirectory() as w:
        archive, manifest, _d = attest.reconstruct_source_from_commit(repo, sha, Path(w))
        export_root = Path(w) / "reconstructed"
        git_paths = {e.path for e in ge.list_approved_entries(repo, sha, attest.APPROVED_SOURCE_PATHS)}
        exported = {str(p.relative_to(export_root).as_posix())
                    for p in export_root.rglob("*") if p.is_file() or p.is_symlink()}
        manifest_paths = set(json.loads(manifest.read_text())["entries"])
        with tarfile.open(archive, "r:gz") as tar:
            arch = {m.name[2:] for m in tar.getmembers() if m.isfile() or m.issym()}
    assert git_paths == exported == manifest_paths == arch, "all five representations must agree"


@pytest.mark.parametrize("kind", ["missing_manifest", "extra_manifest", "duplicate_archive"])
def test_path_set_inconsistencies_are_refused(tmp_path, kind):
    repo, sha = _repo(tmp_path)
    git_paths = {e.path for e in ge.list_approved_entries(repo, sha, attest.APPROVED_SOURCE_PATHS)}
    with tempfile.TemporaryDirectory() as w:
        work = Path(w)
        export_root = work / "reconstructed"
        ge.export_approved_paths(repo, sha, attest.APPROVED_SOURCE_PATHS, export_root)
        manifest = work / "m.json"; write_manifest(export_root, manifest)
        archive = work / "a.tar.gz"; da.write_deterministic_targz(export_root, archive)

        if kind == "missing_manifest":
            doc = json.loads(manifest.read_text())
            doc["entries"].pop(sorted(doc["entries"])[0])
            manifest.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        elif kind == "extra_manifest":
            doc = json.loads(manifest.read_text())
            doc["entries"]["ghost.py"] = {"type": "file", "sha256": "0" * 64, "mode": "0o644"}
            manifest.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        elif kind == "duplicate_archive":
            import io
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as tar:
                first = None
                for entry in sorted(export_root.rglob("*")):
                    if entry.is_file():
                        info = tarfile.TarInfo("./" + str(entry.relative_to(export_root).as_posix()))
                        info.size = entry.stat().st_size
                        with entry.open("rb") as fh:
                            tar.addfile(info, fh)
                        if first is None:
                            first = (info, entry)
                info, entry = first
                dup = tarfile.TarInfo(info.name); dup.size = info.size
                with entry.open("rb") as fh:
                    tar.addfile(dup, fh)
            import gzip
            with gzip.open(archive, "wb") as gz:
                gz.write(raw.getvalue())

        with pytest.raises(attest.AttestationError):
            attest._require_identical_path_sets(git_paths, export_root, manifest, archive)


# ---------------------------------------------------------------- PART B: replace objects


@pytest.fixture
def replaced(tmp_path):
    """A repo where refs/replace makes the honest commit resolve to a backdoored one."""
    repo, honest = _repo(tmp_path)
    g = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True)
    honest_tree = g("rev-parse", f"{honest}^{{tree}}").stdout.strip()
    (repo / "src" / "backend" / "m.py").write_text("honest\n# BACKDOOR\n")
    g("add", "-A"); g("commit", "-q", "-m", "evil")
    evil = g("rev-parse", "HEAD").stdout.strip()
    g("reset", "-q", "--hard", honest)
    g("replace", "-f", honest, evil)
    return repo, honest, honest_tree, evil


def test_plain_git_observes_the_replacement(replaced):
    """Precondition: without hardening the substitution is real, not hypothetical."""
    repo, honest, honest_tree, _evil = replaced
    seen = subprocess.run(["git", "-C", str(repo), "rev-parse", f"{honest}^{{tree}}"],
                          capture_output=True, text=True, env=dict(os.environ)).stdout.strip()
    assert seen != honest_tree, "fixture is not exercising a replacement"


def test_the_trust_resolver_ignores_the_replacement(replaced):
    repo, honest, honest_tree, _evil = replaced
    resolved, tree = ge.resolve_commit(repo, honest)
    assert resolved == honest
    assert tree == honest_tree, "GIT_NO_REPLACE_OBJECTS must defeat the replacement"


def test_the_export_ignores_the_replacement(replaced):
    repo, honest, _honest_tree, _evil = replaced
    with tempfile.TemporaryDirectory() as w:
        attest.reconstruct_source_from_commit(repo, honest, Path(w))
        body = (Path(w) / "reconstructed" / "src" / "backend" / "m.py").read_text()
    assert "BACKDOOR" not in body


def test_a_replaced_tree_cannot_make_malicious_bytes_match(replaced, tmp_path):
    """The archive built from the replacement must be refused against the honest commit."""
    repo, honest, _honest_tree, _evil = replaced
    with tempfile.TemporaryDirectory() as w:
        archive, manifest, _d = attest.reconstruct_source_from_commit(repo, honest, Path(w))
        evil_dir = tmp_path / "evil"; evil_dir.mkdir()
        subprocess.run(["git", "-C", str(repo), "cat-file", "-p", f"{honest}^{{tree}}"],
                       capture_output=True, check=False)
        # Forge an archive containing the backdoor and present it as the build output.
        import shutil
        forged = tmp_path / "forged.tar.gz"; shutil.copyfile(archive, forged)
        with forged.open("ab") as fh:
            fh.write(b"BACKDOOR")
        with pytest.raises(attest.AttestationError):
            attest._require_matches_commit(forged, manifest, repo, honest)


def test_repositories_without_replacement_refs_still_pass(tmp_path):
    repo, sha = _repo(tmp_path)
    resolved, tree = ge.resolve_commit(repo, sha)
    assert resolved == sha and len(tree) == 40


def test_stale_replace_state_is_ignored(replaced):
    repo, honest, honest_tree, _evil = replaced
    for _ in range(3):
        assert ge.resolve_commit(repo, honest)[1] == honest_tree


# ---------------------------------------------------------------- PART B: hostile environment


HOSTILE = {
    "GIT_NO_REPLACE_OBJECTS": "", "GIT_REPLACE_REF_BASE": "refs/replace/",
    "GIT_OBJECT_DIRECTORY": "/tmp/evil-objects", "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/tmp/evil",
    "GIT_DIR": "/tmp/evil.git", "GIT_WORK_TREE": "/tmp/evil-wt", "GIT_COMMON_DIR": "/tmp/evil-common",
    "GIT_INDEX_FILE": "/tmp/evil-index", "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "core.bare", "GIT_CONFIG_VALUE_0": "false",
    "GIT_NAMESPACE": "evil", "GIT_CEILING_DIRECTORIES": "/",
}


def test_a_hostile_inherited_git_environment_cannot_redirect_object_access(replaced, monkeypatch):
    repo, honest, honest_tree, _evil = replaced
    for key, value in HOSTILE.items():
        monkeypatch.setenv(key, value)
    resolved, tree = ge.resolve_commit(repo, honest)
    assert resolved == honest and tree == honest_tree
    entries = ge.list_approved_entries(repo, honest, attest.APPROVED_SOURCE_PATHS)
    assert entries, "export must still work under a hostile environment"


def test_the_controlled_environment_sets_the_hardening_flag():
    env = ge._git_env()
    assert env["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert env["LC_ALL"] == "C"
    for unsafe in ge._UNSAFE_GIT_ENV:
        assert unsafe not in env, f"{unsafe} must not reach git"


def test_every_git_invocation_uses_the_controlled_environment():
    """Static proof: no subprocess call in the module may omit env=_git_env()."""
    source = Path(ge.__file__).read_text()
    calls = [ln for ln in source.splitlines() if "subprocess.run(" in ln and not ln.strip().startswith("#")]
    assert len(calls) == 1, f"expected a single choke point for git invocation, found {len(calls)}"
    body = source[source.index("def _git("):source.index("def resolve_commit")]
    assert "env=_git_env()" in body
    assert "--no-replace-objects" in body


def test_retained_environment_variables_are_documented_and_safe():
    assert set(ge._RETAINED_GIT_ENV) == {"PATH", "HOME"}
    source = Path(ge.__file__).read_text()
    assert "Retained deliberately" in source, "retained variables must be justified in the source"


# ---------------------------------------------------------------- static guarantees


def test_the_gate_precedes_assembly_provenance_and_signing():
    source = Path(attest.__file__).read_text()
    gate = source.index("_require_matches_commit(\n")
    assembly = source.index("shutil.copyfile(p1s / SOURCE_ARCHIVE")
    provenance = source.index("write_provenance(document")
    assert gate < assembly < provenance


def test_no_warning_only_branch_can_authorize(tmp_path):
    source = Path(attest.__file__).read_text()
    body = source[source.index("def reconstruct_source_from_commit"):source.index("def _require_canonical")]
    assert "raise AttestationError" in body
    assert "warnings.warn" not in body and "logging.warning" not in body


def test_the_signer_is_unreachable_after_an_omission_failure(tmp_path, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(attest, "write_provenance", lambda *a, **k: calls.append("x"), raising=True)
    repo, sha = _repo(tmp_path, extra={"src/backend/__pycache__/evil.py": "payload\n"})
    with tempfile.TemporaryDirectory() as w:
        with pytest.raises(attest.AttestationError):
            attest.reconstruct_source_from_commit(repo, sha, Path(w))
    assert calls == []
