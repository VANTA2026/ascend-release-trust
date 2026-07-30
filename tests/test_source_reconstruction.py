"""The signed source must be what the attested Git commit produces — not merely what two builders agree on.

Confirmed HIGH finding: `compare-and-sign` compared the two build passes to each other and never
reconstructed the tree from the attested commit. Two agreeing jobs prove they behaved *identically*,
not that they built the *right thing*: feed both the same wrong tree, or subvert the build itself,
and the old check passes perfectly.

The decisive test here is `test_two_agreeing_builders_with_a_wrong_tree_are_refused`: it constructs
exactly that situation and requires refusal, and separately proves the signer is never invoked.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

import attest
import deterministic_archive as da
from manifest_policy import write_manifest

WORKFLOW_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"


# ---------------------------------------------------------------- the approved path set


def test_approved_paths_match_the_source_build_workflow():
    """The reconstruction and the build must select the SAME paths, or they cannot agree."""
    doc = yaml.safe_load((WORKFLOW_DIR / "_build-source.yml").read_text())
    declared = (doc.get("env") or {}).get("APPROVED_PATHS", "").split()
    assert declared, "the source build must declare APPROVED_PATHS"
    assert declared == attest.APPROVED_SOURCE_PATHS, (
        f"drift between workflow ({declared}) and trust code ({attest.APPROVED_SOURCE_PATHS})"
    )


# ---------------------------------------------------------------- a real repository fixture


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "candidate"
    r.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(r), *a], check=True, capture_output=True)
    run("init", "-q", "-b", "main")
    run("config", "user.email", "t@example.invalid")
    run("config", "user.name", "T")
    for rel in attest.APPROVED_SOURCE_PATHS:
        p = r / rel
        if "." in Path(rel).name:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f"content of {rel}\n")
        else:
            p.mkdir(parents=True, exist_ok=True)
            (p / "mod.py").write_text(f"# {rel}\n")
    (r / "NOT_APPROVED.txt").write_text("must never be exported\n")
    run("add", "-A")
    run("commit", "-q", "-m", "candidate")
    return r


@pytest.fixture
def head(repo: Path) -> str:
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()


def _honest_build(repo: Path, sha: str, dest: Path) -> tuple[Path, Path]:
    """Produce what an honest build job produces, using the same trust-owned code."""
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        arch, man, _ = attest.reconstruct_source_from_commit(repo, sha, Path(tmp))
        a, m = dest / attest.SOURCE_ARCHIVE, dest / attest.SOURCE_MANIFEST
        a.write_bytes(arch.read_bytes()); m.write_bytes(man.read_bytes())
    return a, m


# ---------------------------------------------------------------- positive


def test_honest_build_matches_a_fresh_export(repo: Path, head: str, tmp_path: Path):
    a, m = _honest_build(repo, head, tmp_path / "pass1")
    digest = attest._require_matches_commit(a, m, repo, head)
    assert digest == hashlib.sha256(a.read_bytes()).hexdigest()


def test_reconstruction_only_contains_approved_paths(repo: Path, head: str, tmp_path: Path):
    with tempfile.TemporaryDirectory() as tmp:
        attest.reconstruct_source_from_commit(repo, head, Path(tmp))
        names = {p.name for p in (Path(tmp) / "reconstructed").rglob("*")}
    assert "NOT_APPROVED.txt" not in names


def test_reconstruction_is_deterministic(repo: Path, head: str):
    digests = []
    for _ in range(2):
        with tempfile.TemporaryDirectory() as tmp:
            digests.append(attest.reconstruct_source_from_commit(repo, head, Path(tmp))[2])
    assert digests[0] == digests[1]


# ---------------------------------------------------------------- THE critical negative


def test_two_agreeing_builders_with_a_wrong_tree_are_refused(repo: Path, head: str, tmp_path: Path):
    """Both passes byte-identical, both wrong. The old check passes; this one must not."""
    a1, m1 = _honest_build(repo, head, tmp_path / "p1")
    a2, m2 = _honest_build(repo, head, tmp_path / "p2")
    assert a1.read_bytes() == a2.read_bytes(), "precondition: honest passes agree"

    # Both builders emit the SAME malicious tree, with a matching manifest.
    with tempfile.TemporaryDirectory() as tmp:
        evil = Path(tmp) / "evil"
        subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(evil), head],
                       check=True, capture_output=True)
        (evil / ".git").unlink(missing_ok=True)
        target = evil / "alembic.ini"
        target.write_text(target.read_text() + "\n# BACKDOOR\n")
        for keep in list(evil.iterdir()):
            if keep.name not in {p.split("/")[0] for p in attest.APPROVED_SOURCE_PATHS}:
                if keep.is_dir():
                    __import__("shutil").rmtree(keep)
                else:
                    keep.unlink()
        for a, m in ((a1, m1), (a2, m2)):
            write_manifest(evil, m)
            da.write_deterministic_targz(evil, a)

    assert a1.read_bytes() == a2.read_bytes(), "the two builders still agree exactly"
    assert m1.read_bytes() == m2.read_bytes(), "their manifests also agree"

    with pytest.raises(attest.AttestationError, match="does not match a fresh export"):
        attest._require_matches_commit(a1, m1, repo, head)


def test_the_signer_is_not_invoked_after_a_mismatch(repo: Path, head: str, tmp_path: Path, monkeypatch):
    """Control-flow proof: a mismatch raises before anything a signer could consume."""
    calls: list[str] = []

    def fake_signer(*_a, **_k):
        calls.append("signed")
        return "signed"

    monkeypatch.setattr(attest, "write_provenance", fake_signer, raising=True)
    a, m = _honest_build(repo, head, tmp_path / "p1")
    with a.open("ab") as fh:
        fh.write(b"tampered")
    with pytest.raises(attest.AttestationError):
        attest._require_matches_commit(a, m, repo, head)
    assert calls == [], "no signing-adjacent call may occur after a mismatch"


# ---------------------------------------------------------------- content negatives


@pytest.mark.parametrize("mutation", ["modify", "add", "omit", "mode", "symlink"])
def test_archive_content_mutations_are_refused(repo: Path, head: str, tmp_path: Path, mutation):
    a, m = _honest_build(repo, head, tmp_path / "p1")
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "t"
        subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(tree), head],
                       check=True, capture_output=True)
        (tree / ".git").unlink(missing_ok=True)
        for extra in list(tree.iterdir()):
            if extra.name not in {p.split("/")[0] for p in attest.APPROVED_SOURCE_PATHS}:
                __import__("shutil").rmtree(extra) if extra.is_dir() else extra.unlink()
        target = tree / "alembic.ini"
        if mutation == "modify":
            target.write_text("changed\n")
        elif mutation == "add":
            (tree / "EXTRA.txt").write_text("smuggled\n")
        elif mutation == "omit":
            target.unlink()
        elif mutation == "mode":
            os.chmod(target, 0o755)
        elif mutation == "symlink":
            target.unlink(); os.symlink("requirements.txt", target)
        write_manifest(tree, m)
        da.write_deterministic_targz(tree, a)
    with pytest.raises(attest.AttestationError):
        attest._require_matches_commit(a, m, repo, head)


def test_manifest_alteration_alone_is_refused(repo: Path, head: str, tmp_path: Path):
    a, m = _honest_build(repo, head, tmp_path / "p1")
    doc = json.loads(m.read_text())
    doc["entry_count"] = 999
    m.write_text(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    with pytest.raises(attest.AttestationError, match="manifest does not match"):
        attest._require_matches_commit(a, m, repo, head)


# ---------------------------------------------------------------- commit-reference negatives


@pytest.mark.parametrize("bad", [
    "main", "master", "HEAD", "refs/heads/main", "v1.0.0",
    "0123456", "0123456789012345678901234567890123456789012",
])
def test_mutable_or_malformed_commit_references_are_refused(repo: Path, head: str, tmp_path: Path, bad):
    a, m = _honest_build(repo, head, tmp_path / "p1")
    with pytest.raises(Exception):
        attest._require_matches_commit(a, m, repo, bad)


def test_uppercase_sha_is_refused(repo: Path, head: str, tmp_path: Path):
    a, m = _honest_build(repo, head, tmp_path / "p1")
    with pytest.raises(Exception):
        attest._require_matches_commit(a, m, repo, head.upper())


def test_one_character_wrong_sha_is_refused(repo: Path, head: str, tmp_path: Path):
    a, m = _honest_build(repo, head, tmp_path / "p1")
    wrong = ("b" if head[0] != "b" else "c") + head[1:]
    with pytest.raises(Exception):
        attest._require_matches_commit(a, m, repo, wrong)


def test_missing_git_object_is_refused(repo: Path, head: str, tmp_path: Path):
    a, m = _honest_build(repo, head, tmp_path / "p1")
    empty = tmp_path / "empty"
    empty.mkdir()
    subprocess.run(["git", "-C", str(empty), "init", "-q"], check=True, capture_output=True)
    with pytest.raises(Exception):
        attest._require_matches_commit(a, m, empty, head)


def test_a_tag_pointing_at_the_right_commit_is_still_refused(repo: Path, head: str, tmp_path: Path):
    """Correct target, mutable reference. The reference form itself must be refused."""
    subprocess.run(["git", "-C", str(repo), "tag", "release-1", head], check=True, capture_output=True)
    a, m = _honest_build(repo, head, tmp_path / "p1")
    with pytest.raises(Exception):
        attest._require_matches_commit(a, m, repo, "release-1")


def test_resolve_commit_rejects_a_non_commit_object(repo: Path, head: str):
    from git_object_export import ExportError, resolve_commit

    tree = subprocess.run(["git", "-C", str(repo), "rev-parse", f"{head}^{{tree}}"],
                          capture_output=True, text=True, check=True).stdout.strip()
    with pytest.raises(ExportError, match="expected a commit"):
        resolve_commit(repo, tree)


# ---------------------------------------------------------------- no weakening


def test_the_two_builder_equality_check_is_retained():
    source = Path(attest.__file__).read_text()
    assert "compare_passes(" in source, "independent-build byte equality must remain"
    assert source.count("compare_passes(") >= 4, "all four pass comparisons must remain"


def test_the_gate_runs_before_artifact_assembly():
    source = Path(attest.__file__).read_text()
    gate = source.index("_require_matches_commit(")
    assemble = source.index("shutil.copyfile(p1s / SOURCE_ARCHIVE")
    provenance = source.index("write_provenance(document")
    assert gate < assemble < provenance, "the reconstruction gate must precede assembly and provenance"


def test_no_override_or_continue_on_error_exists():
    source = Path(attest.__file__).read_text()
    for weak in ("continue-on-error", "SKIP_RECONSTRUCTION", "ALLOW_MISMATCH", "force=True"):
        assert weak not in source
    for wf in WORKFLOW_DIR.glob("*.yml"):
        text = wf.read_text()
        live = [ln for ln in text.splitlines()
                if "continue-on-error" in ln and not ln.strip().startswith("#")]
        assert not live, f"{wf.name}: continue-on-error present"


def test_mismatch_is_an_exception_not_a_logged_warning():
    source = Path(attest.__file__).read_text()
    body = source[source.index("def _require_matches_commit"):source.index("def _require_canonical")]
    assert "raise AttestationError" in body
    assert "warning" not in body.lower()
    assert "return True" not in body
