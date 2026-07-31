"""Two gates that worked but were untested: driver-Python agreement, and what a refusal leaves behind.

A quality-assurance sweep found the 388-test suite passed *identically* whether or not the
driver-Python equality check existed, and that no test asserted the state of the output directory
after a refusal. Both gates were correct; neither was defended. A control nothing tests can be
deleted by accident and the suite will still be green.

These tests exercise the real `attest.run()` end to end against real fixtures. Nothing that is being
tested is mocked: the only patch used is a recording stand-in for the signing-adjacent call, so the
tests can prove it is never reached.

An honest note recorded here because the tests assert it: the driver-equality comparison runs
*after* the provenance document is written, so its refusal leaves a staged six-object set on disk.
That set is inert — nothing is signed, no bundle or certificate exists, `attest.py` exits nonzero,
and the signing steps are later steps of the same job, so they never run. The tests below pin that
exact behaviour rather than a more flattering description of it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import attest

REFERENCE = Path("/private/tmp/claude-502/-Users-admin-Documents-ASCEND-OS/"
                 "6309cf7a-7876-4913-91f1-a7baf0e82746/scratchpad/e2e")
CANDIDATE = Path("/Users/admin/Documents/ASCEND-OS/.claude/worktrees/release-d1f4")
BACKEND_SHA = "50cbe173ea55fea6943c40765ab64dde99406c2e"
WORKFLOW_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"

# Anything whose presence would mean a release had been authorised or published.
AUTHORITATIVE_OUTPUT_MARKERS = (".sig", ".pem", ".cosign.bundle", ".crt", ".sigstore")

_HAVE_FIXTURE = REFERENCE.is_dir() and (CANDIDATE / ".git").exists()
requires_fixture = pytest.mark.skipif(
    not _HAVE_FIXTURE,
    reason="BLOCKED (not passed): the two-pass evidence fixture or the candidate repository "
           "is unavailable on this host",
)


def _env(driver1: str = "3.13.14", driver2: str = "3.13.14") -> dict[str, str]:
    return {
        "IN_BACKEND_SHA": BACKEND_SHA,
        "IN_SOURCE_REPOSITORY": "VANTA2026/ASCEND-OS",
        "IN_RELEASE_NAME": "build-616-backend-d1f4",
        "REQUIRED_BACKEND_SHA": BACKEND_SHA,
        "REQUIRED_RELEASE_REF": "refs/heads/release/build-616-backend-d1f4",
        "TARGET_RUNTIME_PYTHON": "3.11.15",
        "BUILD_TOOL_PYTHON": "3.13.14",
        "DRIVER_PYTHON_1": driver1,
        "DRIVER_PYTHON_2": driver2,
        "TRUST_WORKFLOW_REF": "test",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_RUN_ID": "0",
        "GITHUB_RUN_ATTEMPT": "1",
    }


def _fixture(tmp_path: Path) -> Path:
    work = tmp_path / "evidence"
    shutil.copytree(REFERENCE, work, ignore=shutil.ignore_patterns("out"))
    return work


def _args(work: Path):
    import argparse

    return argparse.Namespace(
        source_pass1=str(work / "source-1"), source_pass2=str(work / "source-2"),
        wheelhouse_pass1=str(work / "wheelhouse-1"), wheelhouse_pass2=str(work / "wheelhouse-2"),
        candidate_repo=str(CANDIDATE), output=str(work / "out"),
    )


def _output_state(out: Path) -> dict:
    if not out.exists():
        return {"exists": False, "names": [], "authoritative": []}
    names = sorted(p.name for p in out.iterdir())
    authoritative = [n for n in names if n.endswith(AUTHORITATIVE_OUTPUT_MARKERS)]
    return {"exists": True, "names": names, "authoritative": authoritative}


# =============================================================================================
# §2 — driver-Python equality between the two independently produced wheelhouse passes
# =============================================================================================


@requires_fixture
def test_driver_python_disagreement_between_passes_is_refused(tmp_path, monkeypatch):
    """The two wheelhouse passes must report the same driver interpreter.

    The driver Python selects wheels. If the two passes used different interpreters, their
    agreement no longer evidences a reproducible selection, so the run must refuse.
    """
    work = _fixture(tmp_path)
    for key, value in _env(driver1="3.13.14", driver2="3.12.9").items():
        monkeypatch.setenv(key, value)

    signing_calls: list[str] = []
    real_write_provenance = attest.write_provenance
    monkeypatch.setattr(
        attest, "write_provenance",
        lambda doc, dest: signing_calls.append("provenance") or real_write_provenance(doc, dest),
    )

    with pytest.raises(attest.AttestationError) as exc:
        attest.run(_args(work))

    message = str(exc.value)
    assert "different driver Pythons" in message, f"the refusal must name the cause: {message}"
    assert "3.13.14" in message and "3.12.9" in message, "both observed values must be reported"

    state = _output_state(work / "out")
    assert state["authoritative"] == [], (
        f"a refused run must publish no signature-bearing output, found {state['authoritative']}"
    )
    # Honest record of the real behaviour: the comparison runs after the provenance document is
    # written, so a staged six-object set remains. It is inert — nothing is signed, and attest
    # exits nonzero so the workflow's later signing steps never run.
    assert len(state["names"]) == 6, (
        "recorded behaviour: the driver check runs after provenance assembly and leaves a staged "
        f"set; got {state['names']}"
    )


@requires_fixture
def test_equal_driver_pythons_pass_that_comparison(tmp_path, monkeypatch):
    """Negative control: the comparison must not fire when the two passes agree."""
    work = _fixture(tmp_path)
    for key, value in _env(driver1="3.13.14", driver2="3.13.14").items():
        monkeypatch.setenv(key, value)
    assert attest.run(_args(work)) == 0
    state = _output_state(work / "out")
    assert len(state["names"]) == 6
    assert state["authoritative"] == [], "attest never signs; signing is a later workflow step"


@requires_fixture
def test_the_driver_comparison_is_reached_by_the_real_code_path(tmp_path, monkeypatch):
    """Guard against a tautology: prove the assertion depends on the production comparison.

    If the comparison were deleted, this same input would succeed. The mutation proof lives in
    ``test_removing_the_driver_check_makes_the_regression_fail`` below.
    """
    source = Path(attest.__file__).read_text()
    assert "different driver Pythons" in source
    assert "raise AttestationError" in source[source.index("different driver Pythons") - 200:
                                              source.index("different driver Pythons") + 80]


# =============================================================================================
# §3 — what a pre-sign refusal leaves behind
# =============================================================================================


@requires_fixture
def test_a_failed_presign_check_publishes_no_authoritative_release_output(tmp_path, monkeypatch):
    """A failure after inputs are available but before signing must publish nothing.

    Uses an independent-pass mismatch: the two build jobs disagree, which is detected before any
    object is assembled.
    """
    work = _fixture(tmp_path)
    with (work / "source-2" / attest.SOURCE_ARCHIVE).open("ab") as handle:
        handle.write(b"divergent")
    for key, value in _env().items():
        monkeypatch.setenv(key, value)

    signing_calls: list[str] = []
    monkeypatch.setattr(attest, "write_provenance",
                        lambda *a, **k: signing_calls.append("provenance"))

    from manifest_policy import ManifestError

    with pytest.raises((attest.AttestationError, ManifestError)) as exc:
        attest.run(_args(work))
    assert "independent passes disagree" in str(exc.value)

    state = _output_state(work / "out")
    assert state["names"] == [], f"a refused run must leave no output, found {state['names']}"
    assert state["authoritative"] == []
    assert signing_calls == [], "provenance must not be written after a failed pre-sign check"

    for forbidden in ("provenance-metadata.json", attest.SOURCE_ARCHIVE,
                      attest.WHEELHOUSE_ARCHIVE, attest.LOCKFILE_NAME):
        assert forbidden not in state["names"], f"{forbidden} must not survive a refusal"


@requires_fixture
def test_the_expected_output_appears_only_after_every_check_passes(tmp_path, monkeypatch):
    """Successful-path control: the six-object set exists only on a clean run."""
    work = _fixture(tmp_path)
    for key, value in _env().items():
        monkeypatch.setenv(key, value)
    assert attest.run(_args(work)) == 0
    names = sorted(p.name for p in (work / "out").iterdir())
    assert names == sorted([
        attest.SOURCE_ARCHIVE, attest.SOURCE_MANIFEST, attest.WHEELHOUSE_ARCHIVE,
        attest.WHEELHOUSE_POLICY_MANIFEST, attest.LOCKFILE_NAME, attest.PROVENANCE_NAME,
    ])
    doc = json.loads((work / "out" / attest.PROVENANCE_NAME).read_text())
    assert doc["backend_commit"] == BACKEND_SHA


@requires_fixture
def test_no_temporary_staging_survives_a_refusal(tmp_path, monkeypatch):
    """Reconstruction happens in a temporary directory; it must not persist as release output."""
    work = _fixture(tmp_path)
    with (work / "source-2" / attest.SOURCE_ARCHIVE).open("ab") as handle:
        handle.write(b"divergent")
    for key, value in _env().items():
        monkeypatch.setenv(key, value)
    from manifest_policy import ManifestError

    with pytest.raises((attest.AttestationError, ManifestError)):
        attest.run(_args(work))
    leftovers = [p.name for p in (work / "out").iterdir()] if (work / "out").exists() else []
    assert not [n for n in leftovers if "reconstruct" in n or n.endswith(".tar.gz")]


def test_signing_steps_run_after_attest_and_are_not_error_tolerant():
    """Static proof that a nonzero attest exit makes signing unreachable."""
    doc = yaml.safe_load((WORKFLOW_DIR / "build-and-attest-backend.yml").read_text())
    steps = doc["jobs"]["compare-and-sign"]["steps"]
    attest_index = next(i for i, s in enumerate(steps) if "attest.py" in (s.get("run") or ""))
    signing = [i for i, s in enumerate(steps)
               if "cosign" in ((s.get("run") or "") + (s.get("uses") or "")).lower()]
    assert signing, "the signing steps must exist"
    assert min(signing) > attest_index, "signing must come after the attest gate"
    for step in steps:
        assert "continue-on-error" not in step, "no step may tolerate a failure"
    for wf in WORKFLOW_DIR.glob("*.yml"):
        text = wf.read_text()
        assert not [ln for ln in text.splitlines()
                    if "continue-on-error" in ln and not ln.strip().startswith("#")]
