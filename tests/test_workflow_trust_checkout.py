"""The trust checkout must fetch the TRUST repository, at the commit defining the running job.

This suite exists because of a real failure. In run 30571193992 the workflows checked out "the
trust repository" with `actions/checkout` and no `repository:` input. Inside a reusable workflow
that input defaults to `github.repository` — the CALLER's repository — so the job checked out the
candidate repo into `trust/` and could not find `trust_tools/`. It failed closed before signing, but
had it been a later job the workflow would have loaded its own *measuring code* from the repository
it was supposed to be measuring.

The correct anchor is the `job.workflow_*` family, which identifies the workflow file defining the
current job (for jobs in a reusable workflow, that is the reusable workflow file — unlike
`github.workflow_*`, which follows the caller).

These tests parse the committed YAML; they are not a description of intent.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

WORKFLOW_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"
WORKFLOWS = sorted(WORKFLOW_DIR.glob("*.yml"))
TRUST_REPOSITORY = "VANTA2026/ascend-release-trust"

TRUST_MODULES = [
    "attest", "deterministic_archive", "git_object_export",
    "lock_policy", "manifest_policy", "provenance", "wheelhouse_policy",
]


def _doc(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _jobs(path: Path) -> dict:
    return _doc(path).get("jobs") or {}


def _steps(job: dict) -> list[dict]:
    return job.get("steps") or []


def _trust_checkout_steps(path: Path):
    for job_name, job in _jobs(path).items():
        for step in _steps(job):
            uses = step.get("uses", "")
            with_ = step.get("with") or {}
            if uses.startswith("actions/checkout@") and with_.get("path") == "trust":
                yield job_name, step, with_


def test_workflows_exist():
    assert len(WORKFLOWS) == 3, [w.name for w in WORKFLOWS]


# --------------------------------------------------------------------------------------------
# 1 / 2 / 9 / 10 — the exact failure


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_trust_checkout_names_repository_and_ref(path: Path):
    """(2) Both inputs required. (1) A checkout without `repository:` is categorically forbidden."""
    found = list(_trust_checkout_steps(path))
    assert found, f"{path.name} has no trust checkout"
    for job_name, _step, with_ in found:
        assert with_.get("repository") == "${{ job.workflow_repository }}", (
            f"{path.name}:{job_name} trust checkout must set "
            f"repository: ${{{{ job.workflow_repository }}}}, got {with_.get('repository')!r}"
        )
        assert with_.get("ref") == "${{ job.workflow_sha }}", (
            f"{path.name}:{job_name} trust checkout must set "
            f"ref: ${{{{ job.workflow_sha }}}}, got {with_.get('ref')!r}"
        )


def test_the_exact_failed_configuration_from_run_30571193992_is_detected():
    """(10) Reconstruct the failed step and prove the rule above rejects it."""
    failed_step = {
        "name": "Check out the TRUST repository (this repo, at the pinned commit)",
        "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "with": {"persist-credentials": False, "path": "trust"},
    }
    with_ = failed_step["with"]
    assert "repository" not in with_, "the failed config omitted repository:, which is the defect"
    assert with_.get("repository") != "${{ job.workflow_repository }}"
    assert with_.get("ref") != "${{ job.workflow_sha }}"


def test_removing_the_explicit_trust_checkout_fails_validation():
    """(9) The validator must fail when the checkout is absent, not pass vacuously."""
    doc = {"jobs": {"j": {"steps": [{"uses": "actions/checkout@abc", "with": {"path": "trust"}}]}}}
    steps = doc["jobs"]["j"]["steps"]
    offending = [s for s in steps if (s.get("with") or {}).get("repository") != "${{ job.workflow_repository }}"]
    assert offending, "a trust checkout lacking repository: must be reported"


# --------------------------------------------------------------------------------------------
# 3 / 4 / 5 / 6 — forbidden anchors


FORBIDDEN_EXPRESSIONS = [
    r"\$\{\{\s*github\.repository\s*\}\}",
    r"\$\{\{\s*github\.workflow_sha\s*\}\}",
    r"\$\{\{\s*github\.workflow_ref\s*\}\}",
    r"\$\{\{\s*github\.sha\s*\}\}",
    r"\$GITHUB_SHA",
    r"\$\{GITHUB_SHA",
    r"GITHUB_WORKFLOW_REF",
]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
@pytest.mark.parametrize("pattern", FORBIDDEN_EXPRESSIONS)
def test_forbidden_identity_expressions_are_absent(path: Path, pattern: str):
    """(3)(4)(5) github.* follows the CALLER in a reusable workflow and must never anchor trust."""
    text = path.read_text()
    live = [
        line for line in text.splitlines()
        if re.search(pattern, line) and not line.strip().startswith("#")
    ]
    assert not live, f"{path.name}: forbidden identity expression {pattern}: {live[:2]}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_trust_checkout_uses_a_branch_or_tag(path: Path):
    """(6) A moving reference would let the trusted code change after the operator pinned it."""
    for job_name, _step, with_ in _trust_checkout_steps(path):
        ref = str(with_.get("ref", ""))
        assert ref == "${{ job.workflow_sha }}", f"{path.name}:{job_name} ref={ref!r}"
        assert ref not in ("main", "master", "HEAD"), f"{path.name}:{job_name} uses a moving ref"
        assert not re.match(r"^v?\d+(\.\d+)*$", ref), f"{path.name}:{job_name} uses a tag"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_the_trust_sha_is_never_a_workflow_input(path: Path):
    """A caller-supplied trust SHA would hand the trust anchor to the candidate."""
    doc = _doc(path)
    on = doc.get(True) or doc.get("on") or {}
    inputs = (on.get("workflow_call") or {}).get("inputs") or {}
    for name in inputs:
        assert "trust" not in name.lower(), f"{path.name}: input {name!r} may select trust code"
    for _job_name, _step, with_ in _trust_checkout_steps(path):
        assert "inputs." not in str(with_.get("ref", "")), f"{path.name}: trust ref from an input"
        assert "inputs." not in str(with_.get("repository", "")), f"{path.name}: trust repo from an input"


# --------------------------------------------------------------------------------------------
# 7 — independent verification in all three workflows


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_job_with_a_trust_checkout_asserts_its_identity(path: Path):
    """(7) Each workflow independently verifies repository, sha and file path — fail closed."""
    expected_file = f".github/workflows/{path.name}"
    for job_name, job in _jobs(path).items():
        steps = _steps(job)
        has_checkout = any(
            s.get("uses", "").startswith("actions/checkout@") and (s.get("with") or {}).get("path") == "trust"
            for s in steps
        )
        if not has_checkout:
            continue
        assertion = [s for s in steps if "Assert the workflow identity" in (s.get("name") or "")]
        assert assertion, f"{path.name}:{job_name} has a trust checkout but no identity assertion"
        env = assertion[0].get("env") or {}
        assert env.get("JOB_WORKFLOW_REPOSITORY") == "${{ job.workflow_repository }}"
        assert env.get("JOB_WORKFLOW_SHA") == "${{ job.workflow_sha }}"
        assert env.get("JOB_WORKFLOW_FILE_PATH") == "${{ job.workflow_file_path }}"
        assert env.get("JOB_WORKFLOW_REF") == "${{ job.workflow_ref }}"
        assert env.get("EXPECTED_TRUST_REPOSITORY") == TRUST_REPOSITORY
        assert env.get("EXPECTED_TRUST_WORKFLOW_FILE") == expected_file, (
            f"{path.name}:{job_name} expects {env.get('EXPECTED_TRUST_WORKFLOW_FILE')!r}"
        )
        body = assertion[0].get("run") or ""
        assert "exit 1" in body, "the assertion must fail closed"
        assert "rev-parse HEAD" in body, "must confirm the checkout HEAD equals job.workflow_sha"
        assert "trust/trust_tools" in body, "must confirm trust_tools exists in the trust checkout"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_job_context_values_are_passed_through_env_not_interpolated_into_shell(path: Path):
    """Interpolating a value into shell source makes it code; through env it stays data."""
    for _job_name, job in _jobs(path).items():
        for step in _steps(job):
            body = step.get("run")
            if not body:
                continue
            live = [ln for ln in body.splitlines() if "${{" in ln and not ln.strip().startswith("#")]
            assert not live, f"{path.name}: expression interpolated into shell source: {live[:2]}"


# --------------------------------------------------------------------------------------------
# 8 — candidate isolation


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_the_candidate_checkout_uses_a_distinct_path(path: Path):
    for _job_name, job in _jobs(path).items():
        for step in _steps(job):
            with_ = step.get("with") or {}
            if step.get("uses", "").startswith("actions/checkout@") and with_.get("repository", "").startswith("${{ inputs."):
                assert with_.get("path") == "source", "the candidate must be checked out at 'source'"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_trust_tool_is_executed_from_the_candidate_checkout(path: Path):
    """(8) A candidate shipping malicious trust_tools must be unusable — nothing runs from source/."""
    text = path.read_text()
    offenders = re.findall(r"(?m)^\s*[^#\n]*\bpython[^\n]*\bsource/(?:trust_tools|tools)/[^\n]*", text)
    assert not offenders, f"{path.name}: executes code from the candidate checkout: {offenders[:2]}"
    # `source/trust_tools` may appear ONLY inside the guard that refuses such a candidate — never
    # on a line that would add it to an import path or execute it.
    for line in text.splitlines():
        if "source/trust_tools" not in line:
            continue
        guard = ("-e source/trust_tools" in line) or ("refusing" in line)
        assert guard, f"{path.name}: non-guard reference to the candidate's trust_tools: {line.strip()!r}"
        assert "PYTHONPATH" not in line and "python " not in line, (
            f"{path.name}: candidate trust_tools reached an import path: {line.strip()!r}"
        )


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_trust_code_is_referenced_only_under_the_trust_checkout(path: Path):
    text = path.read_text()
    for module in TRUST_MODULES:
        for match in re.finditer(rf"[\w/.$-]*{module}\.py", text):
            ref = match.group(0)
            if ref.startswith("#"):
                continue
            assert "source/" not in ref, f"{path.name}: {module}.py referenced under the candidate: {ref}"


def test_a_simulated_malicious_candidate_cannot_supply_trust_tools(tmp_path):
    """(8) The assertion refuses a candidate checkout that contains trust_tools at all."""
    candidate = tmp_path / "source"
    (candidate / "trust_tools").mkdir(parents=True)
    (candidate / "trust_tools" / "attest.py").write_text("raise SystemExit('PWNED')\n")
    guard_text = (WORKFLOW_DIR / "build-and-attest-backend.yml").read_text()
    assert "the candidate checkout contains trust_tools; refusing" in guard_text
    assert (candidate / "trust_tools").exists(), "the hostile layout the guard must reject"
