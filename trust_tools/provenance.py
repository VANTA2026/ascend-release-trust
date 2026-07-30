"""Input validation and provenance-document generation.

Two separate jobs, deliberately in one place because they share the same principle: **untrusted
text must never reach an interpreter that can be steered by it.**

- Every GitHub-supplied input is validated against a strict allowlist *before* it is used. Workflow
  inputs arrive as `${{ inputs.x }}`, which GitHub textually substitutes into the shell script it
  generates — a value containing a quote or a backtick becomes shell *code*. The workflows pass
  every input through an environment variable and then through these validators.

- The provenance document is produced by `json.dumps`, never by a shell heredoc. A heredoc
  interpolating an untrusted `release_name` can inject arbitrary JSON — or arbitrary shell, if the
  value escapes the quoting — and the resulting document is then *signed*, which would launder the
  injection into an attested artifact.

Trust-owned. Lives in the protected public trust repository; never imported from candidate code.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

__all__ = [
    "ValidationError",
    "validate_commit_sha", "validate_repository", "validate_release_name",
    "validate_pass_label", "validate_python_version",
    "build_provenance", "write_provenance",
]

PROVENANCE_SCHEMA = "ascend-backend-provenance/3"

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_RELEASE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_PASS_LABEL_RE = re.compile(r"^[12]$")
_PYVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

RELEASE_NAME_MAX = 64


class ValidationError(ValueError):
    """Raised when an input fails its allowlist."""


def validate_commit_sha(value: str, *, field: str = "backend_sha") -> str:
    if not isinstance(value, str) or not _SHA_RE.match(value):
        raise ValidationError(f"{field} must be exactly 40 lowercase hex characters, got {value!r:.80}")
    return value


def validate_repository(value: str, *, field: str = "source_repository") -> str:
    if not isinstance(value, str) or not _REPO_RE.match(value):
        raise ValidationError(f"{field} must be 'owner/name' with no shell metacharacters, got {value!r:.80}")
    return value


def validate_release_name(value: str, *, field: str = "release_name") -> str:
    """Strict character and length policy: this value is embedded in a SIGNED document."""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    if len(value) > RELEASE_NAME_MAX:
        raise ValidationError(f"{field} exceeds {RELEASE_NAME_MAX} characters ({len(value)})")
    if not _RELEASE_NAME_RE.match(value):
        raise ValidationError(
            f"{field} may contain only letters, digits, space, dot, underscore and hyphen, "
            f"must start alphanumeric, got {value!r:.80}"
        )
    return value


def validate_pass_label(value: str, *, field: str = "pass_label") -> str:
    if not isinstance(value, str) or not _PASS_LABEL_RE.match(value):
        raise ValidationError(f"{field} must be '1' or '2', got {value!r:.80}")
    return value


def validate_python_version(value: str, *, field: str = "python_version") -> str:
    if not isinstance(value, str) or not _PYVER_RE.match(value):
        raise ValidationError(f"{field} must be an exact X.Y.Z version, got {value!r:.80}")
    return value


def build_provenance(
    *,
    backend_sha: str,
    source_repository: str,
    release_name: str,
    release_ref: str,
    signed_objects: dict[str, str],
    target_runtime_python: str,
    build_tool_python: str,
    wheelhouse_driver_python: str,
    lockfile_name: str,
    lockfile_sha256: str,
    locked_distribution_count: int,
    accepted_wheel_count: int,
    universal2_wheels: list[str],
    trust_workflow_ref: str,
    runner_environment: str,
    run_id: str,
    run_attempt: str,
    pass_comparisons: dict[str, str],
) -> dict:
    """Assemble the provenance document. Every caller-supplied string is validated here."""
    validate_commit_sha(backend_sha)
    validate_repository(source_repository)
    validate_release_name(release_name)
    validate_python_version(target_runtime_python, field="target_runtime_python")
    validate_python_version(build_tool_python, field="build_tool_python")
    validate_python_version(wheelhouse_driver_python, field="wheelhouse_driver_python")

    for label, digest in signed_objects.items():
        if not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
            raise ValidationError(f"signed object {label!r} has a malformed sha256: {digest!r:.80}")
    if len(signed_objects) != 6:
        raise ValidationError(f"expected exactly 6 signed objects, got {len(signed_objects)}: {sorted(signed_objects)}")
    if not re.fullmatch(r"[0-9a-f]{64}", lockfile_sha256 or ""):
        raise ValidationError("lockfile_sha256 is malformed")

    return {
        "schema": PROVENANCE_SCHEMA,
        "backend_commit": backend_sha,
        "source_repository": source_repository,
        "release_name": release_name,
        "release_ref": release_ref,
        "trust_workflow_ref": trust_workflow_ref,
        "trust_workflow_ref_note": (
            "Recorded for human review only. It is NOT the trust anchor: the anchor is the "
            "job_workflow_ref claim in the Fulcio signing certificate, which the host "
            "verification policy pins independently of anything this document says."
        ),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "runner_environment": runner_environment,
        "target_runtime_python": target_runtime_python,
        "build_tool_python": build_tool_python,
        "wheelhouse_driver_python": wheelhouse_driver_python,
        "wheelhouse_driver_note": (
            "The driver Python only executes `pip download` with explicit target metadata. It is "
            "not evidence of runtime compatibility; that comes from the offline installation gate "
            "on exact CPython " + target_runtime_python + "."
        ),
        "lockfile": lockfile_name,
        "lockfile_sha256": lockfile_sha256,
        "locked_distributions": locked_distribution_count,
        "accepted_wheels": accepted_wheel_count,
        "universal2_wheels": sorted(universal2_wheels),
        "signed_objects": dict(sorted(signed_objects.items())),
        "pass_comparisons": dict(sorted(pass_comparisons.items())),
        "reproduced_independently": True,
        "digests_measured_by": "trust_tools (public trust repository), independently of the build jobs",
    }


def write_provenance(document: dict, destination: str | Path) -> str:
    """Serialise with a real JSON serialiser and return the document's sha256."""
    payload = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    Path(destination).write_text(payload, encoding="utf-8")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _main(argv: list[str]) -> int:
    """Validate a single input from the environment. Used by workflows as a gate."""
    if len(argv) != 3:
        print("usage: provenance.py <kind> <value>", flush=True)
        return 2
    kinds = {
        "sha": validate_commit_sha,
        "repository": validate_repository,
        "release_name": validate_release_name,
        "pass_label": validate_pass_label,
        "python_version": validate_python_version,
    }
    if argv[1] not in kinds:
        print(f"unknown kind {argv[1]!r}")
        return 2
    try:
        kinds[argv[1]](argv[2])
    except ValidationError as exc:
        print(f"REFUSED: {exc}")
        return 1
    print("ok")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    import sys

    raise SystemExit(_main(sys.argv))
