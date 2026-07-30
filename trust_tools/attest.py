"""The promotion decision, made entirely from bytes.

`compare-and-sign` calls exactly this. Nothing a build job *reported* is consulted: both passes of
both artifacts are downloaded and re-measured here, the lockfile is re-exported from the candidate's
Git object database by trust-owned code, and the wheel policy is re-evaluated from scratch against
the extracted wheelhouse. The build jobs are therefore untrusted producers, and this module is the
only place a digest becomes authoritative.

It emits exactly six objects for signing, and records every independently measured digest in the
provenance document.

Trust-owned. Lives in the protected public trust repository; never imported from candidate code.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from git_object_export import export_approved_paths, read_blob, list_approved_entries, resolve_commit
from lock_policy import load_validated_lock
from deterministic_archive import write_deterministic_targz
from manifest_policy import (ManifestError, compare_passes, sha256_file,
                             verify_archive_against_manifest, write_manifest)
from provenance import build_provenance, validate_commit_sha, validate_release_name, validate_repository, write_provenance
from wheelhouse_policy import evaluate_wheelhouse, policy_manifest

SOURCE_ARCHIVE = "ascend-backend-source.tar.gz"
SOURCE_MANIFEST = "ascend-backend-source-manifest.json"
WHEELHOUSE_ARCHIVE = "ascend-wheelhouse-macos-arm64.tar.gz"
WHEELHOUSE_POLICY_MANIFEST = "ascend-wheelhouse-policy-manifest.json"
LOCKFILE_NAME = "requirements.macos-arm64-py311.lock.txt"
PROVENANCE_NAME = "provenance-metadata.json"

# The exact approved release paths. This list MUST equal the APPROVED_PATHS env value in
# .github/workflows/_build-source.yml — a test asserts they agree, so the two cannot drift.
APPROVED_SOURCE_PATHS = [
    "src/backend",
    "migrations",
    "alembic.ini",
    "requirements.txt",
    "requirements.macos-arm64-py311.lock.txt",
    "tools/release",
]


class AttestationError(RuntimeError):
    pass


def _env(name: str, *, required: bool = True, default: str = "") -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise AttestationError(f"required environment variable {name} is unset")
    return value


def reconstruct_source_from_commit(candidate_repo: str | os.PathLike[str], backend_sha: str,
                                   workdir: Path) -> tuple[Path, Path, str]:
    """Rebuild the canonical source archive from the EXACT attested Git commit.

    Returns ``(archive_path, manifest_path, archive_sha256)``.

    Nothing from the downloaded artifact is an input here. The tree comes from the candidate's Git
    object database at the attested commit — never a worktree, never the branch head, never the
    current checkout — and is written into a freshly created directory so no untracked, ignored,
    generated or cached file can participate.
    """
    resolved, tree = resolve_commit(candidate_repo, backend_sha)
    if resolved != backend_sha:
        raise AttestationError(f"candidate repo resolved {resolved}, expected the attested {backend_sha}")

    export_root = workdir / "reconstructed"
    export_approved_paths(candidate_repo, backend_sha, APPROVED_SOURCE_PATHS, export_root)

    manifest_path = workdir / "reconstructed-manifest.json"
    write_manifest(export_root, manifest_path)
    archive_path = workdir / "reconstructed.tar.gz"
    digest = write_deterministic_targz(export_root, archive_path)
    print(f"  reconstructed from commit {backend_sha} (tree {tree}): sha256={digest}")
    return archive_path, manifest_path, digest


def _require_matches_commit(downloaded_archive: Path, downloaded_manifest: Path,
                            candidate_repo: str | os.PathLike[str], backend_sha: str) -> str:
    """THE gate: the signed source must be what the attested commit produces.

    Two independent build jobs agreeing proves they behaved identically — not that they built the
    right thing. If both were fed the same wrong tree, or both ran a subverted build, their outputs
    agree perfectly and the old check passed. This reconstructs the tree from Git objects with
    trust-owned code and demands the bytes match exactly.

    Both SHA-256 equality AND raw byte equality are required. Extracted-tree similarity, manifest
    similarity, file counts and builder agreement are explicitly NOT accepted as substitutes.
    """
    with tempfile.TemporaryDirectory() as tmp:
        rebuilt, rebuilt_manifest, rebuilt_digest = reconstruct_source_from_commit(
            candidate_repo, backend_sha, Path(tmp)
        )
        measured = sha256_file(downloaded_archive)
        if rebuilt_digest != measured:
            raise AttestationError(
                "source archive does not match a fresh export of the attested commit: "
                f"reconstructed {rebuilt_digest}, downloaded {measured} "
                f"(commit {backend_sha}). Two agreeing build jobs do not prove the tree is correct."
            )
        if rebuilt.read_bytes() != Path(downloaded_archive).read_bytes():
            raise AttestationError(
                "source archive differs byte-for-byte from the reconstruction despite an equal "
                "SHA-256 — refusing"
            )
        recorded = json.loads(Path(downloaded_manifest).read_text())
        rebuilt_manifest_doc = json.loads(rebuilt_manifest.read_text())
        if recorded != rebuilt_manifest_doc:
            raise AttestationError(
                "source manifest does not match the manifest of a fresh export of the attested commit"
            )
    return rebuilt_digest


def _require_canonical(archive: Path, extracted_root: Path, label: str) -> None:
    """Require the artifact to be EXACTLY what the deterministic writer produces from its content.

    Content equality is not enough. A gzip stream tolerates trailing bytes and a tar reader ignores
    them, so an attacker controlling both build runners could append arbitrary data to the artifact
    and still satisfy an extract-and-compare-the-manifest check — and that appended data would then
    be signed. Rebuilding from the verified tree and demanding byte equality closes that: the signed
    artifact must be the canonical encoding of its own verified content, with nothing extra.
    """
    from deterministic_archive import write_deterministic_targz

    with tempfile.TemporaryDirectory() as tmp:
        rebuilt = Path(tmp) / "canonical.tar.gz"
        write_deterministic_targz(extracted_root, rebuilt)
        if rebuilt.read_bytes() != Path(archive).read_bytes():
            raise AttestationError(
                f"{label} is not the canonical encoding of its own content: rebuilding it from the "
                f"verified tree yields different bytes (measured {sha256_file(archive)}, "
                f"canonical {sha256_file(rebuilt)})"
            )


def run(args: argparse.Namespace) -> int:
    backend_sha = validate_commit_sha(_env("IN_BACKEND_SHA"))
    source_repository = validate_repository(_env("IN_SOURCE_REPOSITORY"))
    release_name = validate_release_name(_env("IN_RELEASE_NAME", required=False, default="unlabelled"))

    required_sha = _env("REQUIRED_BACKEND_SHA")
    if backend_sha != required_sha:
        raise AttestationError(f"refusing: this workflow builds only {required_sha}")

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    p1s, p2s = Path(args.source_pass1), Path(args.source_pass2)
    p1w, p2w = Path(args.wheelhouse_pass1), Path(args.wheelhouse_pass2)

    # --- 1. byte-compare both passes of both artifacts, by measuring them ------------------
    comparisons = {
        "source_archive": compare_passes("source archive", p1s / SOURCE_ARCHIVE, p2s / SOURCE_ARCHIVE),
        "source_manifest": compare_passes("source manifest", p1s / SOURCE_MANIFEST, p2s / SOURCE_MANIFEST),
        "wheelhouse_archive": compare_passes("wheelhouse archive", p1w / WHEELHOUSE_ARCHIVE, p2w / WHEELHOUSE_ARCHIVE),
        "wheelhouse_policy_manifest": compare_passes(
            "wheelhouse policy manifest", p1w / WHEELHOUSE_POLICY_MANIFEST, p2w / WHEELHOUSE_POLICY_MANIFEST
        ),
    }
    for label, c in comparisons.items():
        print(f"  agree  {label}: {c.pass1_sha256}")

    # --- 2. re-export the lockfile from Git objects, with trust-owned code -----------------
    with tempfile.TemporaryDirectory() as tmp:
        lock_export = Path(tmp) / "lock"
        export_approved_paths(args.candidate_repo, backend_sha, [LOCKFILE_NAME], lock_export)
        lock_source = lock_export / LOCKFILE_NAME
        shutil.copyfile(lock_source, out / LOCKFILE_NAME)
    lock = load_validated_lock(out / LOCKFILE_NAME)
    lockfile_sha256 = lock.sha256
    print(f"  lock: {len(lock.distributions)} distributions, sha256={lockfile_sha256}")

    # --- 3. THE RECONSTRUCTION GATE -------------------------------------------------------
    # Two agreeing build jobs prove only that they behaved identically. Before anything reaches
    # the signer, rebuild the source from the attested commit's Git objects with trust-owned code
    # and require exact byte equality. This runs BEFORE the six objects are assembled, so a
    # mismatch raises and no later step — including signing — is reachable.
    reconstructed_digest = _require_matches_commit(
        p1s / SOURCE_ARCHIVE, p1s / SOURCE_MANIFEST, args.candidate_repo, backend_sha
    )
    print(f"  source reconstructed from {backend_sha} and byte-identical: {reconstructed_digest}")

    # --- 4. verify the source artifact re-extracts to exactly its manifest -----------------
    shutil.copyfile(p1s / SOURCE_ARCHIVE, out / SOURCE_ARCHIVE)
    shutil.copyfile(p1s / SOURCE_MANIFEST, out / SOURCE_MANIFEST)
    with tempfile.TemporaryDirectory() as tmp:
        recomputed = verify_archive_against_manifest(out / SOURCE_ARCHIVE, out / SOURCE_MANIFEST, tmp)
        _require_canonical(out / SOURCE_ARCHIVE, Path(tmp) / "extracted", "source archive")
    print(f"  source round-trip verified and canonical: {recomputed['entry_count']} entries")

    # --- 5. re-run the wheel policy from scratch on the extracted wheelhouse ---------------
    shutil.copyfile(p1w / WHEELHOUSE_ARCHIVE, out / WHEELHOUSE_ARCHIVE)
    with tempfile.TemporaryDirectory() as tmp:
        from manifest_policy import safe_extract

        wheel_root = Path(tmp) / "wheels"
        safe_extract(out / WHEELHOUSE_ARCHIVE, wheel_root)
        _require_canonical(out / WHEELHOUSE_ARCHIVE, wheel_root, "wheelhouse archive")
        wheels = sorted(p for p in wheel_root.rglob("*") if p.is_file())
        verdict = evaluate_wheelhouse(wheels, lock)
        if not verdict.ok:
            details = [f"{d.filename}: {d.reason}" for d in verdict.refused] + verdict.problems
            raise AttestationError("wheelhouse failed the trust-owned policy:\n  - " + "\n  - ".join(details))
        independent_manifest = policy_manifest(verdict, lock)

    # The build job's policy manifest must equal the one derived here, independently.
    reported = json.loads((p1w / WHEELHOUSE_POLICY_MANIFEST).read_text(encoding="utf-8"))
    if reported != independent_manifest:
        raise AttestationError(
            "the build job's wheelhouse policy manifest does not match an independent re-derivation"
        )
    payload = json.dumps(independent_manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    (out / WHEELHOUSE_POLICY_MANIFEST).write_text(payload, encoding="utf-8")
    print(f"  wheelhouse policy re-derived independently: {len(verdict.accepted)} wheels")

    # --- 6. measure the five objects, then build and measure the sixth ---------------------
    signed_objects = {
        SOURCE_ARCHIVE: sha256_file(out / SOURCE_ARCHIVE),  # == reconstructed_digest, asserted below
        SOURCE_MANIFEST: sha256_file(out / SOURCE_MANIFEST),
        WHEELHOUSE_ARCHIVE: sha256_file(out / WHEELHOUSE_ARCHIVE),
        WHEELHOUSE_POLICY_MANIFEST: sha256_file(out / WHEELHOUSE_POLICY_MANIFEST),
        LOCKFILE_NAME: sha256_file(out / LOCKFILE_NAME),
        PROVENANCE_NAME: "0" * 64,  # placeholder; replaced below once the document exists
    }

    if signed_objects[SOURCE_ARCHIVE] != reconstructed_digest:
        raise AttestationError("source digest drifted from the reconstruction after assembly")

    document = build_provenance(
        backend_sha=backend_sha,
        source_repository=source_repository,
        release_name=release_name,
        release_ref=_env("REQUIRED_RELEASE_REF"),
        signed_objects=signed_objects,
        target_runtime_python=_env("TARGET_RUNTIME_PYTHON"),
        build_tool_python=_env("BUILD_TOOL_PYTHON"),
        wheelhouse_driver_python=_env("DRIVER_PYTHON_1"),
        lockfile_name=LOCKFILE_NAME,
        lockfile_sha256=lockfile_sha256,
        locked_distribution_count=len(lock.distributions),
        accepted_wheel_count=len(verdict.accepted),
        universal2_wheels=verdict.universal2,
        trust_workflow_ref=_env("TRUST_WORKFLOW_REF", required=False, default="unrecorded"),
        runner_environment=_env("RUNNER_ENVIRONMENT", required=False, default="unknown"),
        run_id=_env("GITHUB_RUN_ID", required=False, default="0"),
        run_attempt=_env("GITHUB_RUN_ATTEMPT", required=False, default="0"),
        pass_comparisons={k: c.pass1_sha256 for k, c in comparisons.items()},
    )
    # The provenance document cannot contain its own digest; it names the other five and is itself
    # the sixth signed object, so its integrity comes from its own signature.
    document["signed_objects"][PROVENANCE_NAME] = "self"
    document["signed_object_count"] = 6
    digest = write_provenance(document, out / PROVENANCE_NAME)
    print(f"  provenance written: sha256={digest}")

    both = [DRIVER := _env("DRIVER_PYTHON_1"), _env("DRIVER_PYTHON_2")]
    if both[0] != both[1]:
        raise AttestationError(f"the two wheelhouse passes used different driver Pythons: {both}")

    produced = sorted(p.name for p in out.iterdir())
    expected = sorted([SOURCE_ARCHIVE, SOURCE_MANIFEST, WHEELHOUSE_ARCHIVE,
                       WHEELHOUSE_POLICY_MANIFEST, LOCKFILE_NAME, PROVENANCE_NAME])
    if produced != expected:
        raise AttestationError(f"output directory must contain exactly the six signed objects; got {produced}")
    print("  six objects ready for signing")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Independently measure both passes and assemble provenance.")
    parser.add_argument("--source-pass1", required=True)
    parser.add_argument("--source-pass2", required=True)
    parser.add_argument("--wheelhouse-pass1", required=True)
    parser.add_argument("--wheelhouse-pass2", required=True)
    parser.add_argument("--candidate-repo", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv[1:])
    try:
        return run(args)
    except (AttestationError, ManifestError) as exc:
        print(f"::error::{exc}")
        return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main(sys.argv))
