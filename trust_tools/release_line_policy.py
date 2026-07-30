"""Prove that the candidate commit is contained in the approved private release line.

The earlier implementation ran `git fetch` inside the candidate checkout. That checkout is created
with `persist-credentials: false` — deliberately, so no token is left on disk — so the fetch could
not authenticate against the private repository and the job failed (run 30578134633). Restoring
credentials to git would have solved the symptom by weakening the reason the checkout is safe.

Instead, ancestry is proven over the GitHub REST API with the caller-scoped job token, held only in
memory for the life of the step, while the checkout stays credential-free. The two are separate
controls and must stay separate:

    the API      proves release-line ancestry
    the checkout provides the exact candidate Git objects

The repository and branch are **fixed constants here**, not caller inputs. A caller that could name
the repository or the branch could point the ancestry proof at something it controls; the only
candidate-supplied value is the 40-hex commit SHA, and even that is re-checked against what the API
returns.

Everything fails closed: any non-200, malformed body, timeout, identity mismatch, or unexpected
compare status is a refusal.

Trust-owned. Lives in the protected public trust repository; never imported from candidate code.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

__all__ = [
    "AncestryError", "AncestryProof",
    "EXPECTED_REPOSITORY", "EXPECTED_RELEASE_BRANCH",
    "prove_release_line_ancestry",
]

# Fixed trust-owned constants. NOT caller inputs.
EXPECTED_REPOSITORY = "VANTA2026/ASCEND-OS"
EXPECTED_RELEASE_BRANCH = "release/build-616-backend-d1f4"

API_ROOT = "https://api.github.com"
REQUEST_TIMEOUT_SECONDS = 30
ACCEPTED_STATUSES = ("identical", "ahead")

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class AncestryError(RuntimeError):
    """Raised when release-line containment cannot be proven. Always fail closed."""


@dataclass(frozen=True)
class AncestryProof:
    repository: str
    branch: str
    candidate_sha: str
    branch_head_sha: str
    merge_base_sha: str
    status: str

    def render(self) -> str:
        return (
            "release-line ancestry verified:\n"
            f"  repository={self.repository}\n"
            f"  branch={self.branch}\n"
            f"  candidate={self.candidate_sha}\n"
            f"  branch_head={self.branch_head_sha}\n"
            f"  merge_base={self.merge_base_sha}\n"
            f"  status={self.status}"
        )


def _validate_sha(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.match(value):
        raise AncestryError(f"{field} must be exactly 40 lowercase hex characters, got {value!r:.60}")
    return value


def _api_get(path: str, token: str, *, opener=None) -> dict:
    """Authenticated GET returning parsed JSON. The token never leaves the request header."""
    url = f"{API_ROOT}{path}"
    request = urllib.request.Request(url, method="GET")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("User-Agent", "ascend-release-trust")
    try:
        opener = opener or urllib.request.urlopen
        with opener(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", None) or response.getcode()
            if status != 200:
                raise AncestryError(f"GET {path} returned HTTP {status}")
            body = response.read()
    except urllib.error.HTTPError as exc:  # 401 / 403 / 404 / 5xx
        raise AncestryError(f"GET {path} failed with HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise AncestryError(f"GET {path} failed: {exc.reason}") from None
    except TimeoutError:
        raise AncestryError(f"GET {path} timed out after {REQUEST_TIMEOUT_SECONDS}s") from None
    except AncestryError:
        raise
    except Exception as exc:  # noqa: BLE001 - any transport failure is a refusal
        raise AncestryError(f"GET {path} failed: {type(exc).__name__}") from None

    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise AncestryError(f"GET {path} returned a malformed JSON body") from None
    if not isinstance(parsed, dict):
        raise AncestryError(f"GET {path} returned {type(parsed).__name__}, expected an object")
    return parsed


def _resolve_branch_head(token: str, *, opener=None) -> str:
    """Resolve the fixed approved branch to its current head SHA."""
    quoted = urllib.parse.quote(EXPECTED_RELEASE_BRANCH, safe="")
    payload = _api_get(f"/repos/{EXPECTED_REPOSITORY}/branches/{quoted}", token, opener=opener)

    name = payload.get("name")
    if name != EXPECTED_RELEASE_BRANCH:
        raise AncestryError(f"branch endpoint returned name {name!r}, expected {EXPECTED_RELEASE_BRANCH!r}")

    # If the response identifies a repository, it must be the fixed one.
    repo = ((payload.get("_links") or {}).get("html") or "")
    if repo and EXPECTED_REPOSITORY not in repo:
        raise AncestryError(f"branch endpoint response does not belong to {EXPECTED_REPOSITORY}")

    head = ((payload.get("commit") or {}).get("sha")) or ""
    if not head:
        raise AncestryError("branch endpoint returned no commit sha")
    return _validate_sha(head, field="branch head sha")


def _assert_commit_exists(candidate_sha: str, token: str, *, opener=None) -> None:
    """The candidate must exist in the fixed repository, at exactly that full SHA."""
    payload = _api_get(f"/repos/{EXPECTED_REPOSITORY}/commits/{candidate_sha}", token, opener=opener)
    returned = payload.get("sha")
    if returned != candidate_sha:
        raise AncestryError(f"commit endpoint returned sha {returned!r}, expected {candidate_sha!r}")


def _compare(candidate_sha: str, head_sha: str, token: str, *, opener=None) -> tuple[str, str, str]:
    """Compare candidate...branch_head. Returns (status, base_commit_sha, merge_base_sha)."""
    path = f"/repos/{EXPECTED_REPOSITORY}/compare/{candidate_sha}...{head_sha}"
    payload = _api_get(path, token, opener=opener)

    status = payload.get("status")
    if not isinstance(status, str) or not status:
        raise AncestryError("compare response has no status field")

    base_commit = payload.get("base_commit")
    if not isinstance(base_commit, dict) or "sha" not in base_commit:
        raise AncestryError("compare response has no base_commit")
    merge_base = payload.get("merge_base_commit")
    if not isinstance(merge_base, dict) or "sha" not in merge_base:
        raise AncestryError("compare response has no merge_base_commit")

    return status, base_commit["sha"], merge_base["sha"]


def prove_release_line_ancestry(candidate_sha: str, token: str, *, opener=None) -> AncestryProof:
    """Prove the candidate is contained in the approved release line, or raise."""
    if not token:
        raise AncestryError("no API token was supplied; refusing to attempt an unauthenticated proof")
    _validate_sha(candidate_sha, field="backend_sha")

    head_sha = _resolve_branch_head(token, opener=opener)
    _assert_commit_exists(candidate_sha, token, opener=opener)
    status, base_sha, merge_base_sha = _compare(candidate_sha, head_sha, token, opener=opener)

    if base_sha != candidate_sha:
        raise AncestryError(f"compare base_commit is {base_sha!r}, expected the candidate {candidate_sha!r}")
    if merge_base_sha != candidate_sha:
        raise AncestryError(
            f"merge base is {merge_base_sha!r}, not the candidate {candidate_sha!r} — "
            "the candidate is NOT an ancestor of the approved release line"
        )
    if status not in ACCEPTED_STATUSES:
        raise AncestryError(
            f"compare status is {status!r}; only {' or '.join(ACCEPTED_STATUSES)} proves containment "
            "('behind' and 'diverged' mean the release line does not contain the candidate)"
        )

    return AncestryProof(
        repository=EXPECTED_REPOSITORY,
        branch=EXPECTED_RELEASE_BRANCH,
        candidate_sha=candidate_sha,
        branch_head_sha=head_sha,
        merge_base_sha=merge_base_sha,
        status=status,
    )


def _main() -> int:
    # Both values arrive through the environment. Neither is ever placed on a command line,
    # written to a file, put in a URL, or stored in Git configuration.
    token = os.environ.get("GITHUB_API_TOKEN", "")
    candidate = os.environ.get("BACKEND_SHA", "")
    try:
        proof = prove_release_line_ancestry(candidate, token)
    except AncestryError as exc:
        print(f"::error::{exc}")
        return 1
    print(proof.render())
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(_main())
