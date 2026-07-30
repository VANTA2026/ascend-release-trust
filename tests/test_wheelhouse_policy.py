"""Filename, internal METADATA, internal WHEEL tags and the lock must all agree."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import make_lock_text, make_wheel

import lock_policy as lp
import wheelhouse_policy as wp

PC = wp.PlatformClass


def _lock(entries):
    return lp.validate_lock(make_lock_text(entries))


def _one(tmp_path: Path, **kw):
    """Build one wheel and a lock that permits exactly it."""
    project = kw.pop("project", "pkg")
    version = kw.pop("version", "1.0")
    path, digest = make_wheel(tmp_path, project=project, version=version, **kw)
    return path, _lock([(project, version, [digest])])


# ---------------------------------------------------------------- classification


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("certifi-2026.7.22-py3-none-any.whl", PC.PURE),
        ("six-1.17.0-py2.py3-none-any.whl", PC.PURE),
        ("psycopg_binary-3.2.3-cp311-cp311-macosx_11_0_arm64.whl", PC.MACOS_ARM64),
        ("pkg-1.0-cp311-cp311-macosx_11_0_universal2.whl", PC.MACOS_UNIVERSAL2),
        ("pkg-1.0-cp311-cp311-macosx_11_0_x86_64.whl", PC.MACOS_X86_64),
        ("pkg-1.0-cp311-cp311-macosx_10_9_intel.whl", PC.MACOS_X86_64),
        ("pkg-1.0-cp311-cp311-manylinux_2_17_aarch64.whl", PC.LINUX),
        ("pkg-1.0-cp311-cp311-musllinux_1_2_x86_64.whl", PC.LINUX),
        ("pkg-1.0-cp311-cp311-win_amd64.whl", PC.WINDOWS),
        ("pkg-1.0.tar.gz", PC.SDIST),
        ("pkg-1.0.zip", PC.SDIST),
        ("not-a-wheel.txt", PC.UNKNOWN),
    ],
)
def test_classification(filename, expected):
    assert wp.classify_wheel(filename) == expected


@pytest.mark.parametrize(
    "filename",
    [
        "pkg-1.0+universal2-cp311-cp311-macosx_10_9_x86_64.whl",
        "pkg_arm64-1.0-cp311-cp311-macosx_10_9_intel.whl",
        "universal2tool-1.0-cp311-cp311-macosx_10_9_x86_64.whl",
    ],
)
def test_a_platform_token_elsewhere_in_the_name_cannot_impersonate_a_platform_tag(filename):
    """Tags are the last three hyphen fields; a name or local version segment is not a tag."""
    assert wp.classify_wheel(filename) == PC.MACOS_X86_64


def test_compressed_tag_set_resolves_to_its_best_member():
    name = "orjson-3.10.7-cp311-cp311-macosx_10_15_x86_64.macosx_11_0_arm64.macosx_10_15_universal2.whl"
    assert wp.classify_wheel(name) == PC.MACOS_UNIVERSAL2
    assert wp.classify_wheel("pkg-1.0-cp311-cp311-macosx_10_15_x86_64.macosx_10_9_intel.whl") == PC.MACOS_X86_64


def test_tag_triple_is_positional():
    assert wp.split_wheel_tags("pkg-1.0-cp311-cp311-macosx_11_0_arm64.whl") == ("cp311", "cp311", "macosx_11_0_arm64")
    assert wp.split_wheel_tags("pkg-1.0-1-cp311-cp311-macosx_11_0_arm64.whl") == ("cp311", "cp311", "macosx_11_0_arm64")
    assert wp.split_wheel_tags("nope.txt") is None


# ---------------------------------------------------------------- ABI policy


@pytest.mark.parametrize("python_tag,abi_tag,ok", [
    ("cp311", "cp311", True),
    ("cp39", "abi3", True),      # abi3 carries the MINIMUM CPython, not the target's
    ("cp37", "abi3", True),
    ("cp311", "abi3", True),
    ("cp313", "abi3", False),    # newer than the target
    ("cp313", "cp313", False),
    ("py3", "none", True),
    ("pp311", "pypy311_pp73", False),
    ("graalpy311_311_native", "graalpy311_311_native", False),
    ("CP313", "CP313", False),
])
def test_abi_compatibility_fails_closed(python_tag, abi_tag, ok):
    assert wp.abi_is_target_compatible(python_tag, abi_tag) is ok


def test_abi3_universal2_wheel_is_accepted(tmp_path):
    path, lock = _one(tmp_path, python_tag="cp39", abi_tag="abi3", platform_tag="macosx_10_9_universal2")
    verdict = wp.evaluate_wheelhouse([path], lock)
    assert verdict.ok, [d.reason for d in verdict.refused] + verdict.problems
    assert verdict.universal2 == [path.name]


# ---------------------------------------------------------------- universal2 policy


def test_universal2_accepted_and_declared(tmp_path):
    path, lock = _one(tmp_path, platform_tag="macosx_11_0_universal2")
    verdict = wp.evaluate_wheelhouse([path], lock)
    assert verdict.ok
    assert verdict.universal2 == [path.name]


def test_universal2_not_in_the_lock_is_refused(tmp_path):
    path, _ = make_wheel(tmp_path, project="pkg", version="1.0", platform_tag="macosx_11_0_universal2")
    lock = _lock([("pkg", "1.0", ["d" * 64])])
    verdict = wp.evaluate_wheelhouse([path], lock)
    assert not verdict.ok
    assert "not permitted for pkg" in verdict.refused[0].reason


def test_universal2_is_never_warning_only(tmp_path):
    """Regression: an unpinned fat wheel must REFUSE, not warn."""
    path, _ = make_wheel(tmp_path, project="pkg", version="1.0", platform_tag="macosx_11_0_universal2")
    verdict = wp.evaluate_wheelhouse([path], _lock([("pkg", "1.0", ["e" * 64])]))
    assert verdict.refused and not verdict.accepted


def test_filename_claiming_universal2_without_internal_tags_is_refused(tmp_path):
    path, digest = make_wheel(
        tmp_path, project="pkg", version="1.0",
        platform_tag="macosx_11_0_universal2",
        wheel_tags=["cp311-cp311-macosx_11_0_x86_64"],   # internal tags disagree
    )
    verdict = wp.evaluate_wheelhouse([path], _lock([("pkg", "1.0", [digest])]))
    assert not verdict.ok
    assert "internal WHEEL tags" in verdict.refused[0].reason


def test_x86_64_only_is_refused_even_when_fully_pinned(tmp_path):
    path, lock = _one(tmp_path, platform_tag="macosx_11_0_x86_64")
    verdict = wp.evaluate_wheelhouse([path], lock)
    assert not verdict.ok
    assert "never be accepted as an arm64 substitute" in verdict.refused[0].reason


# ---------------------------------------------------------------- internal metadata


def test_metadata_name_mismatch_is_refused(tmp_path):
    path, digest = make_wheel(tmp_path, project="pkg", version="1.0", metadata_name="somethingelse")
    verdict = wp.evaluate_wheelhouse([path], _lock([("pkg", "1.0", [digest])]))
    assert not verdict.ok
    assert "METADATA Name" in verdict.refused[0].reason


def test_metadata_version_mismatch_is_refused(tmp_path):
    path, digest = make_wheel(tmp_path, project="pkg", version="1.0", metadata_version="9.9.9")
    verdict = wp.evaluate_wheelhouse([path], _lock([("pkg", "1.0", [digest])]))
    assert not verdict.ok
    assert "METADATA Version" in verdict.refused[0].reason


def test_missing_metadata_or_wheel_is_refused(tmp_path):
    a, da = make_wheel(tmp_path / "a", project="pkg", version="1.0", omit_metadata=True) if (tmp_path / "a").mkdir() is None else (None, None)
    verdict = wp.evaluate_wheelhouse([a], _lock([("pkg", "1.0", [da])]))
    assert not verdict.ok
    assert "valid wheel" in verdict.refused[0].reason

    (tmp_path / "b").mkdir()
    b, db = make_wheel(tmp_path / "b", project="pkg", version="1.0", omit_wheel=True)
    verdict = wp.evaluate_wheelhouse([b], _lock([("pkg", "1.0", [db])]))
    assert not verdict.ok
    assert "valid wheel" in verdict.refused[0].reason


def test_a_wheel_that_is_not_a_zip_is_refused(tmp_path):
    path = tmp_path / "pkg-1.0-cp311-cp311-macosx_11_0_arm64.whl"
    path.write_bytes(b"not a zip")
    import hashlib

    verdict = wp.evaluate_wheelhouse([path], _lock([("pkg", "1.0", [hashlib.sha256(b"not a zip").hexdigest()])]))
    assert not verdict.ok
    assert "valid wheel" in verdict.refused[0].reason


# ---------------------------------------------------------------- lock association


def test_altered_wheel_bytes_are_refused(tmp_path):
    path, lock = _one(tmp_path)
    path.write_bytes(path.read_bytes() + b"\x00")
    verdict = wp.evaluate_wheelhouse([path], lock)
    assert not verdict.ok
    assert "not permitted" in verdict.refused[0].reason


def test_a_digest_belonging_to_another_distribution_is_refused(tmp_path):
    """The exact swap a global hash pool would allow."""
    a, digest_a = make_wheel(tmp_path, project="alpha", version="1.0")
    lock = _lock([("alpha", "1.0", ["f" * 64]), ("beta", "1.0", [digest_a])])
    verdict = wp.evaluate_wheelhouse([a], lock)
    assert not verdict.ok
    assert "not permitted for alpha" in verdict.refused[0].reason


def test_wrong_version_is_refused(tmp_path):
    path, digest = make_wheel(tmp_path, project="pkg", version="2.0")
    verdict = wp.evaluate_wheelhouse([path], _lock([("pkg", "1.0", [digest])]))
    assert not verdict.ok
    assert "not the locked version" in verdict.refused[0].reason


def test_a_distribution_absent_from_the_lock_is_refused(tmp_path):
    path, digest = make_wheel(tmp_path, project="stranger", version="1.0")
    verdict = wp.evaluate_wheelhouse([path], _lock([("pkg", "1.0", ["a" * 64])]))
    assert not verdict.ok
    assert any("not a locked distribution" in d.reason for d in verdict.refused)


# ---------------------------------------------------------------- completeness


def test_exactly_one_wheel_per_locked_distribution(tmp_path):
    a, da = make_wheel(tmp_path, project="alpha", version="1.0")
    b, db = make_wheel(tmp_path, project="beta", version="2.0")
    lock = _lock([("alpha", "1.0", [da]), ("beta", "2.0", [db])])
    verdict = wp.evaluate_wheelhouse([a, b], lock)
    assert verdict.ok, [d.reason for d in verdict.refused] + verdict.problems
    assert len(verdict.accepted) == 2


def test_a_missing_locked_distribution_is_a_problem(tmp_path):
    a, da = make_wheel(tmp_path, project="alpha", version="1.0")
    lock = _lock([("alpha", "1.0", [da]), ("beta", "2.0", ["a" * 64])])
    verdict = wp.evaluate_wheelhouse([a], lock)
    assert not verdict.ok
    assert any("no compatible wheel" in p for p in verdict.problems)


def test_a_duplicate_wheel_for_one_distribution_is_refused(tmp_path):
    (tmp_path / "x").mkdir()
    (tmp_path / "y").mkdir()
    a, da = make_wheel(tmp_path / "x", project="alpha", version="1.0", platform_tag="macosx_11_0_arm64")
    b, db = make_wheel(tmp_path / "y", project="alpha", version="1.0", platform_tag="macosx_12_0_arm64")
    lock = _lock([("alpha", "1.0", [da, db])])
    verdict = wp.evaluate_wheelhouse([a, b], lock)
    assert not verdict.ok
    assert any("duplicate wheel" in d.reason for d in verdict.refused)


def test_pure_python_wheel_is_bound_to_the_lock_too(tmp_path):
    path, digest = make_wheel(
        tmp_path, project="certifi", version="2026.7.22",
        python_tag="py3", abi_tag="none", platform_tag="any",
    )
    assert wp.evaluate_wheelhouse([path], _lock([("certifi", "2026.7.22", [digest])])).ok
    verdict = wp.evaluate_wheelhouse([path], _lock([("certifi", "2026.7.22", ["a" * 64])]))
    assert not verdict.ok, "a pure wheel still needs its digest permitted by the lock"


@pytest.mark.parametrize("platform_tag,fragment", [
    ("manylinux_2_17_aarch64", "Linux wheel"),
    ("win_amd64", "Windows wheel"),
])
def test_wrong_platform_refusals_are_named(tmp_path, platform_tag, fragment):
    path, lock = _one(tmp_path, platform_tag=platform_tag)
    verdict = wp.evaluate_wheelhouse([path], lock)
    assert not verdict.ok
    assert fragment in verdict.refused[0].reason


def test_sdist_is_refused(tmp_path):
    sdist = tmp_path / "pkg-1.0.tar.gz"
    sdist.write_bytes(b"x")
    verdict = wp.evaluate_wheelhouse([sdist], _lock([("pkg", "1.0", ["a" * 64])]))
    assert not verdict.ok
    assert "sdist present" in verdict.refused[0].reason
