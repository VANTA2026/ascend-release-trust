"""The lockfile validator must be complete, digest-bound, and per-distribution."""

from __future__ import annotations

import hashlib

import pytest
from conftest import make_lock_text

import lock_policy as lp

H1 = "a" * 64
H2 = "b" * 64
H3 = "c" * 64

GOOD = [("alembic", "1.18.5", [H1, H2]), ("fastapi", "0.138.2", [H3])]


def test_a_well_formed_lock_is_accepted():
    lock = lp.validate_lock(make_lock_text(GOOD))
    assert set(lock.distributions) == {"alembic", "fastapi"}
    assert lock.distributions["alembic"].version == "1.18.5"
    assert lock.distributions["alembic"].hashes == frozenset({H1, H2})


def test_hashes_are_associated_with_their_own_distribution():
    """A global 'is this digest anywhere in the lock' pool would accept a swapped wheel."""
    lock = lp.validate_lock(make_lock_text(GOOD))
    assert lock.permitted_hashes("alembic") == frozenset({H1, H2})
    assert lock.permitted_hashes("fastapi") == frozenset({H3})
    assert H3 not in lock.permitted_hashes("alembic")
    assert H1 not in lock.permitted_hashes("fastapi")


def test_project_names_are_pep503_normalized():
    lock = lp.validate_lock(make_lock_text([("PSYCOPG_Binary", "3.2.3", [H1])]))
    assert "psycopg-binary" in lock.distributions
    assert lock.permitted_hashes("psycopg.binary") == frozenset({H1})
    assert lp.normalize_project("Foo_Bar.Baz") == "foo-bar-baz"


def test_expected_digest_is_bound():
    text = make_lock_text(GOOD)
    digest = hashlib.sha256(text.encode()).hexdigest()
    assert lp.validate_lock(text, expected_sha256=digest).sha256 == digest
    with pytest.raises(lp.LockError, match="digest mismatch"):
        lp.validate_lock(text, expected_sha256="0" * 64)


def test_a_single_altered_byte_breaks_the_digest_binding():
    text = make_lock_text(GOOD)
    digest = hashlib.sha256(text.encode()).hexdigest()
    with pytest.raises(lp.LockError, match="digest mismatch"):
        lp.validate_lock(text + " ", expected_sha256=digest)


@pytest.mark.parametrize(
    "mutate,fragment",
    [
        (lambda t: t.replace("alembic==1.18.5", "alembic>=1.18.5"), "not pinned with '=='"),
        (lambda t: t.replace(f"    --hash=sha256:{H3}\n", ""), "no sha256 hashes"),
        (lambda t: "-e .\n" + t, "editable install"),
        (lambda t: "--index-url https://evil.example/simple\n" + t, "index directive"),
        (lambda t: t.replace("alembic==1.18.5", "alembic @ https://x.example/a.whl"), "direct URL"),
        (lambda t: t.replace("alembic==1.18.5", "alembic @ git+https://x.example/a.git"), "VCS reference"),
        (lambda t: t.replace("alembic==1.18.5", "alembic @ file:///tmp/a.whl"), "local file URL"),
        (lambda t: t.replace(f"--hash=sha256:{H1}", "--hash=md5:" + "a" * 32), "non-sha256"),
        (lambda t: t.replace(f"--hash=sha256:{H1}", "--hash=sha256:abcd"), "truncated"),
        (lambda t: t.replace("alembic==1.18.5", 'alembic==1.18.5 ; sys_platform == "linux"'), "environment marker"),
        (lambda t: t + make_lock_text([("alembic", "9.9.9", [H1])]), "conflicting versions"),
    ],
)
def test_policy_violations_are_refused(mutate, fragment):
    with pytest.raises(lp.LockError, match=fragment):
        lp.validate_lock(mutate(make_lock_text(GOOD)))


def test_a_credential_bearing_url_is_refused():
    text = make_lock_text(GOOD).replace("alembic==1.18.5", "alembic @ https://user:pw@x.example/a.whl")
    with pytest.raises(lp.LockError, match="credential-bearing URL"):
        lp.validate_lock(text)


def test_an_empty_lock_is_refused():
    with pytest.raises(lp.LockError, match="no pinned requirements"):
        lp.validate_lock("# only a comment\n")


def test_every_violation_is_reported_not_just_the_first():
    text = make_lock_text([("alembic", "1.18.5", [])])
    text = "-e .\n" + text.replace("alembic==1.18.5", "alembic>=1.18.5")
    with pytest.raises(lp.LockError) as exc:
        lp.validate_lock(text)
    message = str(exc.value)
    assert "editable install" in message
    assert "not pinned with '=='" in message


def test_duplicate_same_version_entry_is_refused():
    with pytest.raises(lp.LockError, match="duplicate entry"):
        lp.validate_lock(make_lock_text(GOOD) + make_lock_text([("alembic", "1.18.5", [H1])]))


def test_continuation_backslashes_do_not_break_hash_parsing():
    """Regression: hashes end with ' \\' and were once rejected as malformed."""
    lock = lp.validate_lock(make_lock_text([("pkg", "1.0", [H1, H2, H3])]))
    assert len(lock.permitted_hashes("pkg")) == 3
