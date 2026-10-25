"""Tests for identity resolution across current and historical identifiers.

Covers: current-email resolution, historical (changed) email resolution, alias
chains (multiple email changes), phone changes, and merged/renamed accounts
with decoy isolation (a former email must not resolve to a different user who
currently uses a look-alike address). Fixtures are synthetic; nothing is tied
to specific dataset case ids.
"""

from __future__ import annotations

from pathlib import Path

from ghostaudit.identity import IdentityResolver, compute_email_hash
from ghostaudit.loader import AuditLogEntry, Dataset, UserIdentity


def _dataset(identities, audit_log) -> Dataset:
    return Dataset(dataset_dir=Path("."), identities=identities, audit_log=audit_log)


def _resolver(identities, audit_log) -> IdentityResolver:
    return IdentityResolver.from_dataset(_dataset(identities, audit_log))


def test_resolves_current_email_to_user() -> None:
    """A current email resolves to its user and identifier set."""
    users = [UserIdentity("user_1", "Ada Lovelace", "ada@now.com",
                          "+1 111", compute_email_hash("ada@now.com"), "2026-01-01T00:00:00Z")]
    identity = _resolver(users, []).resolve("ada@now.com")
    assert identity.resolved and identity.user_id == "user_1"
    assert "ada@now.com" in identity.emails
    assert "+1 111" in identity.phones
    assert compute_email_hash("ada@now.com") in identity.email_hashes
    assert "ada@now.com" in identity.match_keys()


def test_resolves_historical_email_to_user() -> None:
    """A former email (from the audit log) still resolves to the user."""
    users = [UserIdentity("user_1", "Ada", "new@now.com", "+1 111",
                          compute_email_hash("new@now.com"), "2026-02-01T00:00:00Z")]
    audit = [AuditLogEntry("a1", "user_1", "2026-01-15T00:00:00Z",
                           "email", "old@was.com", "new@now.com")]
    identity = _resolver(users, audit).resolve("old@was.com")
    assert identity.resolved and identity.user_id == "user_1"
    assert {"old@was.com", "new@now.com"} <= identity.emails
    # Hash is computed for the historical email too.
    assert compute_email_hash("old@was.com") in identity.email_hashes


def test_alias_chain_collects_all_identifiers() -> None:
    """Multiple sequential email changes yield the union of all identifiers."""
    users = [UserIdentity("user_1", "Ada", "e3@x.com", "+1 111",
                          compute_email_hash("e3@x.com"), "2026-03-01T00:00:00Z")]
    audit = [
        AuditLogEntry("a1", "user_1", "2026-01-01T00:00:00Z", "email", "e1@x.com", "e2@x.com"),
        AuditLogEntry("a2", "user_1", "2026-02-01T00:00:00Z", "email", "e2@x.com", "e3@x.com"),
    ]
    resolver = _resolver(users, audit)
    # Requesting via the oldest address in the chain still resolves.
    identity = resolver.resolve("e1@x.com")
    assert identity.user_id == "user_1"
    assert {"e1@x.com", "e2@x.com", "e3@x.com"} <= identity.emails
    for mail in ("e1@x.com", "e2@x.com", "e3@x.com"):
        assert compute_email_hash(mail) in identity.email_hashes


def test_phone_change_collects_old_and_new() -> None:
    """Both the old and new phone numbers are recovered."""
    users = [UserIdentity("user_1", "Ada", "ada@x.com", "+44 7700 900222",
                          compute_email_hash("ada@x.com"), "2026-02-01T00:00:00Z")]
    audit = [AuditLogEntry("a1", "user_1", "2026-01-10T00:00:00Z",
                           "phone", "+44 7700 900111", "+44 7700 900222")]
    identity = _resolver(users, audit).resolve("ada@x.com")
    assert {"+44 7700 900111", "+44 7700 900222"} <= identity.phones
    keys = identity.match_keys()
    # Phones normalize to digit-only tel: tokens so formatting differences match.
    assert "tel:447700900111" in keys and "tel:447700900222" in keys


def test_email_hash_change_from_audit_is_authoritative() -> None:
    """Historical email_hash values in the log are captured directly."""
    users = [UserIdentity("user_1", "Ada", "new@x.com", "+1 1",
                          compute_email_hash("new@x.com"), "2026-02-01T00:00:00Z")]
    audit = [
        AuditLogEntry("a1", "user_1", "2026-01-01T00:00:00Z", "email", "old@x.com", "new@x.com"),
        AuditLogEntry("a2", "user_1", "2026-01-01T00:00:00Z", "email_hash",
                      "deadbeef", "cafef00d"),
    ]
    identity = _resolver(users, audit).resolve("new@x.com")
    assert {"deadbeef", "cafef00d"} <= identity.email_hashes


def test_merged_or_renamed_account_isolates_decoy() -> None:
    """A former email must not resolve to another user's look-alike address."""
    users = [
        # user_1 renamed away from shared@x.com.
        UserIdentity("user_1", "A", "a.new@x.com", "+1 1",
                     compute_email_hash("a.new@x.com"), "2026-02-01T00:00:00Z"),
        # user_2 currently uses the same-looking address shared@x.com.
        UserIdentity("user_2", "B", "shared@x.com", "+1 2",
                     compute_email_hash("shared@x.com"), "2026-02-01T00:00:00Z"),
    ]
    audit = [AuditLogEntry("a1", "user_1", "2026-01-01T00:00:00Z",
                           "email", "shared@x.com", "a.new@x.com")]
    resolver = _resolver(users, audit)
    # Current ownership wins: shared@x.com resolves to user_2, not user_1.
    assert resolver.resolve("shared@x.com").user_id == "user_2"
    # user_1 is still reachable via its current address.
    assert resolver.resolve("a.new@x.com").user_id == "user_1"


def test_unknown_email_is_unresolved_but_usable() -> None:
    """An unknown email yields an unresolved identity carrying just that email."""
    identity = _resolver([], []).resolve("nobody@nowhere.com")
    assert not identity.resolved and identity.user_id == ""
    assert "nobody@nowhere.com" in identity.emails
