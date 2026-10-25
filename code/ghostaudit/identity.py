"""Identity resolution: recover a subject's current and historical identifiers.

Responsibility
--------------
The request email may be a current or a former address. This module maps that
email to a stable ``user_id`` using the current snapshot
(``user_identities.csv``) and the change history (``user_audit_log.csv``), then
assembles the full set of identifiers under which the subject's data could
appear in any system: every current and historical email, phone, email hash,
display name, and the internal ``user_id`` / subject reference.

It produces the match keys that :mod:`ghostaudit.discovery` uses to connect
evidence to the subject. It performs no record discovery or policy logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .loader import Dataset, UserIdentity


@dataclass
class Identity:
    """The resolved subject and every identifier that may reference them."""

    user_id: str
    current_email: str
    current_phone: str
    current_email_hash: str
    names: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    email_hashes: set[str] = field(default_factory=set)

    def match_keys(self) -> set[str]:
        """Return the normalized union of all identifiers for matching."""
        raise NotImplementedError


def resolve_identity(email: str, dataset: Dataset) -> Identity | None:
    """Resolve the request email to a full :class:`Identity`, or ``None``."""
    raise NotImplementedError


def match_user_by_email(email: str, dataset: Dataset) -> UserIdentity | None:
    """Find the user whose current or historical email equals ``email``."""
    raise NotImplementedError


def historical_values(user_id: str, field_name: str, dataset: Dataset) -> set[str]:
    """Collect every old/new value of ``field_name`` for a user from the log."""
    raise NotImplementedError


def normalize_email(email: str) -> str:
    """Return a canonical form of an email for case-insensitive comparison."""
    raise NotImplementedError


def normalize_identifier(value: str) -> str:
    """Return a canonical form of a non-email identifier (phone, hash, name)."""
    raise NotImplementedError
