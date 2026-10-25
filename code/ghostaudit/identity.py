"""Identity resolution: recover a subject's current and historical identifiers.

Responsibility
--------------
The request email may be a current or a former address. This module maps that
email to a stable ``user_id`` using the current snapshot
(``user_identities.csv``) and the change history (``user_audit_log.csv``),
following rename chains (old email -> new email -> current row), then assembles
the full set of identifiers under which the subject's data could appear in any
system: every current and historical email, phone, and email hash, the display
name, and the internal ``user_id``.

``email_hash`` is sha256 of the email (as the dataset computes it); hashes are
both taken from the audit log (authoritative, for historical values) and
computed for every known email. Every identifier carries provenance (which row
proved it). This module performs no record discovery or policy logic.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field

from .discovery import normalize_tokens
from .loader import Dataset, UserIdentity

# Audit-log field names (values observed in user_audit_log.csv).
_FIELD_EMAIL = "email"
_FIELD_PHONE = "phone"
_FIELD_EMAIL_HASH = "email_hash"


@dataclass(frozen=True)
class Provenance:
    """Where one identifier value came from."""

    identifier_type: str   # email | phone | email_hash | user_id | name
    value: str
    source: str            # user_identities.csv | user_audit_log.csv | computed | request
    reference: str = ""    # user_id, audit_id, or the email a hash was computed from
    detail: str = ""       # e.g. old_value / new_value / updated_at


@dataclass
class Identity:
    """The resolved subject and every identifier that may reference them."""

    user_id: str
    current_email: str = ""
    current_phone: str = ""
    current_email_hash: str = ""
    resolved: bool = False
    names: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    email_hashes: set[str] = field(default_factory=set)
    provenance: list[Provenance] = field(default_factory=list)

    def match_keys(self) -> set[str]:
        """Return the normalized union of strong identifiers for matching.

        Names are intentionally excluded (decoy-prone); matching uses emails,
        phones, email hashes, and the internal ``user_id``. Uses the same
        normalization as the evidence index so keys compare equal.
        """
        tokens: set[str] = set()
        for value in self.emails | self.phones | self.email_hashes:
            tokens |= normalize_tokens(value)
        if self.user_id:
            tokens |= normalize_tokens(self.user_id)
        return tokens


def normalize_email(email: str) -> str:
    """Return a canonical form of an email for case-insensitive comparison."""
    return (email or "").strip().lower()


def normalize_identifier(value: str) -> str:
    """Return a canonical form of a non-email identifier (phone, hash, name)."""
    return (value or "").strip().lower()


def compute_email_hash(email: str) -> str:
    """Compute the dataset's ``email_hash`` = sha256 hexdigest of the email."""
    return hashlib.sha256(email.encode("utf-8")).hexdigest()


class IdentityResolver:
    """Precomputed indexes for fast, deterministic identity resolution.

    Build once per dataset and reuse across all requests.
    """

    def __init__(self, dataset: Dataset) -> None:
        self._by_user_id: dict[str, UserIdentity] = dataset.identity_by_user_id()
        self._audit_by_user: dict[str, list] = defaultdict(list)
        for entry in dataset.audit_log:
            self._audit_by_user[entry.user_id].append(entry)

        # Map every email (current + historical) to its user_id. Current emails
        # take precedence over historical ones on collision (decoy isolation).
        self._email_to_user: dict[str, str] = {}
        for entry in dataset.audit_log:
            if entry.field_name == _FIELD_EMAIL:
                for val in (entry.old_value, entry.new_value):
                    if val:
                        self._email_to_user.setdefault(normalize_email(val), entry.user_id)
        for user in dataset.identities:  # overwrite: current wins
            self._email_to_user[normalize_email(user.email)] = user.user_id

    @classmethod
    def from_dataset(cls, dataset: Dataset) -> "IdentityResolver":
        """Build a resolver from a loaded dataset."""
        return cls(dataset)

    def user_id_for_email(self, email: str) -> str | None:
        """Resolve an email (current or historical) to a ``user_id``."""
        return self._email_to_user.get(normalize_email(email))

    def resolve(self, email: str) -> Identity:
        """Resolve a request email into a full :class:`Identity` with provenance."""
        user_id = self.user_id_for_email(email)
        identity = Identity(user_id=user_id or "", resolved=bool(user_id))

        # The request email itself is always a known identifier.
        self._add_email(identity, email, Provenance("email", email, "request"))

        if user_id is None:
            return identity

        current = self._by_user_id.get(user_id)
        if current is not None:
            identity.current_email = current.email
            identity.current_phone = current.phone
            identity.current_email_hash = current.email_hash
            self._add_email(
                identity, current.email,
                Provenance("email", current.email, "user_identities.csv",
                           user_id, f"updated_at={current.updated_at}"),
            )
            if current.phone:
                self._add_phone(
                    identity, current.phone,
                    Provenance("phone", current.phone, "user_identities.csv", user_id),
                )
            if current.email_hash:
                self._add_hash(
                    identity, current.email_hash,
                    Provenance("email_hash", current.email_hash,
                               "user_identities.csv", user_id),
                )
            if current.name:
                identity.names.add(current.name)
                identity.provenance.append(
                    Provenance("name", current.name, "user_identities.csv", user_id)
                )

        # Walk this user's change history for every historical value.
        for entry in self._audit_by_user.get(user_id, []):
            for role, val in (("old_value", entry.old_value),
                              ("new_value", entry.new_value)):
                if not val:
                    continue
                prov = Provenance(entry.field_name, val, "user_audit_log.csv",
                                  entry.audit_id, role)
                if entry.field_name == _FIELD_EMAIL:
                    self._add_email(identity, val, prov)
                elif entry.field_name == _FIELD_PHONE:
                    self._add_phone(identity, val, prov)
                elif entry.field_name == _FIELD_EMAIL_HASH:
                    self._add_hash(identity, val, prov)

        # Compute the hash for every known email (covers emails with no logged
        # hash, and confirms the authoritative ones).
        for mail in list(identity.emails):
            digest = compute_email_hash(mail)
            self._add_hash(
                identity, digest,
                Provenance("email_hash", digest, "computed", mail, "sha256(email)"),
            )

        return identity

    @staticmethod
    def _add_email(identity: Identity, value: str, prov: Provenance) -> None:
        if value:
            identity.emails.add(value)
            identity.provenance.append(prov)

    @staticmethod
    def _add_phone(identity: Identity, value: str, prov: Provenance) -> None:
        if value:
            identity.phones.add(value)
            identity.provenance.append(prov)

    @staticmethod
    def _add_hash(identity: Identity, value: str, prov: Provenance) -> None:
        if value:
            identity.email_hashes.add(value)
            identity.provenance.append(prov)


# Module-level cache so resolve_identity reuses one resolver per dataset.
_RESOLVER_CACHE: dict[int, IdentityResolver] = {}


def resolve_identity(email: str, dataset: Dataset) -> Identity | None:
    """Resolve the request email to a full :class:`Identity`, or ``None``.

    Returns ``None`` only when the email cannot be tied to any user; an
    unresolved-but-usable identity (carrying just the request email and its
    computed hash) is returned by :meth:`IdentityResolver.resolve` when the
    email is unknown — callers that want that should use the resolver directly.
    """
    resolver = _RESOLVER_CACHE.get(id(dataset))
    if resolver is None:
        resolver = IdentityResolver.from_dataset(dataset)
        _RESOLVER_CACHE[id(dataset)] = resolver
    identity = resolver.resolve(email)
    return identity if identity.resolved else None


def match_user_by_email(email: str, dataset: Dataset) -> UserIdentity | None:
    """Find the user whose current or historical email equals ``email``."""
    resolver = IdentityResolver.from_dataset(dataset)
    user_id = resolver.user_id_for_email(email)
    return dataset.identity_by_user_id().get(user_id) if user_id else None


def historical_values(user_id: str, field_name: str, dataset: Dataset) -> set[str]:
    """Collect every old/new value of ``field_name`` for a user from the log."""
    values: set[str] = set()
    for entry in dataset.audit_log:
        if entry.user_id == user_id and entry.field_name == field_name:
            values.update(v for v in (entry.old_value, entry.new_value) if v)
    return values
