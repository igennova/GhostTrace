"""Tests for identity resolution across current and historical identifiers.

Covers: resolving a request email that is a former address, assembling the full
identifier set from the audit log, and alias-chain resolution (multiple email
or phone changes over time). No fixtures are hardcoded to specific dataset
case ids; tests build synthetic datasets.
"""

from __future__ import annotations


def test_resolves_current_email_to_user() -> None:
    """A current email resolves to its user and identifier set."""
    raise NotImplementedError


def test_resolves_historical_email_to_user() -> None:
    """A former email (from the audit log) still resolves to the user."""
    raise NotImplementedError


def test_alias_chain_collects_all_identifiers() -> None:
    """Multiple historical changes yield the union of all identifiers."""
    raise NotImplementedError
