"""Tests for record discovery and snapshot selection at ``audit_at``.

Covers: matching records by any identifier across SQL/JSON/log sources,
ignoring evidence captured after ``audit_at``, selecting the nearest prior
snapshot, and not matching look-alike records that belong to a different
subject (decoys).
"""

from __future__ import annotations


def test_discovers_records_matching_any_identifier() -> None:
    """Records matching any current/historical identifier are discovered."""
    raise NotImplementedError


def test_ignores_evidence_after_audit_at() -> None:
    """Evidence captured after ``audit_at`` does not affect the result."""
    raise NotImplementedError


def test_does_not_match_decoy_subject() -> None:
    """A similar record belonging to another subject is not matched."""
    raise NotImplementedError
