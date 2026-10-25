"""Retention: records that must be kept, and the identifiers they may keep.

Responsibility
--------------
Some records must survive a deletion: security audit logs within their
retention period, records under an active legal hold, backup archives (kept but
restore-blocked), and account tombstones that preserve only the stable internal
``user_id``. This module identifies those records for the subject and the set
of identifiers each is permitted to retain, so the plan neither deletes what
policy requires to keep nor leaves prohibited identifiers behind.

Its output feeds VERIFY_RECORD_PRESENT / VERIFY_RECORD_REDACTED verification
steps and constrains remediation. It makes no sequencing decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .identity import Identity
from .loader import Dataset
from .rules import RuleEngine


@dataclass
class RetainedRecord:
    """A record policy requires to be kept, with its allowed identifiers."""

    system_id: str
    resource_id: str
    data_category: str
    allowed_identifiers: set[str] = field(default_factory=set)
    evidence_id: str = ""


def retained_records(
    identity: Identity, dataset: Dataset, audit_at: str, rules: RuleEngine
) -> list[RetainedRecord]:
    """Return every record that must be retained for the subject."""
    raise NotImplementedError


def allowed_identifiers(data_category: str, rules: RuleEngine) -> set[str]:
    """Return the identifier fields a retained category may keep."""
    raise NotImplementedError


def is_within_retention(record_fields: dict[str, object], audit_at: str) -> bool:
    """Return whether a record is still inside its retention window."""
    raise NotImplementedError


def legal_hold_active(identity: Identity, dataset: Dataset, audit_at: str) -> bool:
    """Return whether a supplied legal hold covers the subject at ``audit_at``."""
    raise NotImplementedError
