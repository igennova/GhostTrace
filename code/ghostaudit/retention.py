"""Retention: records that must be kept, and the identifiers they may keep.

Responsibility
--------------
Some records must survive a deletion: security audit logs within their
retention period, records under an active legal hold, backup archives (kept but
restore-blocked, handled with recreation), and account tombstones that preserve
only the stable internal ``user_id``. This module checks, at ``audit_at``, that
each such record still exists AND that it carries only the identifiers policy
permits — a tombstone may keep ``user_id`` but must NOT contain name, email,
phone, or email_hash.

It emits VERIFY_RECORD_PRESENT / VERIFY_RECORD_REDACTED verification, and, for a
tombstone that still exposes prohibited identifiers, a REPORT_EXPOSED_PII finding
with a REDACT remediation. It makes no sequencing decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .discovery import STATE_ABSENT, STATE_EXPOSED, DiscoveredRecord, latest_observation_per_resource
from .rules import (
    ACTION_RETAIN,
    DIRECT_IDENTIFIER_FIELDS,
    RuleBook,
)

_TOMBSTONE = "ACCOUNT_TOMBSTONE"


@dataclass
class RetentionResult:
    """Status of one must-retain record (or tombstone) at audit_at."""

    system_id: str
    resource_id: str
    data_category: str
    present: bool
    compliant: bool
    exposed: bool
    evidence_id: str
    forbidden_present: list[str] = field(default_factory=list)
    finding_operation: str | None = None
    finding_state: str | None = None
    remediation_operation: str | None = None
    remediation_state: str | None = None
    verify_operation: str | None = None
    verify_state: str | None = None


def _forbidden_fields(record: DiscoveredRecord) -> list[str]:
    """Return the direct-identifier fields present on a record (should be none)."""
    return sorted(
        k for k, v in record.identifiers.items()
        if k in DIRECT_IDENTIFIER_FIELDS and v not in (None, "")
    )


def assess_retention(
    discovered: list[DiscoveredRecord],
    rules: RuleBook,
) -> list[RetentionResult]:
    """Check every must-retain record and tombstone at ``audit_at``."""
    results: list[RetentionResult] = []
    for (system_id, resource_id), record in latest_observation_per_resource(discovered).items():
        category = record.data_category
        if not category:
            continue
        decision = rules.required_action(category)
        is_tombstone = category == _TOMBSTONE
        is_retain = decision is not None and decision.required_action == ACTION_RETAIN
        if not (is_tombstone or is_retain):
            continue

        present = record.observed_state != STATE_ABSENT

        if is_tombstone:
            forbidden = _forbidden_fields(record)
            exposed = bool(forbidden) or record.observed_state == STATE_EXPOSED
            result = RetentionResult(
                system_id=system_id, resource_id=resource_id, data_category=category,
                present=present, compliant=(present and not exposed), exposed=exposed,
                evidence_id=record.evidence_id, forbidden_present=forbidden,
                verify_operation="VERIFY_RECORD_REDACTED", verify_state="REDACTED",
            )
            if exposed:
                result.finding_operation, result.finding_state = "REPORT_EXPOSED_PII", "PRESENT"
                result.remediation_operation, result.remediation_state = "REDACT_RECORD", "REDACTED"
        else:  # pure RETAIN (security audit log / legal hold): keep as-is, must exist
            result = RetentionResult(
                system_id=system_id, resource_id=resource_id, data_category=category,
                present=present, compliant=present, exposed=False,
                evidence_id=record.evidence_id,
                verify_operation="VERIFY_RECORD_PRESENT", verify_state="PRESENT",
            )
        results.append(result)
    return results


def retained_records(
    discovered: list[DiscoveredRecord], rules: RuleBook
) -> list[RetentionResult]:
    """Alias for :func:`assess_retention` (scaffold-compatible name)."""
    return assess_retention(discovered, rules)
