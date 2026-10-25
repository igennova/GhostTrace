"""Adversarial tests for retention checks.

Scenario (b): a record that policy requires to be retained (an account
tombstone) but which still holds a forbidden email / email_hash must be reported
as exposed PII with a REDACT remediation — not left as-is. A correctly redacted
tombstone (only user_id) is compliant, and a retained security audit log is
verified present.
"""

from __future__ import annotations

from pathlib import Path

from ghostaudit.discovery import STATE_EXPOSED, STATE_PRESENT, STATE_REDACTED, DiscoveredRecord
from ghostaudit.loader import Dataset, DeletionRule
from ghostaudit.retention import assess_retention
from ghostaudit.rules import RuleBook


def _rules() -> RuleBook:
    return RuleBook([
        DeletionRule("r_tomb", "ACCOUNT_TOMBSTONE", "deleted", "REDACT"),
        DeletionRule("r_audit", "SECURITY_AUDIT_LOG", "within retention", "RETAIN"),
    ])


def _rec(system, resource, category, state, identifiers, ev="evidence_x"):
    return DiscoveredRecord(
        system_id=system, resource_id=resource, data_category=category,
        observed_state=state, observed_at="2026-09-01T00:00:00Z", evidence_id=ev,
        identifiers=identifiers, matched_on=list(identifiers.values()),
        table_or_collection="handover",
    )


def test_retained_tombstone_holding_forbidden_email_is_exposed() -> None:
    """A tombstone that still has name/email/email_hash must be redacted."""
    rec = _rec("identity_service", "tombstone_1", "ACCOUNT_TOMBSTONE", STATE_EXPOSED,
               {"subject_reference": "user_9", "email": "a@b.com",
                "email_hash": "f" * 64, "name": "A B"})
    [result] = assess_retention([rec], _rules())
    assert not result.compliant and result.exposed
    assert "email" in result.forbidden_present and "email_hash" in result.forbidden_present
    assert result.finding_operation == "REPORT_EXPOSED_PII"
    assert result.remediation_operation == "REDACT_RECORD"
    assert result.verify_operation == "VERIFY_RECORD_REDACTED"


def test_correctly_redacted_tombstone_is_compliant() -> None:
    """A tombstone keeping only the stable user reference is compliant."""
    rec = _rec("identity_service", "tombstone_2", "ACCOUNT_TOMBSTONE", STATE_REDACTED,
               {"subject_reference": "user_9"})
    [result] = assess_retention([rec], _rules())
    assert result.compliant and not result.exposed and result.forbidden_present == []
    assert result.verify_operation == "VERIFY_RECORD_REDACTED"


def test_retained_audit_log_is_verified_present() -> None:
    """A security audit log within retention must remain and is verified present."""
    rec = _rec("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", STATE_PRESENT,
               {"subject_reference": "user_9"})
    [result] = assess_retention([rec], _rules())
    assert result.compliant and result.present
    assert result.verify_operation == "VERIFY_RECORD_PRESENT"
