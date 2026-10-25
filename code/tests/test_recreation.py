"""Adversarial tests for recreation-risk detection.

Scenario (a): a record deleted in its primary store but kept alive by an active
sync/data flow must be flagged as a recreation risk so the flow is disabled
before the copies are cleaned. Also covers that a disabled flow and a blocked
backup are NOT flagged.
"""

from __future__ import annotations

from pathlib import Path

from ghostaudit.discovery import (
    STATE_ABSENT,
    STATE_ACTIVE,
    STATE_BLOCKED,
    STATE_DISABLED,
    DiscoveredRecord,
)
from ghostaudit.loader import Dataset
from ghostaudit.recreation import KIND_DATA_FLOW, KIND_RESTORE, detect_recreation


class _Identity:
    """Minimal identity stub exposing match_keys()."""

    def __init__(self, tokens):
        self._tokens = set(tokens)

    def match_keys(self):
        return self._tokens


def _rec(system, resource, category, state, ev="evidence_x", ts="2026-09-01T00:00:00Z"):
    return DiscoveredRecord(
        system_id=system, resource_id=resource, data_category=category,
        observed_state=state, observed_at=ts, evidence_id=ev,
        identifiers={"email": "x@y.com"}, matched_on=["x@y.com"],
        table_or_collection="handover",
    )


def _dataset() -> Dataset:
    return Dataset(dataset_dir=Path("."))


def test_deleted_in_primary_but_active_sync_is_flagged() -> None:
    """Account absent in primary, but an active data flow can recreate it."""
    discovered = [
        _rec("account_service", "account_1", "USER_PROFILE", STATE_ABSENT),
        _rec("integration_service", "data_flow_1", "DATA_FLOW", STATE_ACTIVE),
    ]
    risks = detect_recreation(discovered, _dataset(), _Identity({"x@y.com"}), "2026-10-01T00:00:00Z")
    flow = [r for r in risks if r.kind == KIND_DATA_FLOW]
    assert len(flow) == 1
    assert flow[0].resource_id == "data_flow_1" and flow[0].active
    assert flow[0].finding_operation == "REPORT_ACTIVE_DATA_FLOW"
    assert flow[0].remediation_operation == "DISABLE_DATA_FLOW"


def test_disabled_flow_and_blocked_backup_not_flagged() -> None:
    """A disabled connector and a restore-blocked backup are not active risks.

    They are still returned (so a COMPLETE case can verify the safe state), but
    carry no finding/remediation and active=False.
    """
    discovered = [
        _rec("integration_service", "data_flow_2", "DATA_FLOW", STATE_DISABLED),
        _rec("backup_service", "backup_2", "BACKUP_ARCHIVE", STATE_BLOCKED),
    ]
    risks = detect_recreation(discovered, _dataset(), _Identity(set()), "2026-10-01T00:00:00Z")
    assert all(not r.active for r in risks)
    assert all(r.finding_operation is None for r in risks)
    assert {r.verify_operation for r in risks} == {
        "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"}


def test_restorable_backup_is_flagged() -> None:
    """A backup whose restore is still allowed is a restore risk."""
    discovered = [_rec("backup_service", "backup_3", "BACKUP_ARCHIVE", STATE_ACTIVE)]
    risks = detect_recreation(discovered, _dataset(), _Identity(set()), "2026-10-01T00:00:00Z")
    restore = [r for r in risks if r.kind == KIND_RESTORE]
    assert len(restore) == 1 and restore[0].resource_id == "backup_3"
    assert restore[0].remediation_operation == "BLOCK_RESTORE"
