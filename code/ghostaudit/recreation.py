"""Recreation risk: detect paths that can resurrect deleted data.

Responsibility
--------------
A deletion is not complete while an active process can copy the subject's data
back into a cleaned system, or a backup can restore it. This module determines,
at ``audit_at``:

- which connector/sync data flows for the subject are ACTIVE, and
- which backup archives for the subject can still be restored,

establishing each state from EVIDENCE (the discovered DATA_FLOW / BACKUP_ARCHIVE
records, whose enabled / restore_allowed state at the cutoff is authoritative),
and using ``system_activity.csv`` to build the sync/import/export/backup/restore/
indexing graph that corroborates and discovers flows. Activity ``reported_result``
values are claims: an evidence state always overrides an activity claim.

Active data flows become REPORT_ACTIVE_DATA_FLOW (-> DISABLE_DATA_FLOW ->
VERIFY_DATA_FLOW_DISABLED); restorable backups become REPORT_RESTORE_RISK (->
BLOCK_RESTORE -> VERIFY_RESTORE_BLOCKED). Ordering is left to remediation.
"""

from __future__ import annotations

from dataclasses import dataclass

from .discovery import (
    STATE_ACTIVE,
    STATE_BLOCKED,
    STATE_DISABLED,
    DiscoveredRecord,
    _parse_ts,
    latest_observation_per_resource,
    normalize_tokens,
)
from .loader import Dataset

KIND_DATA_FLOW = "DATA_FLOW"
KIND_RESTORE = "RESTORE"

# Activity event types that (re)activate a copy path vs. that shut one down.
_ACTIVATING_FLOW = {"SYNC_RECORD", "IMPORT_RECORD", "INDEX_RECORD",
                    "REFRESH_CACHE", "REPLICATE_RECORD"}
_ACTIVATING_RESTORE = {"RESTORE_RECORD", "CREATE_BACKUP"}
_DEACTIVATING_FLOW = {"DISABLE_DATA_FLOW"}
_BLOCKING_RESTORE = {"BLOCK_RESTORE"}


@dataclass
class RecreationRisk:
    """An active data flow or restorable backup that can recreate the data."""

    system_id: str
    resource_id: str
    kind: str
    active: bool
    evidence_id: str
    basis: str = "evidence"  # evidence | activity_claim
    recent_activity: bool = False
    finding_operation: str | None = None
    finding_state: str | None = None
    remediation_operation: str | None = None
    remediation_state: str | None = None
    verify_operation: str | None = None
    verify_state: str | None = None


def _data_flow_risk(system_id: str, resource_id: str, evidence_id: str,
                    basis: str, recent: bool) -> RecreationRisk:
    return RecreationRisk(
        system_id=system_id, resource_id=resource_id, kind=KIND_DATA_FLOW,
        active=True, evidence_id=evidence_id, basis=basis, recent_activity=recent,
        finding_operation="REPORT_ACTIVE_DATA_FLOW", finding_state="ACTIVE",
        remediation_operation="DISABLE_DATA_FLOW", remediation_state="DISABLED",
        verify_operation="VERIFY_DATA_FLOW_DISABLED", verify_state="DISABLED",
    )


def _restore_risk(system_id: str, resource_id: str, evidence_id: str,
                  basis: str, recent: bool) -> RecreationRisk:
    return RecreationRisk(
        system_id=system_id, resource_id=resource_id, kind=KIND_RESTORE,
        active=True, evidence_id=evidence_id, basis=basis, recent_activity=recent,
        finding_operation="REPORT_RESTORE_RISK", finding_state="ACTIVE",
        remediation_operation="BLOCK_RESTORE", remediation_state="BLOCKED",
        verify_operation="VERIFY_RESTORE_BLOCKED", verify_state="BLOCKED",
    )


def _category_kind(category: str) -> str | None:
    """Map a discovered category to a recreation kind."""
    if category == "DATA_FLOW":
        return KIND_DATA_FLOW
    if category == "BACKUP_ARCHIVE":
        return KIND_RESTORE
    return None


def _subject_activity(dataset: Dataset, subject_resources: set[str],
                      subject_tokens: set[str], audit_at: str):
    """Return activity events at/<= audit_at that reference the subject."""
    cutoff = _parse_ts(audit_at)
    events = []
    for ev in dataset.activity:
        ts = _parse_ts(ev.event_time)
        if cutoff is not None and ts is not None and ts > cutoff:
            continue
        hit = ev.resource_id in subject_resources
        if not hit and subject_tokens:
            detail_tokens = set()
            for word in ev.details.replace("(", " ").replace(")", " ").split():
                detail_tokens |= normalize_tokens(word.strip(".,"))
            hit = bool(detail_tokens & subject_tokens)
        if hit:
            events.append(ev)
    return events


def _recent_activity_for(resource_id: str, events) -> bool:
    """Whether the subject's activity shows a recent (re)activation touching this."""
    return any(
        ev.resource_id == resource_id and ev.event_type in
        (_ACTIVATING_FLOW | _ACTIVATING_RESTORE) for ev in events
    )


def detect_recreation(
    discovered: list[DiscoveredRecord],
    dataset: Dataset,
    identity,
    audit_at: str,
) -> list[RecreationRisk]:
    """Return all active recreation risks for the subject at ``audit_at``."""
    latest = latest_observation_per_resource(discovered)
    subject_resources = {rid for (_sys, rid) in latest}
    subject_tokens = set(identity.match_keys()) if identity is not None else set()
    events = _subject_activity(dataset, subject_resources, subject_tokens, audit_at)

    risks: list[RecreationRisk] = []
    seen: set[str] = set()

    # 1) Evidence-grounded: discovered DATA_FLOW / BACKUP_ARCHIVE records.
    for (system_id, resource_id), record in latest.items():
        kind = _category_kind(record.data_category)
        if kind is None:
            continue
        recent = _recent_activity_for(resource_id, events)
        if kind == KIND_DATA_FLOW and record.observed_state == STATE_ACTIVE:
            risks.append(_data_flow_risk(system_id, resource_id, record.evidence_id,
                                         "evidence", recent))
            seen.add(resource_id)
        elif kind == KIND_RESTORE and record.observed_state == STATE_ACTIVE:
            risks.append(_restore_risk(system_id, resource_id, record.evidence_id,
                                       "evidence", recent))
            seen.add(resource_id)
        elif record.observed_state in (STATE_DISABLED, STATE_BLOCKED):
            seen.add(resource_id)  # explicitly safe; do not re-flag from activity

    # 2) Activity-only flows/backups the evidence did not surface. Treated as a
    #    claim: active unless a later disable/block event appears.
    latest_event: dict[str, object] = {}
    for ev in events:
        rid = ev.resource_id
        if not (rid.startswith("data_flow") or rid.startswith("backup")):
            continue
        prev = latest_event.get(rid)
        if prev is None or (_parse_ts(ev.event_time) or _parse_ts("1970-01-01T00:00:00Z")) \
                >= (_parse_ts(prev.event_time) or _parse_ts("1970-01-01T00:00:00Z")):
            latest_event[rid] = ev
    for rid, ev in latest_event.items():
        if rid in seen:
            continue
        if ev.event_type in _DEACTIVATING_FLOW or ev.event_type in _BLOCKING_RESTORE:
            continue
        if rid.startswith("data_flow") and ev.event_type in _ACTIVATING_FLOW:
            risks.append(_data_flow_risk(ev.target_system or ev.source_system, rid,
                                         ev.activity_id, "activity_claim", True))
        elif rid.startswith("backup") and ev.event_type in _ACTIVATING_RESTORE:
            risks.append(_restore_risk(ev.target_system or ev.source_system, rid,
                                       ev.activity_id, "activity_claim", True))

    risks.sort(key=lambda r: (r.kind, r.system_id, r.resource_id))
    return risks


def detect_recreation_paths(
    discovered: list[DiscoveredRecord], dataset: Dataset, identity, audit_at: str
) -> list[RecreationRisk]:
    """Alias for :func:`detect_recreation` (scaffold-compatible name)."""
    return detect_recreation(discovered, dataset, identity, audit_at)
