"""Account linking and absence synthesis for deleted primary profiles.

Responsibility
--------------
A deleted account leaves no row to discover, so identifier matching alone
cannot produce the ``VERIFY_RECORD_ABSENT`` step its plan needs. This module:

1. **Links** each request's subject to its ``account_service`` resource id.
   An account already tied to the subject by evidence (identifier co-occurrence,
   data-catalog links) wins. Otherwise the deletion workflow's own
   ``DELETE_RECORD`` event on ``account_service`` is used: it lands shortly
   before the request's ``reported_at`` (the workflow reports right after it),
   and its result mirrors the reported status. Accounts linked by evidence to
   anyone are excluded, and every account is assigned to at most one request
   across *all* known requests (evaluation + public sample files share one
   activity stream), best match first.
2. **Resolves** the linked account's own observations (e.g. a 404 readback
   that stores only the resource id) and, when no evidence observes it at
   ``audit_at``, **synthesizes** an ``ABSENT`` observation citing the latest
   account-profile snapshot available at the cutoff that does not contain it.

The activity event only *identifies* the account; absence is always grounded in
a snapshot file, never in the event's claimed result.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .discovery import (
    STATE_ABSENT,
    DiscoveredRecord,
    EvidenceIndex,
    _parse_ts,
    discover_by_resources,
    _read_manifest,
)
from .loader import Dataset, DeletionRequest, load_requests

ACCOUNT_SYSTEM = "account_service"
ACCOUNT_PREFIX = "account_"
ACCOUNT_CATEGORY = "USER_PROFILE"
PROFILE_TABLE_PREFIX = "customer_profiles"

#: How far before ``reported_at`` the workflow's deletion event may land, and
#: how far after (older workflows emit the event just after reporting).
LINK_WINDOW_BEFORE = timedelta(hours=2)
LINK_WINDOW_AFTER = timedelta(minutes=15)

#: The workflow result that the reported status was derived from.
_EXPECTED_RESULT = {
    "COMPLETE": "SUCCESS",
    "PARTIALLY_COMPLETE": "PARTIAL",
    "NOT_STARTED": "FAILED",
}


def request_key(request: DeletionRequest) -> tuple[str, str, str, str]:
    """Identify a request across files (sample and evaluation case ids overlap)."""
    return (request.case_id, request.email.strip().lower(),
            request.requested_at, request.reported_at)


@dataclass(frozen=True)
class AccountLink:
    """The account resource attributed to one request, and how."""

    resource_id: str
    source: str  # "evidence" or "activity"
    activity_id: str = ""


@dataclass(frozen=True)
class ProfileSnapshot:
    """One account-profile table/collection capture and the ids it holds."""

    evidence_id: str
    snapshot_at: str
    file_captured_at: str
    table_or_collection: str
    resource_ids: frozenset[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Linking
# ---------------------------------------------------------------------------
def _evidence_accounts(index: EvidenceIndex, tokens: set[str]) -> list[str]:
    found = {r for t in tokens for r in index.token_to_resources.get(t, ())
             if r.startswith(ACCOUNT_PREFIX)}
    return sorted(found)


def _all_requests(dataset: Dataset) -> list[DeletionRequest]:
    """Every request competing for the shared activity stream."""
    requests = list(dataset.requests)
    sample = Path(dataset.dataset_dir) / "sample_deletion_requests.csv"
    if sample.exists():
        requests += load_requests(sample)
    seen: set[tuple] = set()
    unique: list[DeletionRequest] = []
    for r in requests:
        if request_key(r) not in seen:
            seen.add(request_key(r))
            unique.append(r)
    return unique


def link_accounts(
    dataset: Dataset,
    index: EvidenceIndex,
    resolver,
    requests: list[DeletionRequest] | None = None,
) -> dict[tuple, AccountLink]:
    """Attribute an account resource to each request (see module docstring)."""
    requests = _all_requests(dataset) if requests is None else requests
    claimed = {r for ids in index.token_to_resources.values() for r in ids
               if r.startswith(ACCOUNT_PREFIX)}
    deletions = [
        a for a in dataset.activity
        if a.event_type == "DELETE_RECORD" and a.target_system == ACCOUNT_SYSTEM
        and a.resource_id.startswith(ACCOUNT_PREFIX) and a.resource_id not in claimed
    ]

    links: dict[tuple, AccountLink] = {}
    candidates: list[tuple] = []
    for req in requests:
        key = request_key(req)
        tokens = set(resolver.resolve(req.email).match_keys())
        owned = _evidence_accounts(index, tokens)
        if owned:
            links[key] = AccountLink(owned[0], "evidence")
            continue
        reported, requested = _parse_ts(req.reported_at), _parse_ts(req.requested_at)
        if reported is None:
            continue
        lo = reported - LINK_WINDOW_BEFORE
        if requested is not None:
            lo = max(lo, requested)
        hi = reported + LINK_WINDOW_AFTER
        expected = _EXPECTED_RESULT.get(req.reported_status.strip().upper())
        for a in deletions:
            t = _parse_ts(a.event_time)
            if t is None or not lo <= t <= hi:
                continue
            gap = abs((reported - t).total_seconds())
            candidates.append((
                0 if a.reported_result.strip().upper() == expected else 1,
                gap, req.requested_at, req.case_id, a.activity_id, key, a.resource_id,
            ))

    # Best match first; each request and each account is used at most once.
    # Equal-quality ties go to the longest-pending request (earliest
    # requested_at), then case id, so the assignment is deterministic.
    used: set[str] = set()
    for *_rank, activity_id, key, resource_id in sorted(candidates):
        if key in links or resource_id in used:
            continue
        links[key] = AccountLink(resource_id, "activity", activity_id)
        used.add(resource_id)
    return links


# ---------------------------------------------------------------------------
# Account-profile snapshots
# ---------------------------------------------------------------------------
def _sql_profile_snapshots(path: Path, evidence_id: str, captured_at: str):
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(path.read_text(encoding="utf-8", errors="replace"))
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            if not table.startswith(PROFILE_TABLE_PREFIX):
                continue
            cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
            if "resource_id" not in cols:
                continue
            ids = frozenset(str(r[0]) for r in conn.execute(
                f'SELECT resource_id FROM "{table}"'))
            yield ProfileSnapshot(evidence_id, captured_at, captured_at, table, ids)
    except sqlite3.Error:
        return
    finally:
        conn.close()


def _json_profile_snapshots(path: Path, evidence_id: str, captured_at: str):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    for snap in data.get("snapshots") or []:
        if not isinstance(snap, dict):
            continue
        if snap.get("data_store") != ACCOUNT_SYSTEM:
            continue
        collection = str(snap.get("collection") or "")
        if not collection.startswith(PROFILE_TABLE_PREFIX):
            continue
        ids = frozenset(str(r.get("resource_id")) for r in snap.get("records") or []
                        if isinstance(r, dict) and r.get("resource_id"))
        yield ProfileSnapshot(evidence_id, str(snap.get("captured_at") or captured_at),
                              captured_at, collection, ids)


def load_profile_snapshots(dataset_dir: str | Path) -> list[ProfileSnapshot]:
    """Collect every account-profile table/collection capture in the evidence."""
    dataset_dir = Path(dataset_dir)
    snapshots: list[ProfileSnapshot] = []
    for entry in _read_manifest(dataset_dir):
        path = dataset_dir / entry.file_path
        if not path.exists():
            continue
        if path.suffix == ".sql":
            snapshots += _sql_profile_snapshots(path, entry.evidence_id, entry.captured_at)
        elif path.suffix == ".json":
            snapshots += _json_profile_snapshots(path, entry.evidence_id, entry.captured_at)
    return snapshots


def authoritative_snapshot(
    snapshots: list[ProfileSnapshot], audit_at: str, not_before: str = ""
) -> ProfileSnapshot | None:
    """The latest account-profile capture available at ``audit_at``.

    With ``not_before`` (the request time) only captures taken after the
    request qualify: an earlier snapshot shows the account before deletion
    was asked for and cannot prove its absence.
    """
    cutoff = _parse_ts(audit_at)
    floor = _parse_ts(not_before) if not_before else None
    best, best_rank = None, None
    for s in snapshots:
        taken, filed = _parse_ts(s.snapshot_at), _parse_ts(s.file_captured_at)
        if taken is None or cutoff is None or taken > cutoff:
            continue
        if floor is not None and taken < floor:
            continue
        if filed is not None and filed > cutoff:
            continue
        rank = (taken, filed or taken, s.evidence_id, s.table_or_collection)
        if best_rank is None or rank > best_rank:
            best, best_rank = s, rank
    return best


# ---------------------------------------------------------------------------
# Synthesis
# ---------------------------------------------------------------------------
@dataclass
class AccountContext:
    """Per-run account links and snapshot catalog shared by every case."""

    links: dict[tuple, AccountLink]
    snapshots: list[ProfileSnapshot]
    index: EvidenceIndex | None = None

    @classmethod
    def build(cls, dataset: Dataset, index: EvidenceIndex, resolver) -> "AccountContext":
        return cls(link_accounts(dataset, index, resolver),
                   load_profile_snapshots(dataset.dataset_dir), index)


def synthesize_absence(
    request: DeletionRequest,
    records: list[DiscoveredRecord],
    context: AccountContext | None,
) -> list[DiscoveredRecord]:
    """Return the linked account's records missing from ``records``.

    The account's own observations at the cutoff win (its real state). Only
    when there are none is an ABSENT record synthesized from the authoritative
    snapshot. Nothing is added when no account is linked, or when no snapshot
    available at ``audit_at`` can ground the absence.
    """
    if context is None:
        return []
    link = context.links.get(request_key(request))
    if link is None:
        return []
    if any(r.resource_id == link.resource_id for r in records):
        return []
    floor = _parse_ts(request.requested_at)
    if context.index is not None:
        observed = [
            r for r in discover_by_resources(
                context.index, {link.resource_id}, request.audit_at)
            if floor is None or (_parse_ts(r.captured_at or r.observed_at) or floor) >= floor
        ]
        if observed:
            return observed
    snap = authoritative_snapshot(context.snapshots, request.audit_at,
                                  not_before=request.requested_at)
    if snap is None or link.resource_id in snap.resource_ids:
        return []
    return [DiscoveredRecord(
        system_id=ACCOUNT_SYSTEM, resource_id=link.resource_id,
        data_category=ACCOUNT_CATEGORY, observed_state=STATE_ABSENT,
        observed_at=snap.snapshot_at, evidence_id=snap.evidence_id,
        identifiers={}, matched_on=[f"(account-link:{link.source})"],
        table_or_collection=snap.table_or_collection, captured_at=snap.file_captured_at,
    )]
