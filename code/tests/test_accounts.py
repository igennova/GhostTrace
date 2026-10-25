"""Tests for account linking and deleted-account absence synthesis."""

from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path

from ghostaudit import accounts, discovery
from ghostaudit.loader import ActivityEvent, Dataset, DeletionRequest


class _Identity:
    def __init__(self, keys):
        self._keys = keys

    def match_keys(self):
        return set(self._keys)


class _Resolver:
    def resolve(self, email):
        return _Identity({email.lower()})


def _req(case_id, email, status, reported_at="2026-09-02T12:00:00Z",
         requested_at="2026-08-31T12:00:00Z", audit_at="2026-09-15T12:00:00Z"):
    return DeletionRequest(case_id, email, requested_at, status, reported_at,
                           audit_at, "Please delete my account.")


def _delete(activity_id, when, resource_id, result):
    return ActivityEvent(activity_id, when, "DELETE_RECORD", "deletion_worker",
                         "account_service", resource_id, result, "")


def _index(token_to_resources=None):
    return discovery.EvidenceIndex(fingerprint="t",
                                   token_to_resources=token_to_resources or {})


def test_links_by_result_match_and_excludes_evidence_claimed_accounts() -> None:
    """The workflow event whose result mirrors the reported status is chosen,
    and an account tied to someone by evidence is never reassigned."""
    ds = Dataset(dataset_dir=Path("/nonexistent"), activity=[
        _delete("a1", "2026-09-02T11:00:00Z", "account_1", "SUCCESS"),
        _delete("a2", "2026-09-02T10:50:00Z", "account_2", "FAILED"),
        _delete("a3", "2026-09-02T11:30:00Z", "account_3", "FAILED"),
    ])
    reqs = [_req("case_a", "a@x.com", "NOT_STARTED")]
    idx = _index({"other@x.com": ["account_3"]})
    links = accounts.link_accounts(ds, idx, _Resolver(), reqs)
    link = links[accounts.request_key(reqs[0])]
    assert (link.resource_id, link.source) == ("account_2", "activity")


def test_each_account_is_assigned_once_and_window_is_bounded() -> None:
    """Two requests never share an account; a far-away event is not linked."""
    ds = Dataset(dataset_dir=Path("/nonexistent"), activity=[
        _delete("a1", "2026-09-02T11:00:00Z", "account_1", "FAILED"),
        _delete("a9", "2026-09-01T09:00:00Z", "account_9", "FAILED"),
    ])
    early = _req("case_a", "a@x.com", "NOT_STARTED", requested_at="2026-08-30T12:00:00Z")
    late = _req("case_b", "b@x.com", "NOT_STARTED", requested_at="2026-09-01T12:00:00Z")
    links = accounts.link_accounts(ds, _index(), _Resolver(), [late, early])
    assert links[accounts.request_key(early)].resource_id == "account_1"
    assert accounts.request_key(late) not in links


def test_evidence_link_wins_over_activity() -> None:
    ds = Dataset(dataset_dir=Path("/nonexistent"), activity=[
        _delete("a1", "2026-09-02T11:00:00Z", "account_1", "SUCCESS"),
    ])
    req = _req("case_a", "a@x.com", "COMPLETE")
    links = accounts.link_accounts(ds, _index({"a@x.com": ["account_7"]}),
                                   _Resolver(), [req])
    assert links[accounts.request_key(req)] == accounts.AccountLink("account_7", "evidence")


def _snapshot_corpus(tmp: Path) -> list[accounts.ProfileSnapshot]:
    (tmp / "evidence").mkdir()
    bundle = {"snapshots": [
        {"captured_at": "2026-09-10T00:00:00Z", "data_store": "account_service",
         "collection": "customer_profiles", "records": [{"resource_id": "account_1"}]},
        {"captured_at": "2026-09-14T00:00:00Z", "data_store": "account_service",
         "collection": "customer_profiles", "records": []},
    ]}
    (tmp / "evidence" / "b.json").write_text(json.dumps(bundle), encoding="utf-8")
    (tmp / "evidence" / "late.json").write_text(json.dumps({"snapshots": [
        {"captured_at": "2026-09-14T06:00:00Z", "data_store": "account_service",
         "collection": "customer_profiles", "records": [{"resource_id": "account_1"}]},
    ]}), encoding="utf-8")
    with (tmp / "evidence_files.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["file_id", "file_path", "origin", "captured_at"])
        w.writerow(["evidence_b", "evidence/b.json", "svc", "2026-09-14T00:00:00Z"])
        # captured after the cutoff: must be ignored even though its snapshot is not
        w.writerow(["evidence_late", "evidence/late.json", "svc", "2026-09-20T00:00:00Z"])
    return accounts.load_profile_snapshots(tmp)


def test_synthesizes_absence_from_latest_snapshot_at_cutoff() -> None:
    with tempfile.TemporaryDirectory() as d:
        snaps = _snapshot_corpus(Path(d))
    req = _req("case_a", "a@x.com", "COMPLETE")
    ctx = accounts.AccountContext(
        {accounts.request_key(req): accounts.AccountLink("account_1", "activity")},
        snaps, _index())
    [rec] = accounts.synthesize_absence(req, [], ctx)
    assert (rec.resource_id, rec.observed_state, rec.evidence_id) == (
        "account_1", discovery.STATE_ABSENT, "evidence_b")
    assert rec.observed_at == "2026-09-14T00:00:00Z"


def test_no_synthesis_when_snapshot_still_holds_account() -> None:
    with tempfile.TemporaryDirectory() as d:
        snaps = _snapshot_corpus(Path(d))
    req = _req("case_a", "a@x.com", "COMPLETE", audit_at="2026-09-12T00:00:00Z")
    ctx = accounts.AccountContext(
        {accounts.request_key(req): accounts.AccountLink("account_1", "activity")},
        snaps, _index())
    assert accounts.synthesize_absence(req, [], ctx) == []


def test_linked_account_readback_beats_snapshot() -> None:
    """A direct observation of the linked account is used instead of synthesis."""
    obs = discovery.Observation(
        evidence_id="evidence_r", origin="svc", system_id="account_service",
        resource_id="account_1", data_category="USER_PROFILE",
        observed_state=discovery.STATE_ABSENT, observed_at="2026-09-13T00:00:00Z",
        captured_at="2026-09-13T00:00:00Z")
    idx = discovery.EvidenceIndex(fingerprint="t", observations=[obs],
                                  resource_index={"account_1": [0]})
    req = _req("case_a", "a@x.com", "COMPLETE")
    ctx = accounts.AccountContext(
        {accounts.request_key(req): accounts.AccountLink("account_1", "activity")},
        [], idx)
    [rec] = accounts.synthesize_absence(req, [], ctx)
    assert rec.evidence_id == "evidence_r"
