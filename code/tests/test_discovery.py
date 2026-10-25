"""Tests for record discovery and identifier matching over a small corpus."""

from __future__ import annotations

import csv
import tempfile
from pathlib import Path

from ghostaudit import discovery


def _corpus(tmp: Path, handover_lines: str) -> discovery.EvidenceIndex:
    (tmp / "evidence").mkdir(parents=True, exist_ok=True)
    (tmp / "evidence" / "h.txt").write_text(handover_lines, encoding="utf-8")
    with (tmp / "evidence_files.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["file_id", "file_path", "origin", "captured_at"])
        w.writerow(["evidence_h", "evidence/h.txt", "svc", "2026-09-15T12:00:00Z"])
    return discovery.build_evidence_index(tmp, cache_path=tmp / ".cache" / "i.json", rebuild=True)


def test_discovers_records_matching_any_identifier() -> None:
    """A record matching any supplied identifier is discovered."""
    body = "2026-09-01T00:00:00Z | account_service | account_1 | USER_PROFILE | FOUND | a@x.com\n"
    with tempfile.TemporaryDirectory() as d:
        idx = _corpus(Path(d), body)
        recs = discovery.discover_by_identifiers(idx, {"a@x.com"}, "2026-09-20T00:00:00Z")
    assert len(recs) == 1 and recs[0].resource_id == "account_1"
    assert recs[0].observed_state == discovery.STATE_PRESENT


def test_ignores_evidence_after_audit_at() -> None:
    """An observation dated after audit_at is excluded."""
    body = "2026-09-10T00:00:00Z | account_service | account_1 | USER_PROFILE | FOUND | a@x.com\n"
    with tempfile.TemporaryDirectory() as d:
        idx = _corpus(Path(d), body)
        recs = discovery.discover_by_identifiers(idx, {"a@x.com"}, "2026-09-01T00:00:00Z")
    assert recs == []


def test_does_not_match_decoy_subject() -> None:
    """A similar record belonging to another subject is not matched."""
    body = (
        "2026-09-01T00:00:00Z | account_service | account_1 | USER_PROFILE | FOUND | a@x.com\n"
        "2026-09-01T00:00:00Z | account_service | account_2 | USER_PROFILE | FOUND | a2@x.com\n"
    )
    with tempfile.TemporaryDirectory() as d:
        idx = _corpus(Path(d), body)
        recs = discovery.discover_by_identifiers(idx, {"a@x.com"}, "2026-09-20T00:00:00Z")
    assert [r.resource_id for r in recs] == ["account_1"]
