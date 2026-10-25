"""Tests for media record verification and index integration (no network)."""

from __future__ import annotations

from pathlib import Path

from ghostaudit import discovery, vision
from ghostaudit.loader import ActivityEvent, Dataset, DeletionRule, EvidenceFile

_PDF_TEXT = "Support reference CS-4827 / support_001\nPriya Raman\npriya.raman@gmail.com\n+91 98765 73142"


def _raw(rid, ids, state="UNKNOWN", conf=0.95):
    return {"resource_id": rid, "identifiers": ids, "state": state, "confidence": conf}


def test_pdf_records_must_literally_appear_in_text() -> None:
    records, rejected = vision._verify_records([
        _raw("support_001", {"email": "priya.raman@gmail.com", "phone": "+91 98765 73142"}),
        _raw("support_002", {"email": "priya.raman@gmail.com"}),          # id not in text
        _raw("support_001", {"email": "someone.else@gmail.com"}),         # value not in text
    ], _PDF_TEXT)
    assert [(r.resource_id, sorted(r.identifiers)) for r in records] == [
        ("support_001", ["email", "phone"])]
    assert any("support_002" in r for r in rejected)


def test_user_reference_is_never_a_record_and_state_only_rows_survive() -> None:
    records, _ = vision._verify_records([
        _raw("user_20", {"email": "a@x.com"}),
        _raw("backup_9", {}, state="RESTORE_BLOCKED"),
        _raw("search_4", {"name": "Only A Name"}),
        _raw("search_5", {"email": "a@x.com"}, conf=0.2),
    ], None)
    assert [r.resource_id for r in records] == ["backup_9"]


def test_local_fallback_attaches_identifiers_to_the_single_resource() -> None:
    idents = [vision.ExtractedIdentifier("email", "priya.raman@gmail.com", 0.9)]
    [rec] = vision._regex_records(_PDF_TEXT + " user_07", idents)
    assert rec.resource_id == "support_001"
    assert vision._regex_records("support_001 and search_2", idents) == []


def _evidence(fid, path):
    return EvidenceFile(fid, path, "capture", "2026-09-12T07:30:00Z")


def test_records_map_through_prefix_maps_and_flag_categories_need_explicit_state() -> None:
    cat = {"support": "SUPPORT_MESSAGE", "backup": "BACKUP_ARCHIVE"}
    sys_ = {"support": "support_platform", "backup": "backup_service"}
    extraction = vision.MediaExtraction("evidence_58", "x.pdf", records=[
        vision.ExtractedRecord("support_001", {"email": "p@x.com"}, state="UNKNOWN"),
        vision.ExtractedRecord("backup_7", {"email": "p@x.com"}, state="UNKNOWN"),
        vision.ExtractedRecord("backup_8", {"email": "p@x.com"}, state="RESTORE_ALLOWED"),
        vision.ExtractedRecord("ticket_3", {"email": "p@x.com"}),  # unknown prefix
    ])
    obs = vision.extraction_to_observations(
        extraction, _evidence("evidence_58", "documents/a.pdf"), cat, sys_)
    got = {(o.resource_id, o.system_id, o.data_category, o.observed_state) for o in obs}
    assert got == {
        ("support_001", "support_platform", "SUPPORT_ATTACHMENT", discovery.STATE_EXPOSED),
        ("backup_8", "backup_service", "BACKUP_ARCHIVE", discovery.STATE_ACTIVE),
    }


def test_integrate_links_identifiers_and_falls_back_to_activity_and_rules() -> None:
    ds = Dataset(
        dataset_dir=Path("/nonexistent"),
        activity=[ActivityEvent("a1", "2026-09-16T07:27:01Z", "LINK_RESOURCE_IDENTITY",
                                "data_catalog", "marketing_platform", "marketing_001",
                                "SUCCESS", "")],
        rules=[DeletionRule("r10", "MARKETING_PROFILE", "Always", "DELETE")],
        evidence=[_evidence("evidence_60", "images/m.png")],
    )
    index = discovery.EvidenceIndex(fingerprint="t")
    extraction = vision.MediaExtraction("evidence_60", "m.png", records=[
        vision.ExtractedRecord("marketing_001", {"email": "sj@x.com"})])
    index = vision.integrate_media(index, [extraction], ds)
    [o] = index.observations
    assert (o.system_id, o.data_category) == ("marketing_platform", "MARKETING_PROFILE")
    recs = discovery.discover_by_identifiers(index, {"sj@x.com"}, "2026-09-20T00:00:00Z")
    assert [r.resource_id for r in recs] == ["marketing_001"]
