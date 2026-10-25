"""Tests for step ordering, serialization, and output validation."""

from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path

from ghostaudit.writer import (
    CaseResult,
    Step,
    order_steps,
    serialize_steps,
    validate_output,
    write_output_csv,
)


def test_orders_steps_by_phase_then_operation() -> None:
    """Steps sort by phase, then operation order, then ids (numeric-aware)."""
    steps = [
        Step("VERIFICATION", "account_service", "account_2", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
        Step("REMEDIATION", "search_service", "search_1", "DELETE_RECORD", "ABSENT", ""),
        Step("REMEDIATION", "integration_service", "data_flow_1", "DISABLE_DATA_FLOW", "DISABLED", ""),
        Step("FINDING", "search_service", "search_1", "REPORT_REMAINING_RECORD", "PRESENT", "e1"),
        Step("VERIFICATION", "account_service", "account_10", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
    ]
    ordered = order_steps(steps)
    assert [s.step_no for s in ordered] == [1, 2, 3, 4, 5]
    assert [s.phase for s in ordered] == [
        "FINDING", "REMEDIATION", "REMEDIATION", "VERIFICATION", "VERIFICATION"]
    # DISABLE_DATA_FLOW precedes DELETE_RECORD (operation-table order).
    assert ordered[1].operation == "DISABLE_DATA_FLOW"
    assert ordered[2].operation == "DELETE_RECORD"
    # account_2 precedes account_10 (numeric-aware).
    assert ordered[3].resource_id == "account_2"
    assert ordered[4].resource_id == "account_10"


def test_serializes_steps_to_parseable_json() -> None:
    """Serialized steps_json is a valid JSON array preserving array order."""
    steps = order_steps([
        Step("FINDING", "search_service", "search_1", "REPORT_REMAINING_RECORD", "PRESENT", "e1"),
        Step("VERIFICATION", "search_service", "search_1", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
    ])
    parsed = json.loads(serialize_steps(steps))
    assert [s["step_no"] for s in parsed] == [1, 2]
    assert parsed[0]["phase"] == "FINDING" and parsed[1]["phase"] == "VERIFICATION"
    assert set(parsed[0]) == {"step_no", "phase", "system_id", "resource_id",
                              "operation", "state", "evidence_id"}


def test_validate_output_flags_contract_violations() -> None:
    """A valid file passes; contract breaches are reported."""
    good = [
        CaseResult("case_1", "NOT_APPLICABLE", []),
        CaseResult("case_2", "INCOMPLETE", [
            Step("FINDING", "s", "r_1", "REPORT_REMAINING_RECORD", "PRESENT", "e1"),
            Step("REMEDIATION", "s", "r_1", "DELETE_RECORD", "ABSENT", ""),
            Step("VERIFICATION", "s", "r_1", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
        ]),
        CaseResult("case_10", "COMPLETE", [
            Step("VERIFICATION", "s", "r_1", "VERIFY_RECORD_ABSENT", "ABSENT", "e9"),
        ]),
    ]
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "output.csv"
        write_output_csv(good, out)
        assert validate_output(out, ["case_1", "case_2", "case_10"]) == []

        # Now corrupt it: NOT_APPLICABLE with steps, and a missing case.
        bad = Path(d) / "bad.csv"
        with bad.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["case_id", "deletion_status", "steps_json"])
            w.writerow(["case_1", "NOT_APPLICABLE",
                        json.dumps([{"step_no": 1, "phase": "FINDING", "system_id": "s",
                                     "resource_id": "r", "operation": "REPORT_REMAINING_RECORD",
                                     "state": "PRESENT", "evidence_id": "e"}])])
        problems = validate_output(bad, ["case_1", "case_2"])
        assert any("NOT_APPLICABLE must have empty steps" in p for p in problems)
        assert any("missing" in p for p in problems)
