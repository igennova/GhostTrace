"""Output schema: the Step model, step ordering, serialization, and validation.

Responsibility
--------------
Own the exact ``output.csv`` contract. Define the :class:`Step` structure (the
shared unit of a plan), apply the canonical ordering (phase, then the spec's
operation order, then ``system_id`` then ``resource_id``) with consecutive
renumbering, serialize each case's steps to a JSON array string, and write the
final CSV with header ``case_id,deletion_status,steps_json`` sorted by
``case_id``. Also validate a produced file against the contract.

Resource and case ids are sorted numeric-aware (``account_2`` before
``account_10``), matching how the dataset presents them. This module owns
serialization only; it does not decide status or build steps.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path

PHASE_ORDER = ("FINDING", "REMEDIATION", "VERIFICATION")

OPERATION_ORDER = (
    # FINDING
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
    # REMEDIATION
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
    # VERIFICATION
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
)

OUTPUT_HEADER = ("case_id", "deletion_status", "steps_json")
VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

_PHASE_INDEX = {p: i for i, p in enumerate(PHASE_ORDER)}
_OPERATION_INDEX = {o: i for i, o in enumerate(OPERATION_ORDER)}
_STEP_FIELDS = ("step_no", "phase", "system_id", "resource_id",
                "operation", "state", "evidence_id")


@dataclass
class Step:
    """One ordered step in a case plan (finding, remediation, or verification)."""

    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str = ""
    step_no: int = 0


@dataclass
class CaseResult:
    """A fully decided case ready for serialization."""

    case_id: str
    deletion_status: str
    steps: list[Step]


def _natural_key(value: str) -> tuple:
    """Numeric-aware sort key: ``account_2`` sorts before ``account_10``."""
    parts = re.split(r"(\d+)", value or "")
    return tuple((int(p) if p.isdigit() else p) for p in parts if p != "")


def order_steps(steps: list[Step]) -> list[Step]:
    """Sort steps by phase/operation/system/resource and renumber from 1."""
    ordered = sorted(
        steps,
        key=lambda s: (
            _PHASE_INDEX.get(s.phase, len(PHASE_ORDER)),
            _OPERATION_INDEX.get(s.operation, len(OPERATION_ORDER)),
            _natural_key(s.system_id),
            _natural_key(s.resource_id),
        ),
    )
    for i, step in enumerate(ordered, start=1):
        step.step_no = i
    return ordered


def serialize_steps(steps: list[Step]) -> str:
    """Serialize ordered steps to the ``steps_json`` array string."""
    return json.dumps(
        [
            {
                "step_no": s.step_no,
                "phase": s.phase,
                "system_id": s.system_id,
                "resource_id": s.resource_id,
                "operation": s.operation,
                "state": s.state,
                "evidence_id": s.evidence_id,
            }
            for s in steps
        ],
        separators=(",", ":"),
    )


def write_output_csv(results: list[CaseResult], output_path: str | Path) -> None:
    """Write all case results to ``output.csv``, sorted by ``case_id``."""
    rows = sorted(results, key=lambda r: _natural_key(r.case_id))
    path = Path(output_path)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(OUTPUT_HEADER)
        for result in rows:
            ordered = order_steps(list(result.steps))
            writer.writerow([
                result.case_id,
                result.deletion_status,
                serialize_steps(ordered),
            ])


def validate_output(
    output_path: str | Path, expected_case_ids: list[str]
) -> list[str]:
    """Validate the written file against the contract; return any problems."""
    problems: list[str] = []
    path = Path(output_path)
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if tuple(header or ()) != OUTPUT_HEADER:
            problems.append(f"bad header: {header!r}")
        seen: list[str] = []
        for lineno, row in enumerate(reader, start=2):
            if len(row) != 3:
                problems.append(f"line {lineno}: expected 3 columns, got {len(row)}")
                continue
            case_id, status, steps_json = row
            seen.append(case_id)
            if status not in VALID_STATUSES:
                problems.append(f"{case_id}: invalid status {status!r}")
            try:
                steps = json.loads(steps_json)
            except json.JSONDecodeError as exc:
                problems.append(f"{case_id}: steps_json not valid JSON ({exc})")
                continue
            problems.extend(_validate_steps(case_id, status, steps))

    expected = sorted(expected_case_ids, key=_natural_key)
    if sorted(seen, key=_natural_key) != expected:
        missing = set(expected_case_ids) - set(seen)
        extra = set(seen) - set(expected_case_ids)
        if missing:
            problems.append(f"missing {len(missing)} case(s): {sorted(missing)[:5]}…")
        if extra:
            problems.append(f"unexpected {len(extra)} case(s): {sorted(extra)[:5]}…")
        if len(seen) != len(expected_case_ids):
            problems.append(f"row count {len(seen)} != expected {len(expected_case_ids)}")
    if seen != expected:
        problems.append("rows not sorted by case_id")
    return problems


def _validate_steps(case_id: str, status: str, steps: list) -> list[str]:
    """Validate one case's steps array against the contract."""
    problems: list[str] = []
    if status == "NOT_APPLICABLE":
        if steps != []:
            problems.append(f"{case_id}: NOT_APPLICABLE must have empty steps")
        return problems
    if not isinstance(steps, list) or not steps:
        problems.append(f"{case_id}: {status} requires a non-empty steps array")
        return problems
    for i, step in enumerate(steps, start=1):
        if set(_STEP_FIELDS) != set(step):
            problems.append(f"{case_id} step {i}: fields {sorted(step)} != contract")
            continue
        if step["step_no"] != i:
            problems.append(f"{case_id} step {i}: step_no={step['step_no']} not consecutive")
        if step["phase"] not in PHASE_ORDER:
            problems.append(f"{case_id} step {i}: bad phase {step['phase']!r}")
        if step["operation"] not in _OPERATION_INDEX:
            problems.append(f"{case_id} step {i}: bad operation {step['operation']!r}")
        if status == "COMPLETE":
            if step["phase"] != "VERIFICATION":
                problems.append(f"{case_id} step {i}: COMPLETE allows only VERIFICATION")
            if not step["evidence_id"]:
                problems.append(f"{case_id} step {i}: COMPLETE verification needs evidence_id")
        else:  # INCOMPLETE
            if step["phase"] == "FINDING" and not step["evidence_id"]:
                problems.append(f"{case_id} step {i}: finding needs evidence_id")
            if step["phase"] in ("REMEDIATION", "VERIFICATION") and step["evidence_id"]:
                problems.append(f"{case_id} step {i}: {step['phase']} must have empty evidence_id")
    return problems
