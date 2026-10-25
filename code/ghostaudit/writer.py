"""Output schema: the Step model, step ordering, serialization, and validation.

Responsibility
--------------
Own the exact ``output.csv`` contract. Define the :class:`Step` structure
(the shared unit of a plan), apply the canonical ordering (phase, then the
spec's operation order, then ``system_id`` then ``resource_id``) with
consecutive renumbering, serialize each case's steps to a JSON array string,
and write the final CSV with header ``case_id,deletion_status,steps_json``
sorted by ``case_id``. Also validate a produced file against the contract.

This module owns serialization only; it does not decide status or build steps.
"""

from __future__ import annotations

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


def order_steps(steps: list[Step]) -> list[Step]:
    """Sort steps by phase/operation/system/resource and renumber from 1."""
    raise NotImplementedError


def serialize_steps(steps: list[Step]) -> str:
    """Serialize ordered steps to the ``steps_json`` array string."""
    raise NotImplementedError


def write_output_csv(results: list[CaseResult], output_path: str | Path) -> None:
    """Write all case results to ``output.csv``, sorted by ``case_id``."""
    raise NotImplementedError


def validate_output(
    output_path: str | Path, expected_case_ids: list[str]
) -> list[str]:
    """Validate the written file against the contract; return any problems."""
    raise NotImplementedError
