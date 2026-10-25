"""Remediation planning: assemble the ordered findings/fix/verify step list.

Responsibility
--------------
Turn treatment findings, recreation risks, and retained records into the three
ordered phases of the output plan:

* FINDING — report remaining records, exposed PII, active flows, restore risks.
* REMEDIATION — stop recreation paths first (disable flows, block restores),
  then clean dependent copies (delete, redact, anonymize).
* VERIFICATION — confirm the required final state of every remediated record
  and process, and that required-retained records remain present.

Ordering within a phase follows the operation order in the spec, then
``system_id`` and ``resource_id``. Final sequencing and renumbering are applied
via :func:`ghostaudit.writer.order_steps`.
"""

from __future__ import annotations

from .recreation import RecreationRisk
from .retention import RetainedRecord
from .treatment import TreatmentFinding
from .writer import Step


def build_findings(
    treatments: list[TreatmentFinding], risks: list[RecreationRisk]
) -> list[Step]:
    """Build FINDING steps for non-compliant records and recreation risks."""
    raise NotImplementedError


def build_remediation(
    treatments: list[TreatmentFinding], risks: list[RecreationRisk]
) -> list[Step]:
    """Build REMEDIATION steps, recreation paths stopped before copies change."""
    raise NotImplementedError


def build_verification(
    treatments: list[TreatmentFinding],
    risks: list[RecreationRisk],
    retained: list[RetainedRecord],
) -> list[Step]:
    """Build VERIFICATION steps for required final states and retained records."""
    raise NotImplementedError


def assemble_plan(
    findings: list[Step], remediation: list[Step], verification: list[Step]
) -> list[Step]:
    """Concatenate, order, and consecutively renumber all phase steps."""
    raise NotImplementedError
