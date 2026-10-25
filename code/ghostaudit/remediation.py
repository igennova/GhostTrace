"""Remediation planning: assemble the ordered findings/fix/verify step list.

Responsibility
--------------
Turn the treatment findings, recreation risks, and retention results into the
``steps_json`` plan for a case:

* FINDING — for every non-compliant copy, active flow, restore risk, or exposed
  retained record, each citing the evidence that proves it.
* REMEDIATION — the fix for each finding, with an empty evidence_id.
* VERIFICATION — the required final state of every relevant record/process. For
  a COMPLETE case these are the only steps and each cites proving evidence; for
  an INCOMPLETE case they describe future work and use an empty evidence_id.

Conceptually, recreation/restore paths are stopped before dependent copies are
relied on; the WRITTEN order, however, follows the spec's phase/operation/
system/resource rule applied by :func:`ghostaudit.writer.order_steps` — no
system-tier order is invented here.
"""

from __future__ import annotations

from .recreation import RecreationRisk
from .retention import RetentionResult
from .status import STATUS_COMPLETE, STATUS_NOT_APPLICABLE
from .treatment import TreatmentFinding
from .writer import Step, order_steps


def _relevant(
    treatments: list[TreatmentFinding],
    retentions: list[RetentionResult],
    risks: list[RecreationRisk],
):
    """Yield (system_id, resource_id, verify_op, verify_state, evidence_id) for
    every relevant record/process that should be verified."""
    for t in treatments:
        if t.verify_operation:
            yield t.system_id, t.resource_id, t.verify_operation, t.verify_state, t.evidence_id
    for r in retentions:
        if r.verify_operation:
            yield r.system_id, r.resource_id, r.verify_operation, r.verify_state, r.evidence_id
    for k in risks:
        if k.verify_operation:
            yield k.system_id, k.resource_id, k.verify_operation, k.verify_state, k.evidence_id


def build_findings(
    treatments: list[TreatmentFinding],
    retentions: list[RetentionResult],
    risks: list[RecreationRisk],
) -> list[Step]:
    """Build FINDING steps for non-compliant records and recreation risks."""
    steps: list[Step] = []
    for t in treatments:
        if not t.compliant and t.finding_operation:
            steps.append(Step("FINDING", t.system_id, t.resource_id,
                              t.finding_operation, t.finding_state, t.evidence_id))
    for r in retentions:
        if r.exposed and r.finding_operation:
            steps.append(Step("FINDING", r.system_id, r.resource_id,
                              r.finding_operation, r.finding_state, r.evidence_id))
    for k in risks:
        if k.active and k.finding_operation:
            steps.append(Step("FINDING", k.system_id, k.resource_id,
                              k.finding_operation, k.finding_state, k.evidence_id))
    return steps


def build_remediation(
    treatments: list[TreatmentFinding],
    retentions: list[RetentionResult],
    risks: list[RecreationRisk],
) -> list[Step]:
    """Build REMEDIATION steps (empty evidence_id) for every finding."""
    steps: list[Step] = []
    for t in treatments:
        if not t.compliant and t.remediation_operation:
            steps.append(Step("REMEDIATION", t.system_id, t.resource_id,
                              t.remediation_operation, t.remediation_state, ""))
    for r in retentions:
        if r.exposed and r.remediation_operation:
            steps.append(Step("REMEDIATION", r.system_id, r.resource_id,
                              r.remediation_operation, r.remediation_state, ""))
    for k in risks:
        if k.active and k.remediation_operation:
            steps.append(Step("REMEDIATION", k.system_id, k.resource_id,
                              k.remediation_operation, k.remediation_state, ""))
    return steps


def build_verification(
    treatments: list[TreatmentFinding],
    retentions: list[RetentionResult],
    risks: list[RecreationRisk],
    complete: bool,
) -> list[Step]:
    """Build VERIFICATION steps for every relevant record/process.

    For a COMPLETE case each cites the evidence proving the current state; for an
    INCOMPLETE case (future work) the evidence_id is empty.
    """
    steps: list[Step] = []
    for system_id, resource_id, op, state, evidence_id in _relevant(
            treatments, retentions, risks):
        steps.append(Step("VERIFICATION", system_id, resource_id, op, state,
                          evidence_id if complete else ""))
    return steps


def build_steps(
    status: str,
    treatments: list[TreatmentFinding],
    retentions: list[RetentionResult],
    risks: list[RecreationRisk],
) -> list[Step]:
    """Assemble, order, and renumber the full step list for a case."""
    if status == STATUS_NOT_APPLICABLE:
        return []
    complete = status == STATUS_COMPLETE
    steps: list[Step] = []
    if not complete:
        steps += build_findings(treatments, retentions, risks)
        steps += build_remediation(treatments, retentions, risks)
    steps += build_verification(treatments, retentions, risks, complete)
    return order_steps(steps)


def assemble_plan(
    findings: list[Step], remediation: list[Step], verification: list[Step]
) -> list[Step]:
    """Concatenate, order, and consecutively renumber all phase steps."""
    return order_steps([*findings, *remediation, *verification])
