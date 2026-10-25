"""Treatment assessment: does each copy already satisfy its required action?

Responsibility
--------------
For each discovered record, establish its actual state *as of* ``audit_at`` from
the evidence (reconciled via the latest authoritative observation — reported
workflow statuses and log "success" results are claims, not proof), then compare
that state against the treatment the policy requires. Classify each copy as
compliant or as a finding: a record that should be gone but is present
(REPORT_REMAINING_RECORD), or one that remains while still exposing identifiers
that must be redacted/anonymized (REPORT_EXPOSED_PII).

The result drives both FINDING steps (non-compliant copies) and VERIFICATION
steps (the required final state). Retained records and account tombstones are
handled by :mod:`ghostaudit.retention`; data flows and backups by
:mod:`ghostaudit.recreation`. This module sequences nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from .discovery import (
    STATE_ABSENT,
    STATE_ANONYMIZED,
    STATE_REDACTED,
    DiscoveredRecord,
    latest_observation_per_resource,
)
from .rules import (
    ACTION_ANONYMIZE,
    ACTION_DELETE,
    ACTION_REDACT,
    RuleBook,
)

# Flow/backup states are not treatment targets (handled by recreation).
_FLOW_STATES = {"ACTIVE", "DISABLED", "BLOCKED"}
_TOMBSTONE = "ACCOUNT_TOMBSTONE"

# Per action: which actual states are already compliant, and the operations to
# emit for a finding / remediation / verification.
_PLAN = {
    ACTION_DELETE: {
        "compliant": {STATE_ABSENT},
        "finding": ("REPORT_REMAINING_RECORD", "PRESENT"),
        "remediation": ("DELETE_RECORD", "ABSENT"),
        "verify": ("VERIFY_RECORD_ABSENT", "ABSENT"),
    },
    ACTION_REDACT: {
        "compliant": {STATE_ABSENT, STATE_REDACTED},
        "finding": ("REPORT_EXPOSED_PII", "PRESENT"),
        "remediation": ("REDACT_RECORD", "REDACTED"),
        "verify": ("VERIFY_RECORD_REDACTED", "REDACTED"),
    },
    ACTION_ANONYMIZE: {
        "compliant": {STATE_ABSENT, STATE_ANONYMIZED},
        "finding": ("REPORT_EXPOSED_PII", "PRESENT"),
        "remediation": ("ANONYMIZE_RECORD", "ANONYMIZED"),
        "verify": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    },
}


@dataclass
class TreatmentFinding:
    """How one record stands relative to its required treatment at audit_at."""

    system_id: str
    resource_id: str
    data_category: str
    required_action: str
    actual_state: str
    compliant: bool
    evidence_id: str
    finding_operation: str | None = None
    finding_state: str | None = None
    remediation_operation: str | None = None
    remediation_state: str | None = None
    verify_operation: str | None = None
    verify_state: str | None = None


def assess_treatments(
    discovered: list[DiscoveredRecord],
    rules: RuleBook,
) -> list[TreatmentFinding]:
    """Classify every DELETE/REDACT/ANONYMIZE record against its required state.

    One finding per (system_id, resource_id), using the reconciled state at
    ``audit_at``. Retained categories and tombstones are skipped here.
    """
    findings: list[TreatmentFinding] = []
    for (system_id, resource_id), record in latest_observation_per_resource(discovered).items():
        category = record.data_category
        if not category or category == _TOMBSTONE:
            continue
        decision = rules.required_action(category)
        if decision is None or decision.required_action not in _PLAN:
            continue  # RETAIN / unknown / flow categories handled elsewhere
        if record.observed_state in _FLOW_STATES:
            continue

        plan = _PLAN[decision.required_action]
        compliant = record.observed_state in plan["compliant"]
        finding = TreatmentFinding(
            system_id=system_id,
            resource_id=resource_id,
            data_category=category,
            required_action=decision.required_action,
            actual_state=record.observed_state,
            compliant=compliant,
            evidence_id=record.evidence_id,
            verify_operation=plan["verify"][0],
            verify_state=plan["verify"][1],
        )
        if not compliant:
            finding.finding_operation, finding.finding_state = plan["finding"]
            finding.remediation_operation, finding.remediation_state = plan["remediation"]
        findings.append(finding)
    return findings


def assess_treatment(
    record: DiscoveredRecord, rules: RuleBook
) -> TreatmentFinding | None:
    """Classify a single discovered record (convenience wrapper)."""
    results = assess_treatments([record], rules)
    return results[0] if results else None
