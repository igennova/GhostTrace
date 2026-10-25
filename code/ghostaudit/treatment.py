"""Treatment assessment: does each copy already satisfy its required action?

Responsibility
--------------
For every discovered record, compare its actual state against the treatment the
policy engine requires, and classify the outcome: a record that should be gone
but is present, a record that may remain but still exposes identifiers that
must be redacted or anonymized, or a record that already complies.

The result drives both the FINDING steps (for non-compliant copies) and the
VERIFICATION steps (for the required final state). This module reads records
and rule decisions only; it does not sequence steps or decide case status.
"""

from __future__ import annotations

from dataclasses import dataclass

from .discovery import DiscoveredRecord
from .identity import Identity
from .rules import RuleDecision


@dataclass
class TreatmentFinding:
    """How one record stands relative to its required treatment."""

    record: DiscoveredRecord
    required_action: str
    satisfied: bool
    finding_operation: str | None = None
    finding_state: str | None = None
    target_state: str | None = None


def assess_treatment(
    record: DiscoveredRecord, decision: RuleDecision, identity: Identity
) -> TreatmentFinding:
    """Classify a record against its required action into a finding."""
    raise NotImplementedError


def is_record_absent(record: DiscoveredRecord) -> bool:
    """Return whether the record no longer exists in its source."""
    raise NotImplementedError


def has_exposed_pii(record: DiscoveredRecord, identity: Identity) -> bool:
    """Return whether the record still exposes identifiers policy forbids."""
    raise NotImplementedError


def is_redacted(record: DiscoveredRecord, required_fields: set[str]) -> bool:
    """Return whether all policy-required identifier fields are removed."""
    raise NotImplementedError


def is_anonymized(record: DiscoveredRecord) -> bool:
    """Return whether the record is irreversibly unlinked from the subject."""
    raise NotImplementedError
