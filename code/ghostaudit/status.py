"""Status decision: COMPLETE, INCOMPLETE, or NOT_APPLICABLE.

Responsibility
--------------
Decide the case-level ``deletion_status`` from the request intent and the
reconstructed state. A request that does not authorize deletion (access,
correction, export, marketing opt-out, etc.) is NOT_APPLICABLE. An authorized
deletion is COMPLETE only when every relevant copy has its required treatment,
every required-retained record remains, and no active flow or restore path can
recreate prohibited data; otherwise it is INCOMPLETE.

This module makes the top-level classification only; it does not build steps.
"""

from __future__ import annotations

from .llm import IntentResult
from .recreation import RecreationRisk
from .retention import RetainedRecord
from .treatment import TreatmentFinding

STATUS_COMPLETE = "COMPLETE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"


def decide_status(
    intent: IntentResult,
    treatments: list[TreatmentFinding],
    risks: list[RecreationRisk],
    retained: list[RetainedRecord],
) -> str:
    """Return the case ``deletion_status`` for the reconstructed state."""
    raise NotImplementedError


def is_authorized_deletion(intent: IntentResult) -> bool:
    """Return whether the request text actually authorizes deletion."""
    raise NotImplementedError


def is_complete(
    treatments: list[TreatmentFinding], risks: list[RecreationRisk]
) -> bool:
    """Return whether every copy complies and no recreation path is active."""
    raise NotImplementedError
