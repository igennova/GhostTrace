"""Status decision: COMPLETE, INCOMPLETE, or NOT_APPLICABLE.

Responsibility
--------------
Decide the case-level ``deletion_status`` deterministically. A request that does
not authorize deletion (update, access/portability, copy/export, marketing
opt-out, email/phone change, etc.) is NOT_APPLICABLE. An authorized deletion is
COMPLETE only when ALL FOUR conditions hold at ``audit_at``:

1. every relevant copy has the treatment the rules require (all treatments
   compliant);
2. no active sync / import / restore path can recreate the data (no active
   recreation risk);
3. retained records contain only the identifiers policy permits (no retained
   record exposes prohibited identifiers);
4. records that must be retained are still present.

Otherwise it is INCOMPLETE. This module makes the classification only.
"""

from __future__ import annotations

import re

from .recreation import RecreationRisk
from .retention import RetentionResult
from .treatment import TreatmentFinding

STATUS_COMPLETE = "COMPLETE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

# Multilingual deletion-intent cues (en/es/fr/pt/de/it/ja/ko/ru/ar and more).
# A request authorizes deletion iff one of these appears in its text.
_DELETION_CUES = re.compile(
    r"delet|eras|remov|clos(e|ing)|purge|wipe|forget|forgotten"
    r"|suppress|supprim|effac|élimin|elimin|suprim|exclus|exclu|borra|cancel"
    r"|lösch|loesch|cancell|rimuov|elimina|apagar|remover"
    r"|削除|消去|抹消|삭제|удал|стере|حذف|مسح",
    re.IGNORECASE,
)


def is_authorized_deletion(request_text: str) -> bool:
    """Return whether the request text actually authorizes deletion."""
    return bool(_DELETION_CUES.search(request_text or ""))


def is_complete(
    treatments: list[TreatmentFinding],
    retentions: list[RetentionResult],
    risks: list[RecreationRisk],
) -> bool:
    """Return whether all four completeness conditions hold."""
    treated = all(t.compliant for t in treatments)              # condition 1
    no_recreation = not any(r.active for r in risks)            # condition 2
    retained_clean = all(not r.exposed for r in retentions)     # condition 3
    retained_present = all(r.present for r in retentions)        # condition 4
    return treated and no_recreation and retained_clean and retained_present


def decide_status(
    authorized: bool,
    treatments: list[TreatmentFinding],
    retentions: list[RetentionResult],
    risks: list[RecreationRisk],
) -> str:
    """Return the case ``deletion_status`` for the reconstructed state."""
    if not authorized:
        return STATUS_NOT_APPLICABLE
    if is_complete(treatments, retentions, risks):
        return STATUS_COMPLETE
    return STATUS_INCOMPLETE
