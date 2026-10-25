"""Orchestration: run the bounded audit pipeline for one case and for all.

Responsibility
--------------
Wire the single-responsibility modules into one bounded flow per request:
classify intent, resolve identity, discover records at ``audit_at``, apply
policy, assess treatment, recreation risk, and retention, decide status, and
assemble the ordered plan. NOT_APPLICABLE yields an empty plan; COMPLETE is
verification-only; INCOMPLETE is findings + remediation + verification.

The substantive logic lives in the modules this coordinates.
"""

from __future__ import annotations

from . import discovery, recreation, remediation, retention, status, treatment
from .identity import IdentityResolver
from .loader import Dataset, DeletionRequest
from .rules import RuleBook
from .writer import CaseResult


def audit_case(
    request: DeletionRequest,
    dataset: Dataset,
    rules: RuleBook,
    index: discovery.EvidenceIndex,
    resolver: IdentityResolver,
) -> CaseResult:
    """Audit a single request end to end and return its decided result."""
    authorized = status.is_authorized_deletion(request.request_text)
    if not authorized:
        return CaseResult(request.case_id, status.STATUS_NOT_APPLICABLE, [])

    identity = resolver.resolve(request.email)
    records = discovery.discover_by_identifiers(
        index, identity.match_keys(), request.audit_at)

    treatments = treatment.assess_treatments(records, rules)
    retentions = retention.assess_retention(records, rules)
    risks = recreation.detect_recreation(records, dataset, identity, request.audit_at)

    decision = status.decide_status(authorized, treatments, retentions, risks)
    steps = remediation.build_steps(decision, treatments, retentions, risks)
    return CaseResult(request.case_id, decision, steps)


def audit_all(
    dataset: Dataset,
    rules: RuleBook,
    index: discovery.EvidenceIndex,
    resolver: IdentityResolver,
) -> list[CaseResult]:
    """Audit every request in the dataset and return all case results."""
    return [
        audit_case(request, dataset, rules, index, resolver)
        for request in dataset.requests
    ]
