"""Orchestration: run the bounded audit pipeline for one case and for all.

Responsibility
--------------
Wire the single-responsibility modules into one bounded flow per request:
classify intent, resolve identity, discover records at ``audit_at`` (plus a
synthesized ABSENT row for a deleted, linked account), apply
policy, assess treatment, recreation risk, and retention, decide status, and
assemble the ordered plan. NOT_APPLICABLE yields an empty plan; COMPLETE is
verification-only; INCOMPLETE is findings + remediation + verification.

The substantive logic lives in the modules this coordinates.
"""

from __future__ import annotations

from . import accounts, discovery, recreation, remediation, retention, status, treatment
from .identity import IdentityResolver
from .loader import Dataset, DeletionRequest
from .rules import RuleBook
from .writer import CaseResult


def _intent(request: DeletionRequest, intent_classifier) -> dict:
    """Decide deletion intent: LLM when available, deterministic regex otherwise."""
    if intent_classifier is not None:
        try:
            r = intent_classifier.classify(request.request_text)
            return {"authorizes_deletion": r.authorizes_deletion,
                    "source": "llm" if r.source in ("llm", "cache") else r.source,
                    "action_type": r.action_type, "rationale": r.rationale}
        except Exception:  # noqa: BLE001 — any LLM failure falls back to regex
            pass
    return {"authorizes_deletion": status.is_authorized_deletion(request.request_text),
            "source": "regex", "action_type": "", "rationale": "multilingual cue match"}


def _after_request(records, requested_at: str):
    """Keep observations captured at or after the request was made.

    Evidence captured before the request can only show the data as it was
    before deletion was asked for; it cannot establish the post-request state.
    """
    start = discovery._parse_ts(requested_at)
    if start is None:
        return records
    kept = []
    for r in records:
        captured = discovery._parse_ts(r.captured_at or r.observed_at)
        if captured is None or captured >= start:
            kept.append(r)
    return kept


def _matched_kinds(tokens: list[str]) -> list[str]:
    """Describe matched identifier tokens by kind only (no raw values in traces)."""
    kinds = set()
    for t in tokens:
        if t.startswith("("):
            kinds.add(t.strip("()").split(":")[0])
        elif "@" in t:
            kinds.add("email")
        elif t.startswith("tel:") or t.startswith("+"):
            kinds.add("phone")
        elif t.startswith("user_"):
            kinds.add("user_id")
        elif len(t) == 64:
            kinds.add("email_hash")
        else:
            kinds.add("other")
    return sorted(kinds)


def _status_reason(decision, treatments, retentions, risks) -> str:
    if decision == status.STATUS_NOT_APPLICABLE:
        return "request does not authorize deletion"
    bad = [t for t in treatments if not t.compliant]
    exposed = [r for r in retentions if r.exposed]
    missing = [r for r in retentions if not r.present]
    active = [k for k in risks if k.active]
    if decision == status.STATUS_COMPLETE:
        return (f"all {len(treatments)} policy-scoped records compliant, "
                f"{len(retentions)} retained record(s) present and clean, "
                f"no active flow/restore path among {len(risks)}")
    parts = []
    if bad:
        parts.append(f"{len(bad)} record(s) not in required state")
    if exposed:
        parts.append(f"{len(exposed)} retained record(s) expose prohibited identifiers")
    if missing:
        parts.append(f"{len(missing)} required retained record(s) missing")
    if active:
        parts.append(f"{len(active)} active recreation path(s)")
    return "; ".join(parts) or "no evidence-backed proof of the required state"


def _build_trace(request, identity, intent, link, records, treatments, retentions,
                 risks, decision, steps) -> dict:
    """Assemble the per-case decision trace (evidence ids + reasoning)."""
    basis: dict[tuple[str, str], str] = {}
    for t in treatments:
        basis[(t.system_id, t.resource_id)] = (
            f"{t.data_category} requires {t.required_action}; observed "
            f"{t.actual_state} ({'compliant' if t.compliant else 'violation'}) in {t.evidence_id}")
    for r in retentions:
        basis[(r.system_id, r.resource_id)] = (
            f"{r.data_category} must be retained; present={r.present} "
            f"exposed={r.exposed} in {r.evidence_id}")
    for k in risks:
        basis[(k.system_id, k.resource_id)] = (
            f"{k.kind} {'ACTIVE' if k.active else 'inactive'} per {k.basis} {k.evidence_id}")
    return {
        "case_id": request.case_id,
        "deletion_status": decision,
        "audit_at": request.audit_at,
        "reported_status": request.reported_status,
        "intent": intent,
        "subject": {"user_id": getattr(identity, "user_id", "") if identity else ""},
        "account_link": ({"resource_id": link.resource_id, "source": link.source,
                          "activity_id": link.activity_id} if link else None),
        "records": [
            {"system_id": r.system_id, "resource_id": r.resource_id,
             "data_category": r.data_category, "observed_state": r.observed_state,
             "observed_at": r.observed_at, "evidence_id": r.evidence_id,
             "matched_on": _matched_kinds(r.matched_on)}
            for r in records
        ],
        "status_reason": _status_reason(decision, treatments, retentions, risks),
        "steps": [
            {"step_no": s.step_no, "phase": s.phase, "operation": s.operation,
             "system_id": s.system_id, "resource_id": s.resource_id,
             "evidence_id": s.evidence_id,
             "basis": basis.get((s.system_id, s.resource_id), "")}
            for s in steps
        ],
    }


def audit_case(
    request: DeletionRequest,
    dataset: Dataset,
    rules: RuleBook,
    index: discovery.EvidenceIndex,
    resolver: IdentityResolver,
    intent_classifier=None,
    account_context: accounts.AccountContext | None = None,
) -> CaseResult:
    """Audit a single request end to end and return its decided result."""
    intent = _intent(request, intent_classifier)
    if not intent["authorizes_deletion"]:
        decision = status.STATUS_NOT_APPLICABLE
        trace = _build_trace(request, None, intent, None, [], [], [], [], decision, [])
        return CaseResult(request.case_id, decision, [], trace)

    identity = resolver.resolve(request.email)
    records = discovery.discover_by_identifiers(
        index, identity.match_keys(), request.audit_at)
    records = _after_request(records, request.requested_at)
    records += accounts.synthesize_absence(request, records, account_context)

    treatments = treatment.assess_treatments(records, rules)
    retentions = retention.assess_retention(records, rules)
    risks = recreation.detect_recreation(records, dataset, identity, request.audit_at)

    decision = status.decide_status(True, treatments, retentions, risks)
    steps = remediation.build_steps(decision, treatments, retentions, risks)
    link = account_context.links.get(accounts.request_key(request)) if account_context else None
    trace = _build_trace(request, identity, intent, link, records, treatments,
                         retentions, risks, decision, steps)
    return CaseResult(request.case_id, decision, steps, trace)


def audit_all(
    dataset: Dataset,
    rules: RuleBook,
    index: discovery.EvidenceIndex,
    resolver: IdentityResolver,
    intent_classifier=None,
    account_context: accounts.AccountContext | None = None,
) -> list[CaseResult]:
    """Audit every request in the dataset and return all case results."""
    if account_context is None:
        account_context = accounts.AccountContext.build(dataset, index, resolver)
    return [
        audit_case(request, dataset, rules, index, resolver, intent_classifier,
                   account_context)
        for request in dataset.requests
    ]
