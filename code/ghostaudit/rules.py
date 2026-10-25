"""Policy engine: map a data category (and system) to its required treatment.

Responsibility
--------------
Turn ``deletion_rules.csv`` into a queryable rule book that returns, for a data
category: the required action (DELETE / REDACT / ANONYMIZE / RETAIN), the
identifiers a surviving record is permitted to keep, and whether the record
*must* be retained (policy forbids deleting it). Categories come straight from
the CSV; the system dimension, when requested, is materialized from
``(system_id, data_category)`` pairs observed in the evidence rather than a
hardcoded system list.

Some rules are conditional (a support message shared with another customer is
redacted not deleted; a security log is retained only within its window), so
queries accept an optional :class:`RuleContext` carrying the facts a condition
needs. This module encodes policy only; it does not inspect records.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .loader import Dataset, DeletionRule

# Canonical action vocabulary (values seen in deletion_rules.csv).
ACTION_DELETE = "DELETE"
ACTION_REDACT = "REDACT"
ACTION_ANONYMIZE = "ANONYMIZE"
ACTION_RETAIN = "RETAIN"

# Field names that directly identify a person. A record "exposes PII" while any
# of these is populated. Derived from the identifier columns/keys that recur
# across the evidence corpus, not from any specific case.
DIRECT_IDENTIFIER_FIELDS: frozenset[str] = frozenset({
    "name",
    "full_name",
    "display_name",
    "requester_name",
    "email",
    "requester_email",
    "owner_email",
    "customer_email",
    "contact_email",
    "phone",
    "requester_phone",
    "owner_phone",
    "email_hash",
})

# Field names that carry only a stable internal reference (no direct PII). These
# are what an account tombstone or a redacted record is permitted to keep.
STABLE_REFERENCE_FIELDS: frozenset[str] = frozenset({
    "user_id",
    "customer_reference",
    "subject_reference",
    "subject_selector",
})


@dataclass(frozen=True)
class RuleContext:
    """Facts a conditional rule needs to resolve its ``condition`` text."""

    shared_with_other_subject: bool = False
    within_retention_period: bool = False
    legal_hold_active: bool = False
    restore_can_be_blocked: bool = False
    extra: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleDecision:
    """The treatment a data category requires under policy."""

    data_category: str
    required_action: str
    rule_id: str
    condition: str
    #: Record is kept (possibly transformed) rather than removed outright.
    record_survives: bool
    #: Policy forbids deleting this record (it must remain available).
    must_retain: bool
    #: Identifier fields a surviving record may keep.
    permitted_identifiers: frozenset[str]
    #: Identifier fields that must be removed from a surviving record.
    prohibited_identifiers: frozenset[str]


def _derive_decision(rule: DeletionRule) -> RuleDecision:
    """Compute the permitted/prohibited identifier sets for one rule."""
    action = rule.required_action.strip().upper()

    if action == ACTION_DELETE:
        permitted: frozenset[str] = frozenset()
        prohibited = DIRECT_IDENTIFIER_FIELDS | STABLE_REFERENCE_FIELDS
        survives = False
        must_retain = False
    elif action == ACTION_REDACT:
        # Keep the record and its stable reference; strip direct identifiers.
        permitted = STABLE_REFERENCE_FIELDS
        prohibited = DIRECT_IDENTIFIER_FIELDS
        survives = True
        must_retain = True
    elif action == ACTION_ANONYMIZE:
        # Keep the record but irreversibly unlink it from the subject.
        permitted = frozenset()
        prohibited = DIRECT_IDENTIFIER_FIELDS | STABLE_REFERENCE_FIELDS
        survives = True
        must_retain = False
    elif action == ACTION_RETAIN:
        # Keep the whole record as-is (retention/legal hold/backup archive).
        permitted = DIRECT_IDENTIFIER_FIELDS | STABLE_REFERENCE_FIELDS
        prohibited = frozenset()
        survives = True
        must_retain = True
    else:  # Unknown action: treat conservatively as keep-as-is, flag via rule.
        permitted = DIRECT_IDENTIFIER_FIELDS | STABLE_REFERENCE_FIELDS
        prohibited = frozenset()
        survives = True
        must_retain = True

    return RuleDecision(
        data_category=rule.data_category.strip().upper(),
        required_action=action,
        rule_id=rule.rule_id,
        condition=rule.condition,
        record_survives=survives,
        must_retain=must_retain,
        permitted_identifiers=permitted,
        prohibited_identifiers=prohibited,
    )


class RuleBook:
    """Queryable view of ``deletion_rules.csv`` keyed by data category."""

    def __init__(self, rules: list[DeletionRule]) -> None:
        self._by_category: dict[str, RuleDecision] = {}
        for rule in rules:
            decision = _derive_decision(rule)
            # First rule for a category wins; later duplicates are ignored.
            self._by_category.setdefault(decision.data_category, decision)

    @classmethod
    def from_dataset(cls, dataset: Dataset) -> "RuleBook":
        """Build a rule book from a loaded dataset's rules."""
        return cls(dataset.rules)

    def categories(self) -> set[str]:
        """Return the set of data categories the policy defines."""
        return set(self._by_category)

    def required_action(
        self, data_category: str, context: RuleContext | None = None
    ) -> RuleDecision | None:
        """Return the treatment for a category, or ``None`` if unknown.

        ``context`` is accepted for conditional rules; the base decision is
        returned as-is and callers may further interpret ``condition`` with the
        context's facts.
        """
        return self._by_category.get(self._normalize(data_category))

    def treatment(
        self,
        system_id: str,
        data_category: str,
        context: RuleContext | None = None,
    ) -> RuleDecision | None:
        """System-aware entry point. Treatment is determined by the category.

        The ``system_id`` is accepted so callers can query by a discovered
        record's (system, category) pair; it does not change the decision,
        which the policy keys on category alone.
        """
        return self.required_action(data_category, context)

    def must_retain(self, data_category: str) -> bool:
        """Return whether policy forbids deleting records of this category."""
        decision = self.required_action(data_category)
        return bool(decision and decision.must_retain)

    def permitted_identifiers(self, data_category: str) -> frozenset[str]:
        """Return the identifier fields a surviving record of this category may keep."""
        decision = self.required_action(data_category)
        return decision.permitted_identifiers if decision else frozenset()

    def build_lookup(
        self, observed_pairs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], RuleDecision]:
        """Materialize a ``(system_id, data_category) -> RuleDecision`` table.

        ``observed_pairs`` are the (system, category) pairs actually seen in the
        evidence (from :mod:`ghostaudit.discovery`), so the table covers only
        real systems and no system name is hardcoded here.
        """
        lookup: dict[tuple[str, str], RuleDecision] = {}
        for system_id, data_category in observed_pairs:
            decision = self.required_action(data_category)
            if decision is not None:
                lookup[(system_id, self._normalize(data_category))] = decision
        return lookup

    @staticmethod
    def _normalize(data_category: str) -> str:
        """Normalize a category string for lookup."""
        return (data_category or "").strip().upper()


def load_rule_engine(dataset: Dataset) -> RuleBook:
    """Build a :class:`RuleBook` from a loaded dataset's rules."""
    return RuleBook.from_dataset(dataset)
