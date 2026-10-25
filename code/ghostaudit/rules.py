"""Policy engine: map a data category + condition to its required treatment.

Responsibility
--------------
Turn ``deletion_rules.csv`` into a queryable engine that returns the required
action (DELETE, REDACT, ANONYMIZE, RETAIN, or tombstone-REDACT) for a given
data category and the record's condition context. Some rules are conditional
(for example, a support message that shares context with another customer is
redacted rather than deleted, or a security log is retained only within its
retention period), so queries accept a context object that carries the facts
needed to evaluate the condition.

This module encodes the policy only; it does not inspect records or decide
whether a record currently complies.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .loader import Dataset, DeletionRule


@dataclass(frozen=True)
class RuleDecision:
    """The treatment a record requires under policy."""

    data_category: str
    required_action: str
    rule_id: str


@dataclass
class RuleContext:
    """Facts a conditional rule needs to resolve its ``condition``."""

    shared_with_other_subject: bool = False
    within_retention_period: bool = False
    legal_hold_active: bool = False
    restore_can_be_blocked: bool = False
    extra: dict[str, object] = field(default_factory=dict)


class RuleEngine:
    """Evaluates ``deletion_rules.csv`` for a category and condition context."""

    def __init__(self, rules: list[DeletionRule]) -> None:
        raise NotImplementedError

    def required_action(
        self, data_category: str, context: RuleContext | None = None
    ) -> RuleDecision:
        """Return the required treatment for a category given its context."""
        raise NotImplementedError

    def redactable_fields(self, data_category: str) -> set[str]:
        """Return the identifier fields a REDACT rule requires to be removed."""
        raise NotImplementedError


def load_rule_engine(dataset: Dataset) -> RuleEngine:
    """Build a :class:`RuleEngine` from a loaded dataset's rules."""
    raise NotImplementedError
