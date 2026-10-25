"""Orchestration: run the bounded audit pipeline for one case and for all.

Responsibility
--------------
Wire the single-responsibility modules into one bounded flow per request:
classify intent, resolve identity, discover records at ``audit_at``, apply
policy, assess treatment, detect recreation risks, determine retained records,
decide status, and assemble the ordered plan. For NOT_APPLICABLE cases the plan
is empty; for COMPLETE cases it is verification-only; for INCOMPLETE cases it is
findings + remediation + verification.

This module coordinates; the substantive logic lives in the modules it calls.
"""

from __future__ import annotations

from .llm import LLMClient
from .loader import Dataset, DeletionRequest
from .rules import RuleEngine
from .writer import CaseResult


def audit_case(
    request: DeletionRequest,
    dataset: Dataset,
    rules: RuleEngine,
    llm_client: LLMClient,
) -> CaseResult:
    """Audit a single request end to end and return its decided result."""
    raise NotImplementedError


def audit_all(
    dataset: Dataset,
    rules: RuleEngine,
    llm_client: LLMClient,
) -> list[CaseResult]:
    """Audit every request in the dataset and return all case results."""
    raise NotImplementedError
