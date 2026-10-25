"""Tests for step ordering, serialization, and output validation.

Covers: canonical phase/operation/system/resource ordering with consecutive
renumbering, JSON serialization that the grader can parse, retained-record
verification steps, and contract validation (header, row count, consecutive
step numbers, evidence-id rules).
"""

from __future__ import annotations


def test_orders_steps_by_phase_then_operation() -> None:
    """Steps sort by phase, then spec operation order, then ids, renumbered."""
    raise NotImplementedError


def test_serializes_steps_to_parseable_json() -> None:
    """Serialized ``steps_json`` is a valid JSON array in array order."""
    raise NotImplementedError


def test_validate_output_flags_contract_violations() -> None:
    """Validation reports missing cases, bad numbering, and evidence misuse."""
    raise NotImplementedError
