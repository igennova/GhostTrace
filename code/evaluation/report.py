"""Reporting: render evaluation metrics and mismatch diffs to Markdown.

Responsibility
--------------
Turn an :class:`evaluation.evaluate.EvaluationResult` into the human-readable
report the submission requires (``evaluation_report.md``): the headline metrics
plus per-case field-level diffs for mismatches, so failures are traceable and
improvements can be documented.

This module formats results only; it computes nothing.
"""

from __future__ import annotations

from pathlib import Path

from .evaluate import EvaluationResult


def build_report(result: EvaluationResult) -> str:
    """Render an evaluation result as a Markdown report string."""
    raise NotImplementedError


def write_report(result: EvaluationResult, path: str | Path) -> None:
    """Write the Markdown evaluation report to ``path``."""
    raise NotImplementedError


def mismatch_diffs(result: EvaluationResult) -> list[str]:
    """Return per-case human-readable diffs for every mismatch."""
    raise NotImplementedError
