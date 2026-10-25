"""Scoring: compare predicted output against expected answers.

Responsibility
--------------
Compare a predicted ``output.csv`` against a reference file of expected answers
(for example, the public sample answers, or participant-authored cases) and
compute the metrics the challenge requires: case-level status accuracy,
step-level and field-level accuracy, and sequence accuracy. Mismatches are
retained per case so :mod:`evaluation.report` can render diffs.

This module reads two result files and scores them; it runs no auditing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CaseScore:
    """Per-case comparison outcome."""

    case_id: str
    status_correct: bool
    step_recall: float
    step_precision: float
    field_accuracy: float
    sequence_correct: bool
    mismatches: list[str] = field(default_factory=list)


@dataclass
class EvaluationResult:
    """Aggregate metrics across all compared cases."""

    case_scores: list[CaseScore] = field(default_factory=list)
    status_accuracy: float = 0.0
    step_accuracy: float = 0.0
    field_accuracy: float = 0.0
    sequence_accuracy: float = 0.0


def evaluate(
    predicted_csv: str | Path, expected_csv: str | Path
) -> EvaluationResult:
    """Score a predicted file against an expected file and aggregate metrics."""
    raise NotImplementedError


def compare_case(predicted_row: dict, expected_row: dict) -> CaseScore:
    """Compare one predicted case row against its expected row."""
    raise NotImplementedError
