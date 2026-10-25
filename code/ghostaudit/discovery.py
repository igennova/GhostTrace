"""Discovery: find every record that references the subject, at ``audit_at``.

Responsibility
--------------
Scan the evidence corpus — SQL snapshots, JSON bundles/exports, logs, text
handovers, and (via :mod:`ghostaudit.vision`) PDFs and images — plus the global
activity stream, for any record whose fields match one of the subject's
identifiers. Only evidence captured at or before ``audit_at`` may establish the
state for a case; later evidence is ignored.

Each hit is normalized into a :class:`DiscoveredRecord` carrying its system,
resource id, inferred data category, the exposed identifier fields, whether the
record is present, and the ``evidence_id`` that proves it. This module only
locates and normalizes records; policy and treatment decisions live elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .identity import Identity
from .loader import Dataset, EvidenceFile


@dataclass
class DiscoveredRecord:
    """A single record found in one evidence source that references the subject."""

    system_id: str
    resource_id: str
    data_category: str
    present: bool
    exposed_identifiers: dict[str, str] = field(default_factory=dict)
    raw_fields: dict[str, object] = field(default_factory=dict)
    evidence_id: str = ""
    captured_at: str = ""


def discover_records(
    identity: Identity, dataset: Dataset, audit_at: str
) -> list[DiscoveredRecord]:
    """Return every subject-matching record established at/before ``audit_at``."""
    raise NotImplementedError


def select_snapshot(
    identity: Identity, dataset: Dataset, audit_at: str
) -> EvidenceFile | None:
    """Pick the authoritative multi-system snapshot nearest to ``audit_at``."""
    raise NotImplementedError


def scan_evidence_file(
    evidence: EvidenceFile, identity: Identity, dataset: Dataset
) -> list[DiscoveredRecord]:
    """Parse one evidence file and return subject-matching records from it."""
    raise NotImplementedError


def scan_sql_snapshot(
    path: str, identity: Identity, evidence: EvidenceFile
) -> list[DiscoveredRecord]:
    """Execute a SQLite snapshot and extract subject-matching rows."""
    raise NotImplementedError


def scan_json_bundle(
    path: str, identity: Identity, evidence: EvidenceFile
) -> list[DiscoveredRecord]:
    """Walk a JSON snapshot/export bundle for subject-matching records."""
    raise NotImplementedError


def scan_log_or_text(
    path: str, identity: Identity, evidence: EvidenceFile
) -> list[DiscoveredRecord]:
    """Parse a structured log or text handover for subject state lines."""
    raise NotImplementedError


def classify_category(system_id: str, record_fields: dict[str, object]) -> str:
    """Infer the policy data category for a record from its system and shape."""
    raise NotImplementedError
