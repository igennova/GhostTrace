"""Recreation risk: detect paths that can resurrect deleted data.

Responsibility
--------------
A deletion is not complete while an active process can copy the subject's data
back into a cleaned system, or a backup can restore it. This module inspects
connector/sync configurations and backup/restore entries in the evidence
(their enabled/restore-allowed state at ``audit_at``) for the subject, and
reports each live data flow or restorable archive.

These become REPORT_ACTIVE_DATA_FLOW and REPORT_RESTORE_RISK findings, and must
be remediated before dependent copies are cleaned. This module only detects
risks; ordering and remediation live in :mod:`ghostaudit.remediation`.
"""

from __future__ import annotations

from dataclasses import dataclass

from .identity import Identity
from .loader import Dataset

KIND_DATA_FLOW = "DATA_FLOW"
KIND_RESTORE = "RESTORE"


@dataclass
class RecreationRisk:
    """An active data flow or restorable backup that can recreate the data."""

    system_id: str
    resource_id: str
    kind: str
    active: bool
    evidence_id: str = ""


def detect_recreation_paths(
    identity: Identity, dataset: Dataset, audit_at: str
) -> list[RecreationRisk]:
    """Return all active recreation risks for the subject at ``audit_at``."""
    raise NotImplementedError


def active_data_flows(
    identity: Identity, dataset: Dataset, audit_at: str
) -> list[RecreationRisk]:
    """Return enabled sync/import connectors referencing the subject."""
    raise NotImplementedError


def restore_risks(
    identity: Identity, dataset: Dataset, audit_at: str
) -> list[RecreationRisk]:
    """Return backup archives whose restore path is not blocked."""
    raise NotImplementedError
