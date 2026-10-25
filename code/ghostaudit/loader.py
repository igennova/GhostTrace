"""Input loading: read every participant-facing CSV and locate evidence media.

Responsibility
--------------
Parse the files under ``dataset/`` into typed, in-memory records and expose a
single :class:`Dataset` container that the rest of the pipeline reads from.
This module performs no auditing logic and makes no decisions; it only reads,
types, and indexes the raw inputs, and resolves evidence file paths on disk.

It must not hardcode any specific ``case_id``, user, resource, or evidence
filename. All paths are derived from the supplied dataset directory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class DeletionRequest:
    """One row of ``deletion_requests.csv`` — a case to audit."""

    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str


@dataclass(frozen=True)
class UserIdentity:
    """One row of ``user_identities.csv`` — current identity snapshot."""

    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: str


@dataclass(frozen=True)
class AuditLogEntry:
    """One row of ``user_audit_log.csv`` — a historical identity-field change."""

    audit_id: str
    user_id: str
    event_time: str
    field_name: str
    old_value: str
    new_value: str


@dataclass(frozen=True)
class ActivityEvent:
    """One row of ``system_activity.csv`` — a global operational event (claim)."""

    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass(frozen=True)
class DeletionRule:
    """One row of ``deletion_rules.csv`` — required treatment for a category."""

    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass(frozen=True)
class EvidenceFile:
    """One row of ``evidence_files.csv`` — an entry in the evidence manifest."""

    file_id: str
    file_path: str
    origin: str
    captured_at: str


@dataclass
class Dataset:
    """All parsed inputs plus indexes used across the pipeline."""

    dataset_dir: Path
    requests: list[DeletionRequest] = field(default_factory=list)
    identities: list[UserIdentity] = field(default_factory=list)
    audit_log: list[AuditLogEntry] = field(default_factory=list)
    activity: list[ActivityEvent] = field(default_factory=list)
    rules: list[DeletionRule] = field(default_factory=list)
    evidence: list[EvidenceFile] = field(default_factory=list)

    def evidence_by_id(self) -> dict[str, EvidenceFile]:
        """Return a ``file_id -> EvidenceFile`` index for quick lookup."""
        raise NotImplementedError

    def identity_by_user_id(self) -> dict[str, UserIdentity]:
        """Return a ``user_id -> UserIdentity`` index for quick lookup."""
        raise NotImplementedError


def load_dataset(dataset_dir: str | Path) -> Dataset:
    """Load all CSVs under ``dataset_dir`` into a populated :class:`Dataset`."""
    raise NotImplementedError


def load_requests(path: str | Path) -> list[DeletionRequest]:
    """Parse ``deletion_requests.csv`` (or the sample file) into records."""
    raise NotImplementedError


def load_identities(path: str | Path) -> list[UserIdentity]:
    """Parse ``user_identities.csv`` into records."""
    raise NotImplementedError


def load_audit_log(path: str | Path) -> list[AuditLogEntry]:
    """Parse ``user_audit_log.csv`` into records."""
    raise NotImplementedError


def load_activity(path: str | Path) -> list[ActivityEvent]:
    """Parse ``system_activity.csv`` into records."""
    raise NotImplementedError


def load_rules(path: str | Path) -> list[DeletionRule]:
    """Parse ``deletion_rules.csv`` into records."""
    raise NotImplementedError


def load_evidence_manifest(path: str | Path) -> list[EvidenceFile]:
    """Parse ``evidence_files.csv`` into records."""
    raise NotImplementedError


def resolve_evidence_path(dataset_dir: str | Path, evidence: EvidenceFile) -> Path:
    """Return the absolute on-disk path for an evidence file's manifest entry."""
    raise NotImplementedError
