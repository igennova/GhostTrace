"""Input loading: read every participant-facing CSV and locate evidence media.

Responsibility
--------------
Parse the files under ``dataset/`` into typed, in-memory records and expose a
single :class:`Dataset` container that the rest of the pipeline reads from.
This module performs no auditing logic and makes no decisions; it only reads,
types, and indexes the raw inputs, and resolves evidence file paths on disk.

It must not hardcode any specific ``case_id``, user, resource, system, or
evidence filename. All paths are derived from the supplied dataset directory.
"""

from __future__ import annotations

import csv
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

    @property
    def suffix(self) -> str:
        """Lowercase file extension (``.sql``, ``.json``, ``.pdf`` …)."""
        return Path(self.file_path).suffix.lower()

    @property
    def is_media(self) -> bool:
        """Whether this evidence is a PDF/image handled by vision later."""
        return self.suffix in {".pdf", ".png", ".jpg", ".jpeg"}


# File names are resolved relative to the dataset directory, not hardcoded.
_REQUESTS = "deletion_requests.csv"
_IDENTITIES = "user_identities.csv"
_AUDIT_LOG = "user_audit_log.csv"
_ACTIVITY = "system_activity.csv"
_RULES = "deletion_rules.csv"
_EVIDENCE = "evidence_files.csv"


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
        return {e.file_id: e for e in self.evidence}

    def identity_by_user_id(self) -> dict[str, UserIdentity]:
        """Return a ``user_id -> UserIdentity`` index for quick lookup."""
        return {u.user_id: u for u in self.identities}

    def media_files(self) -> list[EvidenceFile]:
        """Return the PDF/image evidence entries (handled by vision later)."""
        return [e for e in self.evidence if e.is_media]

    def text_files(self) -> list[EvidenceFile]:
        """Return the text evidence entries (SQL/JSON/log/txt)."""
        return [e for e in self.evidence if not e.is_media]

    def evidence_path(self, file_id: str) -> Path | None:
        """Resolve an evidence ``file_id`` to its absolute path, or ``None``."""
        entry = self.evidence_by_id().get(file_id)
        return resolve_evidence_path(self.dataset_dir, entry) if entry else None


def _read_rows(path: Path) -> list[dict[str, str]]:
    """Read a CSV into a list of dicts, tolerating a UTF-8 BOM."""
    with path.open(newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def load_dataset(dataset_dir: str | Path) -> Dataset:
    """Load all CSVs under ``dataset_dir`` into a populated :class:`Dataset`."""
    dataset_dir = Path(dataset_dir)
    return Dataset(
        dataset_dir=dataset_dir,
        requests=load_requests(dataset_dir / _REQUESTS),
        identities=load_identities(dataset_dir / _IDENTITIES),
        audit_log=load_audit_log(dataset_dir / _AUDIT_LOG),
        activity=load_activity(dataset_dir / _ACTIVITY),
        rules=load_rules(dataset_dir / _RULES),
        evidence=load_evidence_manifest(dataset_dir / _EVIDENCE),
    )


def load_requests(path: str | Path) -> list[DeletionRequest]:
    """Parse ``deletion_requests.csv`` (or the sample file) into records."""
    return [
        DeletionRequest(
            case_id=r["case_id"],
            email=r["email"],
            requested_at=r["requested_at"],
            reported_status=r["reported_status"],
            reported_at=r["reported_at"],
            audit_at=r["audit_at"],
            request_text=r["request_text"],
        )
        for r in _read_rows(Path(path))
    ]


def load_identities(path: str | Path) -> list[UserIdentity]:
    """Parse ``user_identities.csv`` into records."""
    return [
        UserIdentity(
            user_id=r["user_id"],
            name=r["name"],
            email=r["email"],
            phone=r["phone"],
            email_hash=r["email_hash"],
            updated_at=r["updated_at"],
        )
        for r in _read_rows(Path(path))
    ]


def load_audit_log(path: str | Path) -> list[AuditLogEntry]:
    """Parse ``user_audit_log.csv`` into records."""
    return [
        AuditLogEntry(
            audit_id=r["audit_id"],
            user_id=r["user_id"],
            event_time=r["event_time"],
            field_name=r["field_name"],
            old_value=r["old_value"],
            new_value=r["new_value"],
        )
        for r in _read_rows(Path(path))
    ]


def load_activity(path: str | Path) -> list[ActivityEvent]:
    """Parse ``system_activity.csv`` into records."""
    return [
        ActivityEvent(
            activity_id=r["activity_id"],
            event_time=r["event_time"],
            event_type=r["event_type"],
            source_system=r["source_system"],
            target_system=r["target_system"],
            resource_id=r["resource_id"],
            reported_result=r["reported_result"],
            details=r["details"],
        )
        for r in _read_rows(Path(path))
    ]


def load_rules(path: str | Path) -> list[DeletionRule]:
    """Parse ``deletion_rules.csv`` into records."""
    return [
        DeletionRule(
            rule_id=r["rule_id"],
            data_category=r["data_category"],
            condition=r["condition"],
            required_action=r["required_action"],
        )
        for r in _read_rows(Path(path))
    ]


def load_evidence_manifest(path: str | Path) -> list[EvidenceFile]:
    """Parse ``evidence_files.csv`` into records."""
    return [
        EvidenceFile(
            file_id=r["file_id"],
            file_path=r["file_path"],
            origin=r["origin"],
            captured_at=r["captured_at"],
        )
        for r in _read_rows(Path(path))
    ]


def resolve_evidence_path(dataset_dir: str | Path, evidence: EvidenceFile) -> Path:
    """Return the absolute on-disk path for an evidence file's manifest entry."""
    return (Path(dataset_dir) / evidence.file_path).resolve()
