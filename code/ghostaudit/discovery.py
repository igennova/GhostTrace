"""Discovery: a shared, cached evidence index over the whole corpus.

Responsibility
--------------
Scan every TEXT evidence file in the corpus exactly once, deterministically,
and build an inverted index from normalized identifier -> observations. Each
observation records where a record was seen (``evidence_id`` / ``activity_id`` /
``audit_id``), its ``system_id``, ``resource_id``, inferred ``data_category``,
the ``observed_state`` the evidence reports, and a timestamp. The index is
cached to disk keyed by a corpus fingerprint and reused across all 518 cases.

Per request, :func:`discover_records` returns every observation in every system
whose record matches any of the subject's identifiers, as of ``audit_at``.

SQL snapshots are loaded into in-memory SQLite and queried (they are
SQLite-compatible) rather than regex-scraped. JSON, logs, and txt are parsed
structurally. Systems and categories are derived from the data: explicit where
the evidence labels them, otherwise learned from labeled evidence by resource
prefix. Media (PDF/image) is delegated to :mod:`ghostaudit.vision` via
:func:`scan_media_file`, which is a hook returning nothing until vision lands.

No system names, categories, resource ids, or case ids are hardcoded.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .rules import DIRECT_IDENTIFIER_FIELDS, STABLE_REFERENCE_FIELDS

# ---------------------------------------------------------------------------
# Normalized observed-state vocabulary (what the evidence reports, not policy).
# ---------------------------------------------------------------------------
STATE_PRESENT = "PRESENT"       # record exists / found
STATE_ABSENT = "ABSENT"         # record not found / deleted
STATE_EXPOSED = "EXPOSED"       # present and still carries direct identifiers
STATE_ANONYMIZED = "ANONYMIZED"  # present but no direct identifier
STATE_REDACTED = "REDACTED"     # present, only a stable reference remains
STATE_ACTIVE = "ACTIVE"         # data flow enabled / backup restorable
STATE_DISABLED = "DISABLED"     # data flow disabled
STATE_BLOCKED = "BLOCKED"       # backup restore blocked
STATE_UNKNOWN = "UNKNOWN"

TEXT_SUFFIXES = {".sql", ".json", ".log", ".txt"}
MEDIA_SUFFIXES = {".pdf", ".png", ".jpg", ".jpeg"}

# Record fields used to match a record to a subject. Names are intentionally
# excluded (too noisy / decoy-prone); matching uses strong identifiers only.
_MATCH_FIELD_NAMES: frozenset[str] = (
    (DIRECT_IDENTIFIER_FIELDS - {"name", "full_name", "display_name", "requester_name"})
    | STABLE_REFERENCE_FIELDS
    | {"lookup_key", "match_key", "correlation_key", "query", "lookup_value",
       "owner", "key"}
)

# Fields recorded for display (includes names) but not all used for matching.
_IDENTIFIER_FIELD_NAMES: frozenset[str] = (
    DIRECT_IDENTIFIER_FIELDS | STABLE_REFERENCE_FIELDS
    | {"lookup_key", "match_key", "correlation_key", "query", "lookup_value"}
)

_CACHE_VERSION = "1"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Observation:
    """One record seen in one evidence source that may reference a subject."""

    evidence_id: str
    origin: str
    system_id: str
    resource_id: str
    data_category: str
    observed_state: str
    observed_at: str
    identifiers: dict[str, str] = field(default_factory=dict)
    source_path: str = ""
    table_or_collection: str = ""
    matched_on: list[str] = field(default_factory=list)


@dataclass
class EvidenceIndex:
    """All observations plus an inverted identifier index and learned maps."""

    fingerprint: str
    observations: list[Observation] = field(default_factory=list)
    token_index: dict[str, list[int]] = field(default_factory=dict)

    def observed_pairs(self) -> list[tuple[str, str]]:
        """Return the distinct (system_id, data_category) pairs observed."""
        pairs = {
            (o.system_id, o.data_category)
            for o in self.observations
            if o.system_id and o.data_category
        }
        return sorted(pairs)


@dataclass
class DiscoveredRecord:
    """A subject-matching observation returned for one request."""

    system_id: str
    resource_id: str
    data_category: str
    observed_state: str
    observed_at: str
    evidence_id: str
    identifiers: dict[str, str] = field(default_factory=dict)
    matched_on: list[str] = field(default_factory=list)
    table_or_collection: str = ""


# ---------------------------------------------------------------------------
# Identifier normalization (shared by indexing and query key construction)
# ---------------------------------------------------------------------------
def normalize_tokens(value: object) -> set[str]:
    """Return the normalized match tokens for a raw identifier value.

    Emails collapse to lowercase; phone-like values to a ``tel:<digits>`` token;
    everything else to its lowercased string. One value may yield several tokens
    (e.g. a phone written with spaces), and the same function is used on both
    evidence values and subject identifiers so they compare equal.
    """
    tokens: set[str] = set()
    if value is None:
        return tokens
    s = str(value).strip()
    if not s:
        return tokens
    low = s.lower()
    if "@" in low:
        tokens.add(low)
        return tokens
    digits = re.sub(r"\D", "", s)
    if len(digits) >= 7 and sum(c.isdigit() for c in s) >= len(s) - 6:
        tokens.add(f"tel:{digits}")
    tokens.add(low)
    return tokens


def _collect_identifier_values(record: dict) -> dict[str, str]:
    """Pull identifier-bearing fields out of a flat record dict (for display)."""
    found: dict[str, str] = {}
    for key, val in record.items():
        if val in (None, ""):
            continue
        if key in _IDENTIFIER_FIELD_NAMES and not isinstance(val, (dict, list)):
            found[key] = str(val)
    return found


def _match_tokens_for_record(identifiers: dict[str, str]) -> set[str]:
    """Build the set of match tokens for a record's identifier fields."""
    tokens: set[str] = set()
    for key, val in identifiers.items():
        if key in _MATCH_FIELD_NAMES or key in STABLE_REFERENCE_FIELDS:
            tokens |= normalize_tokens(val)
    return tokens


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------
def _parse_ts(value: str) -> datetime | None:
    """Parse an ISO-8601 (``...Z``) timestamp, or return ``None``."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _at_or_before(observed_at: str, audit_at: str, fallback: str) -> bool:
    """Return whether an observation is established at or before ``audit_at``."""
    cutoff = _parse_ts(audit_at)
    if cutoff is None:
        return True
    stamp = _parse_ts(observed_at) or _parse_ts(fallback)
    if stamp is None:
        return True
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp <= cutoff


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
@dataclass
class _ManifestEntry:
    evidence_id: str
    file_path: str
    origin: str
    captured_at: str


def _read_manifest(dataset_dir: Path) -> list[_ManifestEntry]:
    """Read ``evidence_files.csv`` into manifest entries."""
    path = dataset_dir / "evidence_files.csv"
    entries: list[_ManifestEntry] = []
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            entries.append(
                _ManifestEntry(
                    evidence_id=row["file_id"],
                    file_path=row["file_path"],
                    origin=row["origin"],
                    captured_at=row["captured_at"],
                )
            )
    return entries


def _fingerprint(dataset_dir: Path, entries: list[_ManifestEntry]) -> str:
    """Hash the manifest and each file's size+mtime to detect corpus changes."""
    hasher = hashlib.sha256()
    hasher.update(_CACHE_VERSION.encode())
    for entry in sorted(entries, key=lambda e: e.evidence_id):
        p = dataset_dir / entry.file_path
        try:
            st = p.stat()
            sig = f"{entry.evidence_id}:{entry.file_path}:{st.st_size}:{int(st.st_mtime)}"
        except OSError:
            sig = f"{entry.evidence_id}:{entry.file_path}:missing"
        hasher.update(sig.encode())
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# State inference helpers
# ---------------------------------------------------------------------------
def _state_from_identifiers(identifiers: dict[str, str]) -> str:
    """Classify a present record as exposed / redacted / anonymized."""
    has_direct = any(
        k in DIRECT_IDENTIFIER_FIELDS and v not in (None, "")
        for k, v in identifiers.items()
    )
    if has_direct:
        return STATE_EXPOSED
    has_ref = any(
        k in STABLE_REFERENCE_FIELDS and v not in (None, "")
        for k, v in identifiers.items()
    )
    return STATE_REDACTED if has_ref else STATE_ANONYMIZED


def _flatten_record(record: dict) -> dict:
    """Flatten one level of nested identifier holders (e.g. ``document``)."""
    flat: dict[str, object] = {}
    for key, val in record.items():
        if isinstance(val, dict):
            for sub_k, sub_v in val.items():
                flat.setdefault(sub_k, sub_v)
        else:
            flat[key] = val
    return flat


# ---------------------------------------------------------------------------
# Parsers — each returns a list of partially-filled Observation objects.
# ---------------------------------------------------------------------------
def scan_sql_snapshot(path: Path, entry: _ManifestEntry) -> list[Observation]:
    """Load a SQLite snapshot into memory and extract rows as observations."""
    obs: list[Observation] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(text)
        conn.row_factory = sqlite3.Row
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]
        for table in tables:
            if table == "snapshot_scope":
                continue
            cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
            for raw in conn.execute(f'SELECT * FROM "{table}"'):
                row = {c: raw[c] for c in cols}
                if "record_json" in row and row.get("record_json"):
                    try:
                        rec = json.loads(row["record_json"])
                    except (TypeError, json.JSONDecodeError):
                        continue
                    ids = _collect_identifier_values(_flatten_record(rec))
                    obs.append(
                        Observation(
                            evidence_id=entry.evidence_id,
                            origin=entry.origin,
                            system_id=str(row.get("origin_system") or ""),
                            resource_id=str(rec.get("resource_id")
                                             or row.get("resource_id") or ""),
                            data_category="",  # learned later
                            observed_state=STATE_PRESENT,
                            observed_at=str(row.get("updated_at")
                                            or entry.captured_at),
                            identifiers=ids,
                            source_path=entry.file_path,
                            table_or_collection=str(row.get("collection_name") or table),
                        )
                    )
                else:
                    ids = _collect_identifier_values(row)
                    resource_id = str(row.get("resource_id") or "")
                    if not resource_id:
                        continue
                    obs.append(
                        Observation(
                            evidence_id=entry.evidence_id,
                            origin=entry.origin,
                            system_id="",  # learned from prefix
                            resource_id=resource_id,
                            data_category="",
                            observed_state=STATE_PRESENT,
                            observed_at=str(row.get("updated_at")
                                            or row.get("indexed_at")
                                            or entry.captured_at),
                            identifiers=ids,
                            source_path=entry.file_path,
                            table_or_collection=table,
                        )
                    )
    finally:
        conn.close()
    return obs


def _obs_from_flat_record(
    rec: dict, system_id: str, category: str, observed_at: str,
    entry: _ManifestEntry, collection: str, state: str | None = None,
) -> Observation | None:
    """Build an observation from a flat record dict."""
    flat = _flatten_record(rec)
    resource_id = str(flat.get("resource_id") or "")
    if not resource_id:
        return None
    ids = _collect_identifier_values(flat)
    if state is None:
        state = _state_from_identifiers(ids)
    return Observation(
        evidence_id=entry.evidence_id,
        origin=entry.origin,
        system_id=system_id or "",
        resource_id=resource_id,
        data_category=(category or "").upper(),
        observed_state=state,
        observed_at=observed_at or entry.captured_at,
        identifiers=ids,
        source_path=entry.file_path,
        table_or_collection=collection,
    )


def _ledger_observation(
    rec: dict, entry: _ManifestEntry, collection: str, default_system: str = ""
) -> Observation | None:
    """Build an observation from a uniform ledger row (system/record_type/result).

    The subject identifier may be under ``subject_reference``, ``lookup_value``,
    or ``subject`` and may be an email or an internal reference.
    """
    resource_id = str(rec.get("resource_id") or "")
    if not resource_id:
        return None
    state = (STATE_PRESENT if str(rec.get("result")).upper() == "FOUND"
             else STATE_ABSENT)
    id_src = (rec.get("subject_reference") or rec.get("lookup_value")
              or rec.get("subject"))
    ids = _collect_identifier_values({"subject_reference": id_src}) if id_src else {}
    return Observation(
        evidence_id=entry.evidence_id, origin=entry.origin,
        system_id=str(rec.get("system") or default_system or ""),
        resource_id=resource_id,
        data_category=str(rec.get("record_type") or "").upper(),
        observed_state=state,
        observed_at=str(rec.get("recorded_at") or entry.captured_at),
        identifiers=ids, source_path=entry.file_path,
        table_or_collection=collection,
    )


def _is_ledger_row(rec: object) -> bool:
    """Return whether a record is a uniform ledger row."""
    return isinstance(rec, dict) and "record_type" in rec and "result" in rec


def scan_json(path: Path, entry: _ManifestEntry) -> list[Observation]:
    """Parse a JSON evidence file (snapshot / export / ledger) structurally."""
    obs: list[Observation] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return obs
    if not isinstance(data, dict):
        return obs

    # Family: multi-store snapshot bundle. A snapshot may hold flat records or
    # an embedded ledger (operational_record_history) whose rows carry their own
    # system / record_type / result.
    if isinstance(data.get("snapshots"), list):
        for snap in data["snapshots"]:
            system_id = str(snap.get("data_store") or "")
            collection = str(snap.get("collection") or "")
            captured = str(snap.get("captured_at") or entry.captured_at)
            for rec in snap.get("records", []):
                if _is_ledger_row(rec):
                    o = _ledger_observation(rec, entry, collection,
                                            default_system=system_id)
                else:
                    o = _obs_from_flat_record(
                        rec, system_id, "", captured, entry, collection
                    )
                if o:
                    obs.append(o)
        return obs

    # Family: per-service readback probes.
    if isinstance(data.get("service_exports"), dict):
        for system_id, block in data["service_exports"].items():
            if not isinstance(block, dict):
                continue
            for collection, rows in block.items():
                for row in rows or []:
                    obs.extend(
                        _probe_observations(row, system_id, collection, entry)
                    )
        return obs

    # Family: uniform record-lookup ledger.
    records = data.get("records")
    if isinstance(records, list) and records and _is_ledger_row(records[0]):
        collection = str(data.get("collection") or "record_lookup")
        for rec in records:
            o = _ledger_observation(rec, entry, collection)
            if o:
                obs.append(o)
        return obs

    # Family: single-collection record list (export jobs, analytics reports).
    if isinstance(records, list):
        collection = str(data.get("collection") or "")
        for rec in records:
            if isinstance(rec, dict):
                o = _obs_from_flat_record(rec, "", "", "", entry, collection)
                if o:
                    obs.append(o)
        return obs

    return obs


def _probe_observations(
    row: dict, system_id: str, collection: str, entry: _ManifestEntry
) -> list[Observation]:
    """Interpret one service_resource_export probe row into observation(s)."""
    observed_at = str(row.get("observed_at") or entry.captured_at)

    # search index query: records live under hits.documents.
    hits = row.get("hits")
    if isinstance(hits, dict):
        out: list[Observation] = []
        for doc in hits.get("documents", []) or []:
            o = _obs_from_flat_record(
                doc, system_id, "", observed_at, entry, collection,
                state=STATE_PRESENT,
            )
            if o:
                out.append(o)
        return out

    resource_id = str(row.get("resource_id") or "")
    if not resource_id:
        return []

    # account profile lookup: status_code 200/404; profile may be nested.
    if "status_code" in row:
        present = int(row.get("status_code") or 0) == 200
        rec = dict(row)
        if isinstance(row.get("profile"), dict):
            rec.update(row["profile"])
        ids = _collect_identifier_values(rec)
        state = _state_from_identifiers(ids) if present else STATE_ABSENT
        return [Observation(
            evidence_id=entry.evidence_id, origin=entry.origin,
            system_id=system_id, resource_id=resource_id, data_category="",
            observed_state=state, observed_at=observed_at, identifiers=ids,
            source_path=entry.file_path, table_or_collection=collection,
        )]

    # connector: enabled -> ACTIVE/DISABLED.
    if "enabled" in row:
        state = STATE_ACTIVE if row.get("enabled") else STATE_DISABLED
        ids = _collect_identifier_values(row)
        return [Observation(
            evidence_id=entry.evidence_id, origin=entry.origin,
            system_id=system_id, resource_id=resource_id, data_category="",
            observed_state=state, observed_at=observed_at, identifiers=ids,
            source_path=entry.file_path, table_or_collection=collection,
        )]

    # backup: restore_allowed -> ACTIVE/BLOCKED.
    if "restore_allowed" in row:
        state = STATE_ACTIVE if row.get("restore_allowed") else STATE_BLOCKED
        ids = _collect_identifier_values(row)
        return [Observation(
            evidence_id=entry.evidence_id, origin=entry.origin,
            system_id=system_id, resource_id=resource_id, data_category="",
            observed_state=state, observed_at=observed_at, identifiers=ids,
            source_path=entry.file_path, table_or_collection=collection,
        )]

    # generic present record (analytics profile, support ticket, export).
    o = _obs_from_flat_record(row, system_id, "", observed_at, entry, collection,
                              state=None)
    return [o] if o else []


# token pattern: key=value or key="quoted value"
_KV_RE = re.compile(r'(\w+)=("([^"]*)"|\S+)')


def _tokenize_kv(text: str) -> dict[str, str]:
    """Extract ``key=value`` / ``key="value"`` pairs from a log fragment."""
    out: dict[str, str] = {}
    for m in _KV_RE.finditer(text):
        key = m.group(1)
        val = m.group(3) if m.group(3) is not None else m.group(2)
        out[key] = val
    return out


def _tokens_from_log_line(line: str) -> tuple[str, dict[str, str]]:
    """Return (timestamp, token dict) for one log line across wrappers."""
    line = line.rstrip("\n")
    if not line.strip():
        return "", {}
    ts, _, rest = line.partition(" ")

    if rest.startswith("{"):  # structured JSON payload
        try:
            payload = json.loads(rest)
            return ts, {str(k): str(v) for k, v in payload.items()}
        except json.JSONDecodeError:
            return ts, {}

    if 'message="' in rest:  # cloud runtime export: escaped kv inside message
        tokens = _tokenize_kv(rest)
        msg = tokens.get("message", "")
        inner = _tokenize_kv(msg.replace('\\"', '"'))
        tokens.pop("message", None)
        tokens.update(inner)
        if "function" in tokens and "service" not in tokens:
            tokens["service"] = tokens["function"]
        return ts, tokens

    if " | " in rest:  # operations_stream: ts | LEVEL | service | id | event | kv
        parts = [p.strip() for p in rest.split("|") if p.strip()]
        tokens = _tokenize_kv(parts[-1]) if parts else {}
        # After dropping empties: parts[0]=LEVEL, parts[1]=service.
        if len(parts) >= 2 and "service" not in tokens:
            tokens["service"] = parts[1]
        return ts, tokens

    if rest.startswith("["):  # application_trace: [LEVEL] [service] [trace] event: kv
        brackets = re.findall(r"\[([^\]]*)\]", rest)
        tokens = _tokenize_kv(rest.split(":", 1)[1]) if ":" in rest else _tokenize_kv(rest)
        if len(brackets) >= 2 and "service" not in tokens:
            tokens["service"] = brackets[1]
        return ts, tokens

    if rest.startswith("<"):  # syslog: <pri>1 node service trace - - kv
        head, _, kv = rest.partition("- -")
        tokens = _tokenize_kv(kv if kv else rest)
        fields = head.split()
        # fields: <pri>1 node service trace
        if len(fields) >= 3 and "service" not in tokens:
            tokens["service"] = fields[2]
        return ts, tokens

    return ts, _tokenize_kv(rest)  # plain kv (resource_lookup_trace, service_events)


def scan_log(path: Path, entry: _ManifestEntry) -> list[Observation]:
    """Parse a log file: ledger lines per-line, trace lines grouped by trace."""
    obs: list[Observation] = []
    groups: dict[str, dict[str, str]] = defaultdict(dict)
    group_ts: dict[str, str] = {}

    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ts, tokens = _tokens_from_log_line(line)
            if not tokens:
                continue

            # Ledger-style line: self-contained record lookup.
            if "record_type" in tokens and "result" in tokens and tokens.get("resource_id"):
                state = (STATE_PRESENT
                         if str(tokens.get("result")).upper() == "FOUND"
                         else STATE_ABSENT)
                ids = _collect_identifier_values(
                    {"subject_reference": tokens.get("subject_reference")}
                )
                obs.append(Observation(
                    evidence_id=entry.evidence_id, origin=entry.origin,
                    system_id=str(tokens.get("system") or tokens.get("service") or ""),
                    resource_id=str(tokens["resource_id"]),
                    data_category=str(tokens.get("record_type") or "").upper(),
                    observed_state=state, observed_at=ts or entry.captured_at,
                    identifiers=ids, source_path=entry.file_path,
                    table_or_collection="record_lookup",
                ))
                continue

            # Trace-style line: accumulate by trace_id (fallback resource_id).
            key = tokens.get("trace_id") or tokens.get("resource_id")
            if not key:
                continue
            merged = groups[key]
            for k, v in tokens.items():
                if v not in (None, "", "null"):
                    merged[k] = v
            group_ts.setdefault(key, ts)
            if ts:
                group_ts[key] = ts

    for key, tokens in groups.items():
        resource_id = tokens.get("resource_id")
        if not resource_id:
            continue
        state = _state_from_log_tokens(tokens)
        if state == STATE_UNKNOWN:
            continue
        ids = _collect_identifier_values({
            k: tokens[k] for k in tokens
            if k in _IDENTIFIER_FIELD_NAMES
        })
        # lookup_key / match_key / correlation_key carry the subject identifier.
        for probe_key in ("lookup_key", "match_key", "correlation_key", "query"):
            if tokens.get(probe_key):
                ids.setdefault(probe_key, tokens[probe_key])
        obs.append(Observation(
            evidence_id=entry.evidence_id, origin=entry.origin,
            system_id=str(tokens.get("service") or tokens.get("system")
                          or tokens.get("logger") or ""),
            resource_id=str(resource_id),
            data_category="",  # learned later
            observed_state=state,
            observed_at=group_ts.get(key) or entry.captured_at,
            identifiers=ids, source_path=entry.file_path,
            table_or_collection="trace",
        ))
    return obs


def _state_from_log_tokens(tokens: dict[str, str]) -> str:
    """Infer observed state from a trace group's accumulated tokens."""
    if "result" in tokens and str(tokens["result"]).upper() in {"FOUND", "NOT_FOUND"}:
        return STATE_PRESENT if tokens["result"].upper() == "FOUND" else STATE_ABSENT
    if "http_status" in tokens:
        return STATE_PRESENT if str(tokens["http_status"]) == "200" else STATE_ABSENT
    if "enabled" in tokens:
        return STATE_ACTIVE if str(tokens["enabled"]).lower() == "true" else STATE_DISABLED
    if "restore_allowed" in tokens:
        return (STATE_ACTIVE if str(tokens["restore_allowed"]).lower() == "true"
                else STATE_BLOCKED)
    if "marker_found" in tokens:
        return STATE_ABSENT if str(tokens["marker_found"]).lower() == "true" else STATE_PRESENT
    if str(tokens.get("result", "")).lower() == "hit" or tokens.get("total_hits"):
        return STATE_PRESENT
    if "rows" in tokens:
        try:
            return STATE_PRESENT if int(tokens["rows"]) > 0 else STATE_ABSENT
        except ValueError:
            return STATE_UNKNOWN
    return STATE_UNKNOWN


def scan_handover_text(path: Path, entry: _ManifestEntry) -> list[Observation]:
    """Parse a pipe-delimited handover list into observations."""
    obs: list[Observation] = []
    state_map = {
        "NOT_FOUND": STATE_ABSENT, "FOUND": STATE_PRESENT,
        "IDENTIFIABLE": STATE_EXPOSED, "ANONYMIZED": STATE_ANONYMIZED,
        "REDACTED": STATE_REDACTED, "ACTIVE": STATE_ACTIVE,
        "DISABLED": STATE_DISABLED, "BLOCKED": STATE_BLOCKED,
        "PRESENT": STATE_PRESENT, "ABSENT": STATE_ABSENT,
    }
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.lstrip("-").split("|")]
        if len(parts) < 6:
            continue
        ts, system_id, resource_id, category, raw_state, identifier = parts[:6]
        if not resource_id or not system_id:
            continue
        ids = _collect_identifier_values({"subject_reference": identifier}) \
            if identifier and "no direct identifier" not in identifier.lower() else {}
        obs.append(Observation(
            evidence_id=entry.evidence_id, origin=entry.origin,
            system_id=system_id, resource_id=resource_id,
            data_category=category.upper(),
            observed_state=state_map.get(raw_state.upper(), STATE_UNKNOWN),
            observed_at=ts or entry.captured_at,
            identifiers=ids, source_path=entry.file_path,
            table_or_collection="handover",
        ))
    return obs


def scan_media_file(path: Path, entry: _ManifestEntry) -> list[Observation]:
    """Hook for PDF/image evidence — delegated to vision.py later.

    Returns an empty list for now; :mod:`ghostaudit.vision` will populate
    observations from documents and screenshots without changing this contract.
    """
    return []


def _scan_file(path: Path, entry: _ManifestEntry) -> list[Observation]:
    """Dispatch one evidence file to its parser by suffix / shape."""
    suffix = path.suffix.lower()
    if suffix == ".sql":
        return scan_sql_snapshot(path, entry)
    if suffix == ".json":
        return scan_json(path, entry)
    if suffix == ".txt":
        return scan_handover_text(path, entry)
    if suffix == ".log":
        return scan_log(path, entry)
    if suffix in MEDIA_SUFFIXES:
        return scan_media_file(path, entry)
    return []


# ---------------------------------------------------------------------------
# Category / system learning (data-derived, from explicitly labeled evidence)
# ---------------------------------------------------------------------------
def _resource_prefix(resource_id: str) -> str:
    """Return the non-numeric prefix of a resource id (``account_005`` -> ``account``)."""
    m = re.match(r"^(.*?)_\d+$", resource_id)
    return m.group(1) if m else resource_id


def _learn_maps(
    observations: list[Observation],
) -> tuple[dict[str, str], dict[str, str]]:
    """Learn prefix->category and prefix->system from labeled observations."""
    cat_votes: dict[str, Counter] = defaultdict(Counter)
    sys_votes: dict[str, Counter] = defaultdict(Counter)
    for o in observations:
        prefix = _resource_prefix(o.resource_id)
        if o.data_category:
            cat_votes[prefix][o.data_category] += 1
        if o.system_id:
            sys_votes[prefix][o.system_id] += 1
    prefix_cat = {p: c.most_common(1)[0][0] for p, c in cat_votes.items() if c}
    prefix_sys = {p: c.most_common(1)[0][0] for p, c in sys_votes.items() if c}
    return prefix_cat, prefix_sys


def _apply_learned_maps(
    observations: list[Observation],
    prefix_cat: dict[str, str],
    prefix_sys: dict[str, str],
) -> None:
    """Fill missing category/system on observations from the learned maps."""
    for o in observations:
        prefix = _resource_prefix(o.resource_id)
        if not o.data_category:
            o.data_category = prefix_cat.get(prefix, "")
        if not o.system_id:
            o.system_id = prefix_sys.get(prefix, "")


# ---------------------------------------------------------------------------
# Index build / cache / query
# ---------------------------------------------------------------------------
def build_evidence_index(
    dataset_dir: str | Path,
    cache_path: str | Path | None = None,
    rebuild: bool = False,
) -> EvidenceIndex:
    """Build (or load from cache) the shared evidence index for the corpus."""
    dataset_dir = Path(dataset_dir)
    entries = _read_manifest(dataset_dir)
    fingerprint = _fingerprint(dataset_dir, entries)

    cache = Path(cache_path) if cache_path else dataset_dir.parent / ".cache" / "evidence_index.json"
    if not rebuild and cache.exists():
        cached = _load_index(cache)
        if cached and cached.fingerprint == fingerprint:
            return cached

    observations: list[Observation] = []
    for entry in entries:
        path = dataset_dir / entry.file_path
        if not path.exists():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES | MEDIA_SUFFIXES:
            continue
        observations.extend(_scan_file(path, entry))

    prefix_cat, prefix_sys = _learn_maps(observations)
    _apply_learned_maps(observations, prefix_cat, prefix_sys)

    token_index: dict[str, list[int]] = defaultdict(list)
    for idx, o in enumerate(observations):
        for token in _match_tokens_for_record(o.identifiers):
            token_index[token].append(idx)

    index = EvidenceIndex(
        fingerprint=fingerprint,
        observations=observations,
        token_index=dict(token_index),
    )
    _save_index(cache, index)
    return index


def _save_index(cache_path: Path, index: EvidenceIndex) -> None:
    """Serialize the index to JSON on disk."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fingerprint": index.fingerprint,
        "observations": [asdict(o) for o in index.observations],
        "token_index": index.token_index,
    }
    tmp = cache_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    tmp.replace(cache_path)


def _load_index(cache_path: Path) -> EvidenceIndex | None:
    """Load a cached index from disk, or ``None`` if unreadable."""
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    observations = [Observation(**o) for o in payload.get("observations", [])]
    return EvidenceIndex(
        fingerprint=payload.get("fingerprint", ""),
        observations=observations,
        token_index={k: list(v) for k, v in payload.get("token_index", {}).items()},
    )


def discover_by_identifiers(
    index: EvidenceIndex,
    match_tokens: set[str],
    audit_at: str,
) -> list[DiscoveredRecord]:
    """Return every observation matching any token, established by ``audit_at``."""
    seen: dict[int, list[str]] = defaultdict(list)
    for token in match_tokens:
        for idx in index.token_index.get(token, ()):
            seen[idx].append(token)

    results: list[DiscoveredRecord] = []
    for idx, tokens in seen.items():
        o = index.observations[idx]
        if not _at_or_before(o.observed_at, audit_at, o.observed_at):
            continue
        results.append(DiscoveredRecord(
            system_id=o.system_id, resource_id=o.resource_id,
            data_category=o.data_category, observed_state=o.observed_state,
            observed_at=o.observed_at, evidence_id=o.evidence_id,
            identifiers=dict(o.identifiers), matched_on=sorted(set(tokens)),
            table_or_collection=o.table_or_collection,
        ))
    results.sort(key=lambda r: (r.system_id, r.resource_id, r.observed_at))
    return results


def discover_records(
    identity, dataset, audit_at: str, index: EvidenceIndex | None = None
) -> list[DiscoveredRecord]:
    """Return subject-matching records for one request, as of ``audit_at``.

    ``identity`` must expose ``match_keys() -> set[str]`` (see
    :mod:`ghostaudit.identity`). ``dataset`` supplies ``dataset_dir`` when the
    shared ``index`` is not passed in; passing the prebuilt ``index`` is the
    intended path so the corpus is scanned once for all 518 cases.
    """
    if index is None:
        index = build_evidence_index(dataset.dataset_dir)
    return discover_by_identifiers(index, set(identity.match_keys()), audit_at)
