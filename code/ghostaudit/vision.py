"""Multimodal extraction: pull personal identifiers from PDFs and images.

Responsibility
--------------
Some evidence is non-textual: PDF documents (invoices, handover notes,
retention/legal registers) and application screenshots (admin consoles,
tombstone registries, export dashboards). This module extracts the personal
identifiers they contain — email, phone, name, user_id, email_hash — each tied
to the ``file_id`` it came from, using an OpenAI vision/language model at
temperature 0 with strict JSON output.

Hard requirements honored here:
- Document content is treated as UNTRUSTED data; the prompt forbids obeying any
  instruction embedded in a document (see ``prompts/vision_v1.txt``).
- Results are cached to disk keyed by ``file_id`` (plus content hash and prompt
  version), so reruns make zero new model calls and output is deterministic.
- Every extracted identifier is plausibility-checked; values that fail are
  returned separately as low-confidence rather than fed downstream.
- Every model call is logged (tokens + cost estimate) for the usage report.
- Verified identifiers are converted to :class:`ghostaudit.discovery.Observation`
  and merged into the same shared evidence index.

A deterministic local fallback (``backend="local"``) extracts identifiers from
PDF text with pypdf when no model is available; it makes no network calls and
cannot read images. This module is the only place vision I/O happens.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import discovery
from .loader import Dataset, EvidenceFile

PROMPT_VERSION = "vision_v1"
_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "vision_v1.txt"

# Approximate USD pricing per 1M tokens, for the usage report (override in config).
_PRICING = {
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
}

_LOW_CONFIDENCE_THRESHOLD = 0.5

# Plausibility validators per identifier type.
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_HASH = re.compile(r"^[0-9a-f]{64}$")
_RE_USER_ID = re.compile(r"^[a-z][a-z_]*_\d+$", re.IGNORECASE)
_RE_NAME = re.compile(r"^[^\d@]{2,}$")


@dataclass
class ExtractedIdentifier:
    """One identifier the model reported, with verification outcome."""

    type: str
    value: str
    confidence: float
    verified: bool = False
    reason: str = ""
    location: str = ""


@dataclass
class MediaExtraction:
    """Everything recovered from one media file."""

    file_id: str
    path: str
    backend: str = ""
    model: str = ""
    cached: bool = False
    identifiers: list[ExtractedIdentifier] = field(default_factory=list)
    low_confidence: list[ExtractedIdentifier] = field(default_factory=list)
    error: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class VisionConfig:
    """Model, backend, and I/O settings (no secrets)."""

    model: str = "gpt-4o-mini"
    backend: str = "openai"            # "openai" or "local"
    api_key_env: str = "OPENAI_API_KEY"
    base_url_env: str = "OPENAI_BASE_URL"
    temperature: float = 0.0
    max_tokens: int = 1024
    cache_dir: Path = Path(".cache/vision")
    usage_log_path: Path = Path(".cache/usage_vision.jsonl")
    allow_local_fallback: bool = False  # fall back to local PDF parsing on error


# ---------------------------------------------------------------------------
# Plausibility verification
# ---------------------------------------------------------------------------
def verify_identifier(ident: ExtractedIdentifier) -> tuple[bool, str]:
    """Check an extracted identifier is well-formed for its claimed type."""
    value = (ident.value or "").strip()
    if not value:
        return False, "empty value"
    kind = ident.type.lower()
    if kind == "email":
        return (True, "") if _RE_EMAIL.match(value) else (False, "not an email")
    if kind == "email_hash":
        return (True, "") if _RE_HASH.match(value.lower()) else (False, "not a 64-hex hash")
    if kind == "user_id":
        return (True, "") if _RE_USER_ID.match(value) else (False, "not a user reference")
    if kind == "phone":
        digits = re.sub(r"\D", "", value)
        if value.lstrip().startswith("+") and 8 <= len(digits) <= 15:
            return True, ""
        return False, "not an international phone (+<8-15 digits>)"
    if kind == "name":
        # Names are inherently weak identifiers; accept shape but keep low trust.
        return (bool(_RE_NAME.match(value)), "" if _RE_NAME.match(value) else "implausible name")
    return False, f"unknown type {ident.type!r}"


def _partition(idents: list[ExtractedIdentifier]) -> tuple[list, list]:
    """Split identifiers into (verified, low-confidence) lists."""
    verified: list[ExtractedIdentifier] = []
    low: list[ExtractedIdentifier] = []
    for ident in idents:
        ok, reason = verify_identifier(ident)
        ident.verified = ok
        ident.reason = reason
        # Names are always treated as low-confidence (never used for matching).
        if ok and ident.type.lower() != "name" and ident.confidence >= _LOW_CONFIDENCE_THRESHOLD:
            verified.append(ident)
        else:
            if ok and not ident.reason:
                ident.reason = ("name: low-trust identifier"
                                if ident.type.lower() == "name"
                                else "below confidence threshold")
            low.append(ident)
    return verified, low


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------
class VisionExtractor:
    """Extracts identifiers from media files with caching and usage logging."""

    def __init__(self, config: VisionConfig | None = None) -> None:
        self.config = config or VisionConfig()
        self._prompt = _PROMPT_PATH.read_text(encoding="utf-8")
        self._client = None  # lazily created OpenAI client

    # -- public API --------------------------------------------------------
    def extract_file(self, evidence: EvidenceFile, dataset_dir: str | Path) -> MediaExtraction:
        """Extract identifiers from one media file, using the cache if valid."""
        path = Path(dataset_dir) / evidence.file_path
        content_hash = _file_hash(path)
        cached = self._load_cache(evidence.file_id, content_hash)
        if cached is not None:
            cached.cached = True
            return cached

        if self.config.backend == "local":
            extraction = self._extract_local(evidence, path)
        else:
            try:
                extraction = self._extract_openai(evidence, path)
            except Exception as exc:  # noqa: BLE001 — surface any backend failure
                if self.config.allow_local_fallback:
                    extraction = self._extract_local(evidence, path)
                    extraction.error = f"openai failed, used local fallback: {exc}"
                else:
                    extraction = MediaExtraction(
                        file_id=evidence.file_id, path=str(path),
                        backend=self.config.backend, model=self.config.model,
                        error=f"{type(exc).__name__}: {exc}",
                    )

        if not extraction.error:  # never cache a failed extraction
            self._save_cache(evidence.file_id, content_hash, extraction)
        return extraction

    def extract_all(self, dataset: Dataset) -> list[MediaExtraction]:
        """Extract identifiers from every media file in the dataset."""
        return [
            self.extract_file(ev, dataset.dataset_dir)
            for ev in dataset.media_files()
        ]

    # -- OpenAI backend ----------------------------------------------------
    def _get_client(self):
        """Create the OpenAI client lazily (key/base url from the environment)."""
        if self._client is None:
            import os
            from openai import OpenAI  # imported lazily so the dep is optional
            api_key = os.environ.get(self.config.api_key_env)
            if not api_key:
                raise RuntimeError(
                    f"{self.config.api_key_env} is not set; cannot call OpenAI")
            base_url = os.environ.get(self.config.base_url_env) or None
            self._client = OpenAI(api_key=api_key, base_url=base_url)
        return self._client

    def _extract_openai(self, evidence: EvidenceFile, path: Path) -> MediaExtraction:
        """Call the OpenAI model (image for screenshots, text for PDFs)."""
        client = self._get_client()
        if evidence.suffix == ".pdf":
            user_content = [
                {"type": "text",
                 "text": "Document text follows between <doc> tags. "
                         "Extract identifiers per the system instructions.\n"
                         f"<doc>\n{_pdf_text(path)}\n</doc>"},
            ]
        else:
            data_url = _image_data_url(path)
            user_content = [
                {"type": "text", "text": "Extract identifiers from this image "
                                         "per the system instructions."},
                {"type": "image_url", "image_url": {"url": data_url}},
            ]

        t0 = time.time()
        resp = client.chat.completions.create(
            model=self.config.model,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": self._prompt},
                {"role": "user", "content": user_content},
            ],
        )
        latency = time.time() - t0
        content = resp.choices[0].message.content or "{}"
        usage = resp.usage
        extraction = self._build_extraction(
            evidence, path, "openai", self.config.model, content,
            getattr(usage, "prompt_tokens", 0), getattr(usage, "completion_tokens", 0),
        )
        self._log_usage(evidence.file_id, extraction, latency)
        return extraction

    # -- local fallback backend -------------------------------------------
    def _extract_local(self, evidence: EvidenceFile, path: Path) -> MediaExtraction:
        """Deterministically extract identifiers from PDF text (no network)."""
        if evidence.suffix != ".pdf":
            return MediaExtraction(
                file_id=evidence.file_id, path=str(path), backend="local",
                error="image requires a VLM backend (no local OCR)",
            )
        idents = _regex_identifiers(_pdf_text(path))
        verified, low = _partition(idents)
        extraction = MediaExtraction(
            file_id=evidence.file_id, path=str(path), backend="local",
            model="regex", identifiers=verified, low_confidence=low,
        )
        self._log_usage(evidence.file_id, extraction, 0.0)
        return extraction

    # -- parsing / building ------------------------------------------------
    def _build_extraction(
        self, evidence: EvidenceFile, path: Path, backend: str, model: str,
        content: str, prompt_tokens: int, completion_tokens: int,
    ) -> MediaExtraction:
        """Parse strict-JSON model output into a verified extraction."""
        idents: list[ExtractedIdentifier] = []
        try:
            payload = json.loads(content)
            for item in payload.get("identifiers", []):
                idents.append(ExtractedIdentifier(
                    type=str(item.get("type", "")).lower(),
                    value=str(item.get("value", "")),
                    confidence=float(item.get("confidence", 0.0)),
                    location=str(item.get("location", "")),
                ))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            return MediaExtraction(
                file_id=evidence.file_id, path=str(path), backend=backend,
                model=model, error=f"bad JSON from model: {exc}",
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            )
        verified, low = _partition(idents)
        return MediaExtraction(
            file_id=evidence.file_id, path=str(path), backend=backend, model=model,
            identifiers=verified, low_confidence=low,
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
        )

    # -- cache -------------------------------------------------------------
    def _cache_file(self, file_id: str) -> Path:
        return Path(self.config.cache_dir) / f"{file_id}.json"

    def _load_cache(self, file_id: str, content_hash: str) -> MediaExtraction | None:
        path = self._cache_file(file_id)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if payload.get("content_hash") != content_hash \
                or payload.get("prompt_version") != PROMPT_VERSION:
            return None
        return _extraction_from_dict(payload["extraction"])

    def _save_cache(self, file_id: str, content_hash: str, extraction: MediaExtraction) -> None:
        path = self._cache_file(file_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "content_hash": content_hash,
            "prompt_version": PROMPT_VERSION,
            "extraction": asdict(extraction),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # -- usage logging -----------------------------------------------------
    def _log_usage(self, file_id: str, extraction: MediaExtraction, latency: float) -> None:
        in_rate, out_rate = _PRICING.get(self.config.model, (0.0, 0.0))
        cost = (extraction.prompt_tokens / 1e6) * in_rate + \
               (extraction.completion_tokens / 1e6) * out_rate
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "file_id": file_id,
            "backend": extraction.backend,
            "model": extraction.model,
            "prompt_tokens": extraction.prompt_tokens,
            "completion_tokens": extraction.completion_tokens,
            "total_tokens": extraction.prompt_tokens + extraction.completion_tokens,
            "estimated_cost_usd": round(cost, 6),
            "latency_s": round(latency, 3),
            "error": extraction.error,
        }
        path = Path(self.config.usage_log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Index integration
# ---------------------------------------------------------------------------
def extraction_to_observations(
    extraction: MediaExtraction, evidence: EvidenceFile
) -> list[discovery.Observation]:
    """Convert verified identifiers from one file into index observations."""
    if not extraction.identifiers:
        return []
    ids: dict[str, str] = {}
    for ident in extraction.identifiers:
        key = {"email": "email", "phone": "phone", "name": "name",
               "user_id": "user_id", "email_hash": "email_hash"}.get(ident.type)
        if key:
            ids[key] = ident.value
    resource_id = ids.get("user_id") or extraction.file_id
    return [discovery.Observation(
        evidence_id=extraction.file_id,
        origin=evidence.origin,
        system_id=evidence.origin,  # media is attributed to its capture origin
        resource_id=resource_id,
        data_category="",  # unknown from a document alone
        observed_state=discovery.STATE_EXPOSED,
        observed_at=evidence.captured_at,
        identifiers=ids,
        source_path=evidence.file_path,
        table_or_collection="media",
    )]


def integrate_media(
    index: discovery.EvidenceIndex,
    extractions: list[MediaExtraction],
    dataset: Dataset,
) -> discovery.EvidenceIndex:
    """Merge verified media extractions into the shared evidence index."""
    by_id = dataset.evidence_by_id()
    new_obs: list[discovery.Observation] = []
    for extraction in extractions:
        evidence = by_id.get(extraction.file_id)
        if evidence is not None:
            new_obs.extend(extraction_to_observations(extraction, evidence))
    return discovery.add_observations(index, new_obs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _file_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "missing"


def _pdf_text(path: Path) -> str:
    """Extract text from a PDF with pypdf (empty string on failure)."""
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:  # noqa: BLE001
        return ""


def _image_data_url(path: Path) -> str:
    """Encode an image file as a base64 data URL for the vision API."""
    mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg"}.get(
        path.suffix.lower().lstrip("."), "image/png")
    data = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{data}"


_RE_FIND = {
    "email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "email_hash": re.compile(r"\b[0-9a-f]{64}\b"),
    "user_id": re.compile(r"\buser_\d+\b"),
    "phone": re.compile(r"\+\d[\d\s().\-]{6,}\d"),
}


def _regex_identifiers(text: str) -> list[ExtractedIdentifier]:
    """Deterministically find identifiers in text (local fallback)."""
    found: list[ExtractedIdentifier] = []
    seen: set[tuple[str, str]] = set()
    for kind, pattern in _RE_FIND.items():
        for match in pattern.findall(text):
            value = match.strip()
            key = (kind, value.lower())
            if key in seen:
                continue
            seen.add(key)
            found.append(ExtractedIdentifier(
                type=kind, value=value, confidence=0.9, location="pdf_text"))
    return found


def _extraction_from_dict(d: dict) -> MediaExtraction:
    """Rebuild a MediaExtraction (and its identifiers) from cached JSON."""
    def mk(items):
        return [ExtractedIdentifier(**it) for it in items]
    return MediaExtraction(
        file_id=d["file_id"], path=d["path"], backend=d.get("backend", ""),
        model=d.get("model", ""), cached=d.get("cached", False),
        identifiers=mk(d.get("identifiers", [])),
        low_confidence=mk(d.get("low_confidence", [])),
        error=d.get("error", ""),
        prompt_tokens=d.get("prompt_tokens", 0),
        completion_tokens=d.get("completion_tokens", 0),
    )


# Back-compat helpers referenced by the module scaffold.
def extract_identifiers_from_media(path, llm_client=None):  # noqa: D401, ANN001
    """Deprecated shim; use :class:`VisionExtractor`."""
    raise NotImplementedError("use VisionExtractor.extract_file")
