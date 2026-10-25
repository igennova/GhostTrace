"""Multimodal extraction: pull identifiers and facts from PDFs and images.

Responsibility
--------------
Some evidence is non-textual: PDF registers (legal holds, retention windows)
and application screenshots (admin consoles, tombstone registries, export
dashboards). This module extracts the identifiers and structured facts those
artifacts contain — subject references, resource ids, states, retention dates —
so :mod:`ghostaudit.discovery` and :mod:`ghostaudit.retention` can use them.

PDF text is extracted directly where possible; images (and scanned PDFs) are
read via a vision model through :mod:`ghostaudit.llm`. This module returns
extracted content only; it does not match it to a subject or apply policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .llm import LLMClient


@dataclass
class MediaExtraction:
    """Text and structured facts recovered from one media file."""

    path: str
    text: str = ""
    identifiers: dict[str, str] = field(default_factory=dict)
    structured: dict[str, object] = field(default_factory=dict)


def extract_identifiers_from_media(
    path: str, llm_client: LLMClient | None = None
) -> MediaExtraction:
    """Dispatch to the PDF or image extractor by file type and return facts."""
    raise NotImplementedError


def extract_from_pdf(path: str, llm_client: LLMClient | None = None) -> MediaExtraction:
    """Extract text and structured facts from a PDF document."""
    raise NotImplementedError


def extract_from_image(path: str, llm_client: LLMClient) -> MediaExtraction:
    """Extract structured facts from an application screenshot via a VLM."""
    raise NotImplementedError
