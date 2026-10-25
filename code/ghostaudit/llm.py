"""Model access: narrow, structured LLM/VLM calls for messy inputs only.

Responsibility
--------------
Wrap model calls behind a small, deterministic-as-possible interface used only
where rules cannot decide: classifying whether multilingual ``request_text``
authorizes deletion, and reading facts out of images/PDFs. All calls request
structured (JSON) output against an explicit schema so downstream code stays
deterministic.

Credentials are read from environment variables only — never hardcoded or
logged. This module performs no auditing logic; it is an I/O boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IntentResult:
    """Structured classification of a request's intent."""

    authorizes_deletion: bool
    action_type: str
    confidence: float
    rationale: str = ""


@dataclass
class LLMConfig:
    """Model selection and call settings (no secrets)."""

    model: str = "claude-opus-4-8"
    vision_model: str = "claude-opus-4-8"
    api_key_env: str = "ANTHROPIC_API_KEY"
    max_tokens: int = 1024
    temperature: float = 0.0
    extra: dict[str, object] = field(default_factory=dict)


class LLMClient:
    """Thin client for structured text and vision model calls."""

    def __init__(self, config: LLMConfig) -> None:
        raise NotImplementedError

    def classify_deletion_intent(self, request_text: str) -> IntentResult:
        """Classify whether request text authorizes deletion (any language)."""
        raise NotImplementedError

    def extract_structured(
        self,
        prompt: str,
        image_path: str | None = None,
        schema: dict | None = None,
    ) -> dict:
        """Return structured JSON for a text or image prompt against a schema."""
        raise NotImplementedError


def load_llm_client(config: LLMConfig | None = None) -> LLMClient:
    """Construct an :class:`LLMClient`, reading the API key from the env."""
    raise NotImplementedError
