"""Zero-dependency ``.env`` loading.

Loads ``KEY=VALUE`` pairs from a ``.env`` file into ``os.environ`` so secrets
like ``OPENAI_API_KEY`` can live in a repo-root ``.env`` without being exported
by hand. Existing environment variables are never overwritten, nothing is
logged, and no third-party dependency is required.
"""

from __future__ import annotations

import os
from pathlib import Path

_loaded = False


def _parse_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    key, _, value = line.partition("=")
    key = key.strip()
    if key.startswith("export "):
        key = key[len("export "):].strip()
    value = value.strip().strip('"').strip("'")
    return (key, value) if key else None


def find_dotenv(start: str | Path | None = None) -> Path | None:
    """Search the cwd and this file's repo root (and parents) for a ``.env``."""
    candidates: list[Path] = []
    if start is not None:
        candidates.append(Path(start))
    candidates.append(Path.cwd())
    candidates.append(Path(__file__).resolve().parent.parent.parent)  # repo root
    for base in candidates:
        for directory in [base, *base.parents]:
            dotenv = directory / ".env"
            if dotenv.is_file():
                return dotenv
    return None


def load_dotenv(path: str | Path | None = None, override: bool = False) -> bool:
    """Load a ``.env`` into ``os.environ`` once. Returns whether a file loaded.

    Variables already present in the environment are kept unless ``override``.
    Safe to call repeatedly; it only reads the file on the first call.
    """
    global _loaded
    if _loaded and path is None:
        return False
    dotenv = Path(path) if path is not None else find_dotenv()
    if dotenv is None or not dotenv.is_file():
        _loaded = True
        return False
    try:
        for raw in dotenv.read_text(encoding="utf-8").splitlines():
            parsed = _parse_line(raw)
            if parsed is None:
                continue
            key, value = parsed
            if override or key not in os.environ:
                os.environ[key] = value
    except OSError:
        return False
    _loaded = True
    return True
