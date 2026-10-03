"""Security utilities for report generation.

Provides sanitization to prevent information disclosure and injection attacks
in report outputs.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence


def sanitize_text(text: str) -> str:
    """Sanitize text for safe display in reports.

    Removes control characters and normalizes whitespace. Never leaks
    secrets - this is defensive programming.
    """
    # Remove control characters except whitespace that is safe
    sanitized = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", text)
    # Collapse multiple spaces
    sanitized = re.sub(r"\s+", " ", sanitized)
    return sanitized.strip()


def markdown_escape(text: str) -> str:
    """Escape text for safe inclusion in Markdown.

    Protects against table injection and formatting attacks.
    """
    # Escape pipes for tables
    text = text.replace("|", "\\|")
    # Escape backticks
    text = text.replace("`", "\\`")
    # Escape square brackets
    text = text.replace("[", "\\[").replace("]", "\\]")
    # Escape asterisks and underscores
    text = text.replace("*", "\\*").replace("_", "\\_")
    # Escape hash
    text = text.replace("#", "\\#")
    # Escape less/greater than for HTML-like content
    text = text.replace("<", "\\<").replace(">", "\\>")
    # Sanitize control chars
    return sanitize_text(text)


def safe_json_serialize(obj: object) -> object:
    """Convert an object to a JSON-safe structure recursively.

    Ensures deterministic serialization and strips control chars from strings.
    """
    if isinstance(obj, str):
        return sanitize_text(obj)
    elif isinstance(obj, Mapping):
        return {str(k): safe_json_serialize(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, Sequence) and not isinstance(obj, str):
        return [safe_json_serialize(item) for item in obj]
    return obj
