"""Normalisation shared by collectors and rules: message fingerprints and bounded text.

A *fingerprint* identifies "the same kind of message" by masking the parts that vary
between occurrences (numbers, GUIDs, hex addresses, timestamps). Repeated-error
detection groups observations by fingerprint.
"""

from __future__ import annotations

import hashlib
import re

FINGERPRINT_TEXT_LIMIT = 1024
TRUNCATION_MARKER = " … [truncated {omitted} characters]"

_GUID = re.compile(
    r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", re.IGNORECASE
)
_ISO_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_HEX_PREFIXED = re.compile(r"\b0x[0-9a-f]+\b", re.IGNORECASE)
_LONG_HEX = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)
_NUMBER = re.compile(r"\d+(?:\.\d+)?")
_WHITESPACE = re.compile(r"\s+")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize_message(message: str) -> str:
    """Mask variable tokens so that recurring messages compare equal."""
    # Bound the work done on untrusted text before running any regular expression.
    text = message[: FINGERPRINT_TEXT_LIMIT * 2]
    text = _GUID.sub("<guid>", text)
    text = _ISO_TIMESTAMP.sub("<ts>", text)
    text = _HEX_PREFIXED.sub("<hex>", text)
    text = _LONG_HEX.sub("<hex>", text)
    text = _NUMBER.sub("<n>", text)
    text = _WHITESPACE.sub(" ", text).strip().casefold()
    return text[:FINGERPRINT_TEXT_LIMIT]


def fingerprint(*parts: str, message: str) -> str:
    """Stable 96-bit identifier for (context parts, normalised message)."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.casefold().encode("utf-8", "replace"))
        digest.update(b"\x1f")
    digest.update(normalize_message(message).encode("utf-8", "replace"))
    return digest.hexdigest()[:24]


def prepare_message(message: str, max_chars: int) -> tuple[str, bool]:
    """Replace control characters and cap length. Returns ``(text, was_truncated)``."""
    cleaned = _CONTROL_CHARS.sub("�", message)
    if len(cleaned) <= max_chars:
        return cleaned, False
    omitted = len(cleaned) - max_chars
    return cleaned[:max_chars] + TRUNCATION_MARKER.format(omitted=omitted), True
