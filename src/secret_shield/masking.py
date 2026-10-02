"""Redaction helpers for SecretShield.

Every function in this module treats a secret as a hostile string that must
never escape into output. The guarantees the rest of the codebase relies on:

* **Nothing is printed, logged, or embedded in an exception message.** All
  exception messages describe *types and lengths*, never values.
* **Redaction is deterministic.** ``mask(value)`` returns the same string for
  the same input on every run, on every platform, so reports diff cleanly.
* **Redacted output never encodes the secret's length.** The redaction marker
  has a fixed width no matter how long the input was, and short values all
  collapse to the same output.
* ``mask(value) != value`` for every possible input, including inputs that
  already look redacted.
* A raw secret may exist only as a short-lived local variable inside masking
  or detection logic. It must never become an attribute of a
  :class:`~secret_shield.models.Finding`, a report, or a log record.

The fingerprint helpers exist so that two occurrences of the same secret can
be correlated ("this key appears in 12 commits") without anybody having to
store the secret to do it.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

__all__ = [
    "REDACTION",
    "REDACTION_FALLBACK",
    "MIN_HIDDEN_CHARS",
    "MAX_REVEALED_CHARS",
    "FINGERPRINT_LENGTH",
    "Span",
    "MaskPolicy",
    "FULLY_REDACTED",
    "mask",
    "fingerprint",
    "is_fingerprint",
    "contains_control_characters",
    "strip_control_characters",
    "normalize_spans",
    "sanitize_excerpt",
]

REDACTION: Final[str] = "*" * 12
"""Fixed-width marker that replaces secret material in all output."""

REDACTION_FALLBACK: Final[str] = "#" * 12
"""Second fixed-width marker, used only when :func:`mask` would otherwise
return a string identical to its input.

That can only happen for a value that already looks redacted (for example
``"AKIA************MPLE"``). Emitting a distinct marker keeps the
``mask(value) != value`` guarantee true without ever widening what is
revealed.
"""

MIN_HIDDEN_CHARS: Final[int] = 12
"""Minimum number of characters that must stay hidden.

Below this, a "redacted" value would still expose most of a short secret, so
the whole value is redacted instead of partially revealed.
"""

MAX_REVEALED_CHARS: Final[int] = 8
"""Hard ceiling on how many characters of a secret a single mask may reveal,
across both the prefix and the suffix combined.
"""

FINGERPRINT_LENGTH: Final[int] = 12
"""Length of the truncated digest returned by :func:`fingerprint`."""

Span = tuple[int, int]
"""A half-open ``(start, end)`` character range within a single line."""

_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdef")

#: Unicode categories removed from any text that will be displayed.
#:
#: ``Cc`` is the control-character set (including newlines and tabs).
#: ``Cf`` is the format set, which contains the bidirectional override
#: characters used for "Trojan Source" style spoofing. ``Zl`` and ``Zp`` are
#: exotic line and paragraph separators that would break single-line output.
_REMOVED_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _require_int(value: object, name: str) -> None:
    """Reject non-integers, including ``bool``, which is an ``int`` subclass."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")


def _coerce_span(span: Sequence[int]) -> Span:
    """Validate one ``(start, end)`` pair and return it as a tuple of ints."""

    if isinstance(span, (tuple, list)) and len(span) == 2:
        start, end = span
        if not isinstance(start, bool) and not isinstance(end, bool):
            if isinstance(start, int) and isinstance(end, int):
                return start, end
    raise TypeError("each span must be a (start, end) pair of integers")


def mask(value: str, keep_prefix: int = 0, keep_suffix: int = 0) -> str:
    """Redact ``value``, optionally preserving a short prefix and/or suffix.

    Args:
        value: The secret to redact. It is never stored or returned.
        keep_prefix: Characters to preserve from the start of the value.
        keep_suffix: Characters to preserve from the end of the value.
            ``0`` disables suffix preservation, so ``keep_suffix=0`` is safe
            for values that end with a newline.

    Returns:
        A redacted string that never contains the original value, is
        deterministic, and whose width does not depend on the input length.

    The prefix and suffix budgets are clamped to :data:`MAX_REVEALED_CHARS` in
    total, and a partial mask is only produced when at least
    :data:`MIN_HIDDEN_CHARS` characters would remain hidden. In every other
    case -- including an empty value and any value shorter than
    ``MIN_HIDDEN_CHARS + 1`` -- the result is exactly :data:`REDACTION`.

    Raises:
        TypeError: If ``value`` is not a string, or the budgets are not ints.
        ValueError: If either budget is negative.
    """

    if not isinstance(value, str):
        raise TypeError(f"mask() expects str, got {type(value).__name__}")
    _require_int(keep_prefix, "keep_prefix")
    _require_int(keep_suffix, "keep_suffix")
    if keep_prefix < 0 or keep_suffix < 0:
        raise ValueError("keep_prefix and keep_suffix must be non-negative")

    prefix_length = min(keep_prefix, MAX_REVEALED_CHARS)
    suffix_length = min(keep_suffix, MAX_REVEALED_CHARS)
    if prefix_length + suffix_length > MAX_REVEALED_CHARS:
        # The prefix is more informative than the suffix (it usually names
        # the vendor), so the suffix absorbs the clamp.
        suffix_length = MAX_REVEALED_CHARS - prefix_length

    revealed = prefix_length + suffix_length
    if revealed and len(value) - revealed >= MIN_HIDDEN_CHARS:
        masked = value[:prefix_length] + REDACTION + value[len(value) - suffix_length :]
    else:
        masked = REDACTION

    if masked == value:
        masked = REDACTION_FALLBACK
    return masked


def fingerprint(value: str, *, key: bytes | None = None) -> str:
    """Return a short, stable identifier for ``value`` that cannot be reversed
    into the value.

    The fingerprint lets findings be correlated ("the same secret appears in
    12 commits") without persisting the secret. It is a truncated digest, not
    an encoding, and it never contains any part of the input.

    Args:
        value: The secret to fingerprint. It is never stored or returned.
        key: Optional HMAC key. Supply one for low-entropy values: an unkeyed
            digest of a weak secret such as a short password can be
            brute-forced, so such values should be keyed instead. A fresh
            random key per run keeps them unguessable at the cost of
            cross-run correlation.

    Returns:
        Exactly :data:`FINGERPRINT_LENGTH` lowercase hexadecimal characters.

    Raises:
        TypeError: If ``value`` is not a string or ``key`` is not bytes.
        ValueError: If ``key`` is provided but empty.
    """

    if not isinstance(value, str):
        raise TypeError(f"fingerprint() expects str, got {type(value).__name__}")

    # ``surrogatepass`` keeps this total: a value decoded from binary noise may
    # legitimately contain lone surrogates, and crashing on them would turn a
    # redaction helper into a denial of service.
    payload = value.encode("utf-8", errors="surrogatepass")

    if key is None:
        digest = hashlib.sha256(payload).hexdigest()
    else:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError(f"fingerprint() key must be bytes, got {type(key).__name__}")
        if not key:
            raise ValueError("fingerprint() key must not be empty")
        digest = hmac.new(bytes(key), payload, hashlib.sha256).hexdigest()

    return digest[:FINGERPRINT_LENGTH]


def is_fingerprint(value: object) -> bool:
    """Return ``True`` if ``value`` looks like a fingerprint produced here.

    Used for validation and by tests. Only the shape is checked; a random
    12-character hex string will also satisfy it.
    """

    return (
        isinstance(value, str)
        and len(value) == FINGERPRINT_LENGTH
        and _HEX_DIGITS.issuperset(value)
    )


def contains_control_characters(text: str) -> bool:
    """Return ``True`` if ``text`` holds characters unsafe for single-line output.

    Callers use this to decide whether a matched value can be partially
    revealed at all. A multi-line block such as a private key must never keep
    a visible prefix or suffix.
    """

    if not isinstance(text, str):
        raise TypeError(f"contains_control_characters() expects str, got {type(text).__name__}")
    return any(unicodedata.category(character) in _REMOVED_CATEGORIES for character in text)


def strip_control_characters(text: str) -> str:
    """Remove control, format and exotic-separator characters from ``text``.

    This is a display-safety helper. Scanned content is untrusted: a repository
    can contain a filename with bidirectional overrides or ANSI escapes that
    would otherwise repaint a terminal or disguise text in a report.
    """

    if not isinstance(text, str):
        raise TypeError(
            f"strip_control_characters() expects str, got {type(text).__name__}"
        )
    return "".join(
        character
        for character in text
        if unicodedata.category(character) not in _REMOVED_CATEGORIES
    )


def normalize_spans(spans: Iterable[Sequence[int]], *, line_length: int) -> tuple[Span, ...]:
    """Clamp, sort and merge character ranges into disjoint, ordered spans.

    Detection code produces spans from several different sources that may
    overlap, arrive out of order, or run past the end of a line. Normalising
    here means :func:`sanitize_excerpt` cannot double-redact or leave a gap.

    Args:
        spans: ``(start, end)`` pairs in half-open character coordinates.
        line_length: Length of the line the spans refer to. Ranges are clamped
            to ``0..line_length``.

    Returns:
        A tuple of disjoint spans sorted by start offset.

    Raises:
        TypeError: If a span is not a pair of integers.
        ValueError: If ``line_length`` is negative.
    """

    _require_int(line_length, "line_length")
    if line_length < 0:
        raise ValueError("line_length must be non-negative")

    cleaned: list[Span] = []
    for span in spans:
        start, end = _coerce_span(span)
        start = max(start, 0)
        end = min(end, line_length)
        if end <= start:  # empty or fully out-of-range range: nothing to redact
            continue
        cleaned.append((start, end))

    cleaned.sort()

    merged: list[Span] = []
    for start, end in cleaned:
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def sanitize_excerpt(
    line: str,
    spans: Iterable[Sequence[int]] = (),
    *,
    redaction: str = REDACTION,
) -> str:
    """Return ``line`` with every detected span replaced by ``redaction``.

    Reports show a sanitized excerpt of the offending line rather than the raw
    line, because the raw line almost always contains the secret next to the
    match. There is deliberately no option to disable this.

    Args:
        line: A single line of scanned text.
        spans: ``(start, end)`` ranges of secret material within ``line``.
        redaction: Replacement marker.

    Returns:
        The excerpt with all spans redacted and control characters removed.
    """

    if not isinstance(line, str):
        raise TypeError(f"sanitize_excerpt() expects str, got {type(line).__name__}")
    if not isinstance(redaction, str) or not redaction:
        raise ValueError("redaction must be a non-empty string")

    merged = normalize_spans(spans, line_length=len(line))

    pieces: list[str] = []
    cursor = 0
    for start, end in merged:
        pieces.append(line[cursor:start])
        pieces.append(redaction)
        cursor = end
    pieces.append(line[cursor:])

    return strip_control_characters("".join(pieces))


@dataclass(frozen=True, slots=True)
class MaskPolicy:
    """A named, reusable masking rule for one class of secret.

    Policies live here rather than in the detector catalog so that every rule
    that touches secret material routes its redaction through the same,
    testable code path.

    Attributes:
        keep_prefix: Characters to reveal from the start of the value.
        keep_suffix: Characters to reveal from the end of the value.
        name: Human-readable policy name, for documentation and reports.
    """

    keep_prefix: int = 0
    keep_suffix: int = 0
    name: str = "default"

    def __post_init__(self) -> None:
        _require_int(self.keep_prefix, "keep_prefix")
        _require_int(self.keep_suffix, "keep_suffix")
        if self.keep_prefix < 0 or self.keep_suffix < 0:
            raise ValueError("keep_prefix and keep_suffix must be non-negative")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name must be a non-empty string")

    def apply(self, value: str) -> str:
        """Redact ``value`` according to this policy. See :func:`mask`."""

        return mask(value, self.keep_prefix, self.keep_suffix)

    def fingerprint(self, value: str, *, key: bytes | None = None) -> str:
        """Fingerprint ``value``. See :func:`fingerprint`."""

        return fingerprint(value, key=key)


FULLY_REDACTED: Final[MaskPolicy] = MaskPolicy(0, 0, name="fully-redacted")
"""Default policy: reveal nothing at all."""