"""Shannon entropy analysis for SecretShield.

Entropy is a *screening signal*, not proof. A string with high entropy looks
more like machine-generated secret material than like English prose, which
makes it worth a human look. It does **not** establish that a value is a
credential: the same score is produced by a compressed asset, a base64-encoded
image, a git object ID, or a genuinely leaked key. Every consumer of this module
must therefore phrase its output as "worth reviewing", never "confirmed".

Units
-----
Entropy here is measured in **bits per character**, the standard convention for
credential screening. A value of ``H`` means the string needs ``H * len(s)``
bits to describe if each character is chosen independently, which is an
idealisation, not a measurement of the true strength of a secret. Do not quote
these numbers as "bits of guessability".

For reference, English prose sits around 4 bits per character, random base64
around 6, and random hex exactly 4.
"""

from __future__ import annotations

import math
import string
from collections import Counter
from typing import Final

__all__ = [
    "EMPTY_ENTROPY",
    "MAX_ENTROPY",
    "MIN_CANDIDATE_LENGTH",
    "classify_charset",
    "normalized_entropy",
    "shannon_entropy",
    "charset_description",
]

MAX_ENTROPY: Final[float] = 8.0
"""Upper bound on entropy in bits per character: ``log2(256)``.

A value above this needs more than 256 distinct characters to describe, which
is natural language rather than key material. It doubles as the ceiling on the
entropy figure a finding may carry.
"""

EMPTY_ENTROPY: Final[float] = 0.0
"""Entropy of an empty string, defined as ``0.0``.

Zero is mathematically correct: there are no characters, so there is no
variability to describe. Note that this is *low* entropy, which means the
empty string will never be flagged as a candidate.
"""

MIN_CANDIDATE_LENGTH: Final[int] = 20
"""Below this many characters, entropy is not a useful signal.

Short strings cannot accumulate enough variety, and the measurement becomes
dominated by noise. Common API keys and tokens are at least this long.
"""

_HEX_DIGITS: Final[frozenset[str]] = frozenset(string.hexdigits)
_BASE32_ALPHABET: Final[frozenset[str]] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

#: Recognised alphabets, narrowest first.
#:
#: Order matters, and it is the only way to resolve a real ambiguity. A string
#: drawn from ``A-Z2-7`` is simultaneously valid base32, valid base64 and valid
#: uppercase hex, and no amount of inspection reveals which was intended.
#: Checking the narrowest alphabet first always produces the most specific
#: statement that is still true.
#:
#: Standard and URL-safe base64 are deliberately one family: they differ only in
#: ``+/`` versus ``-_``, and a string of letters and digits is indistinguishable
#: between them.
_CHARSET_FAMILIES: Final[tuple[tuple[str, frozenset[str]], ...]] = (
    ("hex", _HEX_DIGITS),
    ("base32", _BASE32_ALPHABET),
    ("base64", frozenset(string.ascii_letters + string.digits + "-_=")),
)


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character.

    For a string of length ``n`` containing symbol ``i`` with probability
    ``p_i``, the result is ``-sum(p_i * log2(p_i))``, which is bounded by
    ``log2(n)``. In practice it is also bounded by ``log2(k)``, where ``k`` is
    the number of distinct characters actually present, so a 40-character hex
    string can never exceed 4.0 bits per character however random it is.

    Args:
        value: The text to measure.

    Returns:
        Entropy in bits per character, in the range ``[0.0, log2(k)]``. An
        empty string returns :data:`EMPTY_ENTROPY`.

    The result is a deterministic pure function of the input: the same string
    always yields the same float, and floating-point summation is ordered so
    that iterating characters in their order of appearance gives bit-identical
    results across runs.

    Examples:
        >>> shannon_entropy("")
        0.0
        >>> shannon_entropy("aaaa")
        0.0
        >>> shannon_entropy("ab")
        1.0
        >>> round(shannon_entropy("abcd"), 6)
        2.0
    """

    if not isinstance(value, str):
        raise TypeError(f"shannon_entropy() expects str, got {type(value).__name__}")
    if not value:
        return EMPTY_ENTROPY

    length = len(value)
    total = 0.0
    # Iterating a Counter is sorted-by-insertion, i.e. by first appearance in
    # the input, which keeps the floating-point summation order deterministic.
    for count in Counter(value).values():
        total += (count / length) * math.log2(count / length)
    return -total


def normalized_entropy(value: str) -> float:
    """Return entropy relative to the alphabet the value actually uses.

    Raw Shannon entropy rewards *alphabet size*, so a long hex digest scores
    4.0 bits per character while an equally random base64 token of the same
    length scores about 5.95. Comparing both against a single fixed threshold
    therefore systematically mishandles one of them.

    This function divides :func:`shannon_entropy` by ``log2(distinct
    characters)``, producing a ``[0.0, 1.0]`` score: how evenly the characters
    are distributed over the alphabet in use, independent of how wide that
    alphabet is.

    Args:
        value: The text to measure.

    Returns:
        A ratio in ``[0.0, 1.0]``. An empty string, or a string where every
        character is identical, returns :data:`EMPTY_ENTROPY`.

    The result is clamped to ``1.0``: a perfectly uniform string divides to
    exactly ``1.0`` in exact arithmetic, but binary floating point can land a
    few ulps above it, which would break the documented range.

    Caveats:
        This ratio is generous with small alphabets. A five-character alphabet
        tops out at ``log2(5) = 2.32``, so ``"aGVsbG8"``-style short strings can
        score 1.0 while being perfectly ordinary. Pair it with
        :data:`MIN_CANDIDATE_LENGTH` and :func:`classify_charset`; never use it
        alone.
    """

    if not isinstance(value, str):
        raise TypeError(f"normalized_entropy() expects str, got {type(value).__name__}")
    if not value:
        return EMPTY_ENTROPY

    distinct = len(set(value))
    if distinct < 2:
        # A single repeated character has zero entropy and an undefined ratio.
        return EMPTY_ENTROPY
    return min(shannon_entropy(value) / math.log2(distinct), 1.0)


def classify_charset(value: str) -> frozenset[str]:
    """Return the character set ``value`` is drawn from.

    This is the universe of characters in ``value``, useful for judging whether
    the text looks like machine-generated material (hex, base64) rather than
    prose. The result is what :func:`normalized_entropy` divides by.

    Args:
        value: The text to classify.

    Returns:
        The distinct characters of ``value``; empty for an empty string.
    """

    if not isinstance(value, str):
        raise TypeError(f"classify_charset() expects str, got {type(value).__name__}")
    return frozenset(value)


def charset_description(value: str) -> str:
    """Describe the character set of ``value`` in words, for reports.

    Args:
        value: The text to describe.

    Returns:
        The most specific matching family name, or ``"mixed"`` when no single
        family covers the value. An empty string is described as ``"empty"``.
    """

    characters = classify_charset(value)
    if not characters:
        return "empty"
    for name, alphabet in _CHARSET_FAMILIES:
        if characters <= alphabet:
            return name
    return "mixed"