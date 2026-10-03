"""Unit tests for :mod:`secret_shield.entropy`.

Entropy is a formula, so most of these tests pin exact values rather than
ranges: a silent change in the calculation should fail loudly.
"""

from __future__ import annotations

import math

import pytest

from secret_shield.entropy import (
    EMPTY_ENTROPY,
    MAX_ENTROPY,
    classify_charset,
    charset_description,
    normalized_entropy,
    shannon_entropy,
)

SYNTHETIC_HEX = "a3f5c9e17b2d4806be35f1c8a07d29e4"
SYNTHETIC_BASE64 = "x8Kq2mNvR4pLzW7yB1cF3dH5jS6tG9uA0"
SYNTHETIC_PROSE = "the quick brown fox jumps over the lazy dog"


# --------------------------------------------------------------------------
# shannon_entropy
# --------------------------------------------------------------------------


def test_empty_string_has_defined_zero_entropy() -> None:
    assert shannon_entropy("") == EMPTY_ENTROPY == 0.0


def test_single_character_has_zero_entropy() -> None:
    assert shannon_entropy("a") == 0.0


@pytest.mark.parametrize("length", [1, 5, 20, 1000])
def test_repeated_characters_have_zero_entropy(length: int) -> None:
    assert shannon_entropy("x" * length) == 0.0


@pytest.mark.parametrize(
    "value, expected",
    [
        ("ab", 1.0),
        ("abcd", 2.0),
        ("abba", 1.0),
        ("aabb", 1.0),
        # Counts of 2, 2 and 1 over five characters:
        # -(0.4*log2(0.4) + 0.4*log2(0.4) + 0.2*log2(0.2))
        ("aabbc", -(2 * 0.4 * math.log2(0.4) + 0.2 * math.log2(0.2))),
    ],
)
def test_known_entropy_values(value: str, expected: float) -> None:
    assert shannon_entropy(value) == pytest.approx(expected, abs=1e-12)


def test_entropy_is_independent_of_order_for_equal_counts() -> None:
    """Entropy counts symbols, not positions."""

    assert shannon_entropy("aabbcc") == pytest.approx(
        shannon_entropy("cbaabc"), abs=1e-12
    )


def test_hex_entropy_is_capped_at_four_bits() -> None:
    """A 32-character hex token cannot exceed log2(16)."""

    assert shannon_entropy(SYNTHETIC_HEX) == pytest.approx(3.9764, abs=0.001)
    assert shannon_entropy(SYNTHETIC_HEX) <= 4.0


def test_base64_token_has_higher_entropy_than_hex() -> None:
    """Shows why one raw threshold cannot rank both alphabets."""

    assert shannon_entropy(SYNTHETIC_BASE64) > shannon_entropy(SYNTHETIC_HEX)


def test_english_prose_sits_near_four_bits() -> None:
    assert 3.5 < shannon_entropy(SYNTHETIC_PROSE) < 4.5


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a",
        "ab",
        SYNTHETIC_HEX,
        SYNTHETIC_BASE64,
        SYNTHETIC_PROSE,
        "日本語のテキストです",
        "x" * 5000,
    ],
)
def test_entropy_never_exceeds_the_alphabet_bound(value: str) -> None:
    """H is bounded by log2(distinct characters), and by MAX_ENTROPY overall."""

    entropy = shannon_entropy(value)

    assert 0.0 <= entropy <= MAX_ENTROPY
    if value:
        assert entropy <= math.log2(len(set(value))) + 1e-12


def test_entropy_is_never_negative() -> None:
    for value in ("", "a", "aaa", "ab", SYNTHETIC_BASE64, "!@#$%^&*()"):
        assert shannon_entropy(value) >= 0.0


def test_entropy_is_deterministic() -> None:
    values = [SYNTHETIC_HEX, SYNTHETIC_BASE64, SYNTHETIC_PROSE]

    assert len({shannon_entropy(value) for value in values}) == 3
    assert shannon_entropy(SYNTHETIC_BASE64) == shannon_entropy(SYNTHETIC_BASE64)


def test_entropy_depends_only_on_character_counts() -> None:
    """Reversing a string preserves its multiset, so its entropy is unchanged."""

    value = "ab" * 500 + "c" * 20 + "d" * 3

    assert shannon_entropy(value) == pytest.approx(
        shannon_entropy(value[::-1]), abs=1e-12
    )


@pytest.mark.parametrize("bad", [None, 42, b"bytes", ["list"]])
def test_entropy_rejects_non_strings(bad: object) -> None:
    with pytest.raises(TypeError):
        shannon_entropy(bad)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# normalized_entropy
# --------------------------------------------------------------------------


def test_normalized_entropy_of_empty_string_is_zero() -> None:
    assert normalized_entropy("") == 0.0


def test_normalized_entropy_of_single_character_is_zero() -> None:
    assert normalized_entropy("a") == 0.0


def test_normalized_entropy_of_uniform_distribution_is_one() -> None:
    assert normalized_entropy("abcd") == pytest.approx(1.0, abs=1e-12)
    assert normalized_entropy("abab") == pytest.approx(1.0, abs=1e-12)


def test_normalized_entropy_is_between_zero_and_one() -> None:
    for value in (
        SYNTHETIC_HEX,
        SYNTHETIC_BASE64,
        SYNTHETIC_PROSE,
        "aaab",
        "abcd" * 20,
    ):
        assert 0.0 <= normalized_entropy(value) <= 1.0


def test_normalized_entropy_never_exceeds_one_despite_rounding() -> None:
    """A perfectly uniform string divides to exactly 1.0; rounding must not exceed it."""

    for value in (
        SYNTHETIC_BASE64,
        "abcd" * 20,
        "".join(chr(97 + n % 26) for n in range(500)),
    ):
        assert normalized_entropy(value) <= 1.0


def test_normalized_entropy_equalizes_different_alphabets() -> None:
    """The whole point of normalizing: hex and base64 can both reach 1.0."""

    assert normalized_entropy(SYNTHETIC_HEX) > 0.95
    assert normalized_entropy(SYNTHETIC_BASE64) > 0.95
    assert normalized_entropy(SYNTHETIC_HEX) < shannon_entropy(SYNTHETIC_HEX)
    assert normalized_entropy(SYNTHETIC_BASE64) < shannon_entropy(SYNTHETIC_BASE64)


def test_normalized_entropy_penalizes_uneven_distribution() -> None:
    assert normalized_entropy("aaaaaaab") < normalized_entropy("abababab")


@pytest.mark.parametrize("bad", [None, 3.14, b"x"])
def test_normalized_entropy_rejects_non_strings(bad: object) -> None:
    with pytest.raises(TypeError):
        normalized_entropy(bad)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# classify_charset and friends
# --------------------------------------------------------------------------


def test_classify_charset_returns_distinct_characters() -> None:
    assert classify_charset("aabbcc") == frozenset("abc")


def test_classify_charset_of_empty_string() -> None:
    assert classify_charset("") == frozenset()


@pytest.mark.parametrize(
    "value, expected",
    [
        ("", "empty"),
        ("deadbeef", "hex"),
        ("0123456789abcdef", "hex"),
        ("aGVsbG8gd29ybGQ=", "base64"),
        ("x8Kq2mNvR4p", "base64"),
        ("MFRGGZDFMZTWQ2LK", "base32"),
        ("hello world", "mixed"),
        ("日本語", "mixed"),
    ],
)
def test_charset_description(value: str, expected: str) -> None:
    assert charset_description(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        # Ambiguous by construction: valid uppercase hex, valid base32 and valid
        # base64. The narrowest alphabet wins.
        ("ABCDEF", "hex"),
        # 'M' and 'R' are outside the hex alphabet, but valid base32.
        ("MFRGGZDFM", "base32"),
        # Not hex: 'x' is outside the 16-character alphabet, but base64 fits.
        ("x8Kq2mNvR4p", "base64"),
        # Characters from no machine alphabet at all.
        ("hello world", "mixed"),
    ],
)
def test_narrowest_matching_alphabet_wins(value: str, expected: str) -> None:
    assert charset_description(value) == expected


def test_classify_helpers_reject_non_strings() -> None:
    with pytest.raises(TypeError):
        classify_charset(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        charset_description(7)  # type: ignore[arg-type]
