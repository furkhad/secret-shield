"""Unit tests for :mod:`secret_shield.masking`.

Every value used here is synthetic. ``EXAMPLE_*`` constants follow placeholders
published in vendor documentation (``AKIAIOSFODNN7EXAMPLE`` is AWS's own
example key); ``SYNTHETIC_*`` values are repetitive blocks that no real system
would issue.

The properties under test are security properties, so several tests assert
negatives ("this must not appear") rather than a specific happy-path string.
"""

from __future__ import annotations

import json

import pytest

from secret_shield.masking import (
    FINGERPRINT_LENGTH,
    FULLY_REDACTED,
    MAX_REVEALED_CHARS,
    MIN_HIDDEN_CHARS,
    REDACTION,
    REDACTION_FALLBACK,
    MaskPolicy,
    contains_control_characters,
    fingerprint,
    is_fingerprint,
    mask,
    normalize_spans,
    sanitize_excerpt,
    strip_control_characters,
)

SYNTHETIC_TOKEN = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
SYNTHETIC_SECRET = "synthetic-secret-value-for-tests-0123456789"
EXAMPLE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
EXAMPLE_GITHUB_TOKEN = "ghp_" + ("0" * 36)

# Values crafted to break the masking guarantee: they already look redacted, so
# a naive mask() would return them unchanged.
COLLISION_CANDIDATES = [
    "AKIA************MPLE",
    REDACTION,
    REDACTION_FALLBACK,
    "*" * 12,
    "ABCD" + "*" * 12 + "EFGH",
]


# --------------------------------------------------------------------------
# mask()
# --------------------------------------------------------------------------


def test_mask_without_reveal_returns_the_fixed_marker() -> None:
    assert mask(SYNTHETIC_TOKEN) == REDACTION
    assert mask(SYNTHETIC_TOKEN, 0, 0) == REDACTION


def test_mask_keeps_the_requested_prefix_and_suffix() -> None:
    masked = mask(EXAMPLE_AWS_KEY, 4, 4)

    assert masked.startswith("AKIA")
    assert masked.endswith("MPLE")
    assert EXAMPLE_AWS_KEY not in masked


def test_masked_value_never_contains_the_original() -> None:
    masked = mask(SYNTHETIC_TOKEN, 4, 4)

    assert SYNTHETIC_TOKEN not in masked
    assert SYNTHETIC_SECRET not in masked
    assert EXAMPLE_AWS_KEY not in mask(EXAMPLE_AWS_KEY, 4, 4)


def test_mask_never_returns_its_input() -> None:
    """The ``mask(v) != v`` guarantee, including adversarial inputs."""

    for value in [SYNTHETIC_TOKEN, *COLLISION_CANDIDATES, "x", "AKIA"]:
        assert mask(value, 4, 4) != value
        assert mask(value) != value


def test_mask_falls_back_when_the_output_would_equal_the_input() -> None:
    # "AKIA************MPLE" masked with 4/4 is itself, so a distinct marker is
    # used instead of widening what is revealed.
    assert mask("AKIA************MPLE", 4, 4) == REDACTION_FALLBACK


@pytest.mark.parametrize("length", list(range(1, 20)))
def test_short_values_collapse_to_one_marker(length: int) -> None:
    """Below the reveal threshold nothing is revealed, whatever the budget."""

    value = "A" * length

    assert mask(value, 4, 4) == REDACTION


@pytest.mark.parametrize("length", list(range(1, 20)))
def test_masked_width_does_not_encode_secret_length(length: int) -> None:
    """Length must not leak: every short value yields an identical string."""

    assert len(mask("A" * length, 4, 4)) == len(REDACTION)


def test_mask_of_empty_value_is_the_marker() -> None:
    assert mask("") == REDACTION
    assert mask("", 4, 4) == REDACTION


def test_mask_never_reveals_more_than_the_hard_budget() -> None:
    """Oversized budgets are clamped to the hard ceiling, not honoured."""

    masked = mask(SYNTHETIC_TOKEN, 100, 100)

    assert len(masked) - len(REDACTION) == MAX_REVEALED_CHARS
    assert SYNTHETIC_TOKEN not in masked


def test_mask_clamps_an_oversized_prefix() -> None:
    """A huge prefix budget must not reveal the whole value."""

    masked = mask(SYNTHETIC_TOKEN, MAX_REVEALED_CHARS, 0)

    assert masked.startswith(SYNTHETIC_TOKEN[:MAX_REVEALED_CHARS])
    assert SYNTHETIC_TOKEN not in masked


def test_mask_prefers_the_prefix_when_both_budgets_are_oversized() -> None:
    masked = mask(SYNTHETIC_TOKEN, MAX_REVEALED_CHARS, MAX_REVEALED_CHARS)

    assert masked.startswith(SYNTHETIC_TOKEN[:MAX_REVEALED_CHARS])
    assert not masked.endswith(SYNTHETIC_TOKEN[-1:])


def test_mask_requires_a_minimum_of_hidden_characters() -> None:
    """Revealing a prefix is only allowed if enough stays hidden."""

    too_short = "A" * (MIN_HIDDEN_CHARS + MAX_REVEALED_CHARS - 1)
    long_enough = "A" * (MIN_HIDDEN_CHARS + MAX_REVEALED_CHARS)

    assert mask(too_short, 4, 4) == REDACTION
    assert mask(long_enough, 4, 4) != REDACTION


def test_mask_is_deterministic() -> None:
    first = mask(SYNTHETIC_TOKEN, 4, 4)
    second = mask(SYNTHETIC_TOKEN, 4, 4)

    assert first == second == mask(SYNTHETIC_TOKEN, 4, 4)


@pytest.mark.parametrize("keep", [-1, -100])
def test_mask_rejects_negative_budgets(keep: int) -> None:
    with pytest.raises(ValueError):
        mask(SYNTHETIC_TOKEN, keep, 0)
    with pytest.raises(ValueError):
        mask(SYNTHETIC_TOKEN, 0, keep)


@pytest.mark.parametrize("bad", [None, 42, b"bytes", ["list"]])
def test_mask_rejects_non_string_values(bad: object) -> None:
    with pytest.raises(TypeError):
        mask(bad)  # type: ignore[arg-type]


def test_mask_rejects_bool_budgets() -> None:
    """``bool`` is an ``int`` subclass and would otherwise be accepted."""

    with pytest.raises(TypeError):
        mask(SYNTHETIC_TOKEN, True, 0)  # type: ignore[arg-type]


def test_mask_writes_nothing_to_the_terminal(
    capsys: pytest.CaptureFixture[str],
) -> None:
    mask(SYNTHETIC_TOKEN, 4, 4)
    fingerprint(SYNTHETIC_TOKEN)
    sanitize_excerpt(f"token = {SYNTHETIC_TOKEN}", [(8, 48)])

    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err == ""


# --------------------------------------------------------------------------
# MaskPolicy
# --------------------------------------------------------------------------


def test_default_policy_reveals_nothing() -> None:
    assert FULLY_REDACTED.apply(SYNTHETIC_TOKEN) == REDACTION
    assert MaskPolicy().keep_prefix == 0


def test_policy_applies_and_fingerprints() -> None:
    policy = MaskPolicy(4, 4, name="aws-style")

    assert policy.apply(EXAMPLE_AWS_KEY).startswith("AKIA")
    assert is_fingerprint(policy.fingerprint(EXAMPLE_AWS_KEY))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"keep_prefix": -1},
        {"keep_prefix": 1.5},
        {"name": ""},
        {"name": "   "},
    ],
)
def test_policy_validates_its_arguments(kwargs: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        MaskPolicy(**kwargs)  # type: ignore[arg-type]


def test_policy_repr_contains_no_secret() -> None:
    """A policy holds configuration only, but prove the invariant anyway."""

    assert SYNTHETIC_TOKEN not in repr(MaskPolicy(4, 4, name="example"))


# --------------------------------------------------------------------------
# fingerprint()
# --------------------------------------------------------------------------


def test_fingerprint_shape_is_stable() -> None:
    result = fingerprint(SYNTHETIC_SECRET)

    assert len(result) == FINGERPRINT_LENGTH
    assert is_fingerprint(result)
    assert result == result.lower()


def test_fingerprint_is_deterministic() -> None:
    assert fingerprint(SYNTHETIC_SECRET) == fingerprint(SYNTHETIC_SECRET)


def test_fingerprint_differs_per_value() -> None:
    assert fingerprint(SYNTHETIC_SECRET) != fingerprint(SYNTHETIC_SECRET + "x")


def test_fingerprint_reveals_nothing_about_the_value() -> None:
    """No window of the secret survives in the digest."""

    result = fingerprint(SYNTHETIC_SECRET)
    windows = {
        SYNTHETIC_SECRET[index : index + 4]
        for index in range(len(SYNTHETIC_SECRET) - 3)
    }

    assert SYNTHETIC_SECRET not in result
    assert result not in SYNTHETIC_SECRET
    assert not any(window in result for window in windows)


def test_hmac_key_changes_the_fingerprint() -> None:
    key = b"per-run-key"

    assert fingerprint(SYNTHETIC_SECRET, key=key) != fingerprint(SYNTHETIC_SECRET)
    assert fingerprint(SYNTHETIC_SECRET, key=key) == fingerprint(
        SYNTHETIC_SECRET, key=key
    )
    assert fingerprint(SYNTHETIC_SECRET, key=key) != fingerprint(
        SYNTHETIC_SECRET, key=b"other"
    )


def test_fingerprint_rejects_an_empty_key() -> None:
    with pytest.raises(ValueError):
        fingerprint(SYNTHETIC_SECRET, key=b"")


def test_fingerprint_rejects_a_non_bytes_key() -> None:
    with pytest.raises(TypeError):
        fingerprint(SYNTHETIC_SECRET, key="not-bytes")  # type: ignore[arg-type]


def test_fingerprint_handles_empty_and_surrogate_values() -> None:
    assert is_fingerprint(fingerprint(""))
    # A value decoded from binary noise must not crash the redactor.
    assert is_fingerprint(fingerprint("\udcff"))


def test_fingerprint_rejects_non_string_values() -> None:
    with pytest.raises(TypeError):
        fingerprint(b"raw-bytes")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value, expected",
    [
        ("0" * FINGERPRINT_LENGTH, True),
        ("a" * FINGERPRINT_LENGTH, True),
        ("0123456789ABC", False),  # uppercase is not produced here
        ("0123456789AB", False),  # too short
        ("0123456789ABCD", False),  # too long
        ("0123456789ag", False),  # not hex
        (None, False),
        (123456, False),
    ],
)
def test_is_fingerprint(value: object, expected: bool) -> None:
    assert is_fingerprint(value) is expected


# --------------------------------------------------------------------------
# spans and excerpts
# --------------------------------------------------------------------------


def test_normalize_spans_sorts_and_merges() -> None:
    assert normalize_spans([(10, 20), (0, 5), (4, 8)], line_length=100) == (
        (0, 8),
        (10, 20),
    )


def test_normalize_spans_clips_to_the_line() -> None:
    assert normalize_spans([(-10, 4), (95, 500)], line_length=100) == (
        (0, 4),
        (95, 100),
    )


def test_normalize_spans_drops_empty_ranges() -> None:
    assert normalize_spans([(5, 5), (9, 3), (200, 300)], line_length=100) == ()


def test_normalize_spans_accepts_lists() -> None:
    assert normalize_spans([[0, 3]], line_length=10) == ((0, 3),)


@pytest.mark.parametrize(
    "span", [(1,), (1, 2, 3), "ab", (None, 2), (1, "2"), (True, 2)]
)
def test_normalize_spans_rejects_malformed_spans(span: object) -> None:
    with pytest.raises(TypeError):
        normalize_spans([span], line_length=10)  # type: ignore[list-item]


def test_normalize_spans_rejects_a_negative_line_length() -> None:
    with pytest.raises(ValueError):
        normalize_spans([], line_length=-1)


def test_sanitize_excerpt_redacts_the_span() -> None:
    line = f'api_key = "{SYNTHETIC_TOKEN}"'

    excerpt = sanitize_excerpt(line, [(11, 51)])

    assert SYNTHETIC_TOKEN not in excerpt
    assert REDACTION in excerpt
    assert excerpt.startswith('api_key = "')


def test_sanitize_excerpt_redacts_multiple_spans() -> None:
    line = f"a={SYNTHETIC_TOKEN} b={EXAMPLE_AWS_KEY}"

    excerpt = sanitize_excerpt(line, [(2, 42), (45, 65)])

    assert SYNTHETIC_TOKEN not in excerpt
    assert EXAMPLE_AWS_KEY not in excerpt


def test_sanitize_excerpt_handles_overlapping_spans_once() -> None:
    line = f"token={SYNTHETIC_TOKEN}"

    excerpt = sanitize_excerpt(line, [(6, 46), (6, 46), (0, 10)])

    assert SYNTHETIC_TOKEN not in excerpt
    assert excerpt.count(REDACTION) == 1


def test_sanitize_excerpt_can_redact_an_entire_line() -> None:
    excerpt = sanitize_excerpt(SYNTHETIC_TOKEN, [(0, len(SYNTHETIC_TOKEN))])

    assert excerpt == REDACTION


def test_sanitize_excerpt_with_no_spans_removes_control_characters() -> None:
    excerpt = sanitize_excerpt("plain text", [])

    assert excerpt == "plain text"


def test_sanitize_excerpt_on_an_empty_line() -> None:
    """Spans are clipped to the line, so an empty line yields an empty excerpt."""

    assert sanitize_excerpt("", [(0, 5)]) == ""
    assert sanitize_excerpt("", []) == ""


def test_sanitize_excerpt_removes_control_characters() -> None:
    line = f"key={SYNTHETIC_TOKEN}\x1b[31m\x07"

    excerpt = sanitize_excerpt(line, [(4, 44)])

    assert "\x1b" not in excerpt
    assert "\x07" not in excerpt


def test_sanitize_excerpt_accepts_a_custom_marker() -> None:
    assert (
        sanitize_excerpt("abcdef", [(0, 3)], redaction="<redacted>") == "<redacted>def"
    )


def test_sanitize_excerpt_rejects_a_non_string_line() -> None:
    with pytest.raises(TypeError):
        sanitize_excerpt(b"bytes", [])  # type: ignore[arg-type]


def test_sanitize_excerpt_rejects_an_empty_marker() -> None:
    with pytest.raises(ValueError):
        sanitize_excerpt("abcdef", [], redaction="")


def test_sanitize_excerpt_output_is_json_safe() -> None:
    line = "note:\tvalue = " + SYNTHETIC_TOKEN

    excerpt = sanitize_excerpt(line, [(14, 54)])

    assert SYNTHETIC_TOKEN not in excerpt
    assert json.loads(json.dumps(excerpt)) == excerpt


# --------------------------------------------------------------------------
# control characters
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "line\nbreak",
        "tab\tseparated",
        "null\x00byte",
        "escape\x1b[31m",
        "bidi‮override",
        "separator here",
    ],
)
def test_strip_control_characters_removes_unsafe_characters(text: str) -> None:
    stripped = strip_control_characters(text)

    assert stripped != text
    assert not contains_control_characters(stripped)


def test_strip_control_characters_keeps_ordinary_text() -> None:
    assert strip_control_characters("password = hunter2") == "password = hunter2"


def test_contains_control_characters_accepts_a_redacted_marker() -> None:
    assert not contains_control_characters(REDACTION)


def test_control_character_helpers_reject_non_strings() -> None:
    with pytest.raises(TypeError):
        contains_control_characters(b"bytes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        strip_control_characters(None)  # type: ignore[arg-type]
