"""Unit tests for :mod:`secret_shield.tokenizer`.

The tokenizer is Stage 1's main defence against noise, so these tests focus on
what it *refuses* to extract as much as on what it does.
"""

from __future__ import annotations

import pytest

from secret_shield.tokenizer import (
    ORIGIN_QUOTED,
    ORIGIN_UNQUOTED,
    Token,
    candidates,
    has_non_secret_structure,
    has_repetitive_structure,
    is_placeholder,
    is_template_expression,
)

SYNTHETIC_TOKEN = "x8Kq2mNvR4pLzW7yB1cF3dH5jS6tG9uA0"
SYNTHETIC_SECRET = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"


def values(text: str) -> list[str]:
    """Return just the candidate values, for compact assertions."""

    return [token.value for token in candidates(text)]


# --------------------------------------------------------------------------
# quoted literals
# --------------------------------------------------------------------------


def test_extracts_double_quoted_string() -> None:
    assert values(f'api_key = "{SYNTHETIC_TOKEN}"') == [SYNTHETIC_TOKEN]


def test_extracts_single_quoted_string() -> None:
    assert values(f"api_key = '{SYNTHETIC_TOKEN}'") == [SYNTHETIC_TOKEN]


def test_extracts_backtick_string() -> None:
    assert values(f"const key = `{SYNTHETIC_TOKEN}`;") == [SYNTHETIC_TOKEN]


def test_quotes_are_not_part_of_the_value() -> None:
    assert '"' not in values(f'x = "{SYNTHETIC_TOKEN}"')[0]


def test_escape_sequence_is_collapsed() -> None:
    """An escaped quote must not end the literal early."""

    assert values(r'x = "abc\"defghijklmnopqrstuv"') == ['abc"defghijklmnopqrstuv']


def test_unterminated_quote_is_not_a_candidate() -> None:
    """Otherwise a stray apostrophe swallows the rest of the file."""

    assert values("it's a trap and there is no closing quote anywhere") == []


def test_double_quoted_string_must_close_on_the_same_line() -> None:
    assert values('x = "unterminated\nmore text here') == []


def test_backtick_string_may_span_lines() -> None:
    """Markdown code spans wrap, so a span can cross a line boundary.

    Such a span is extracted, and then discarded because key material is
    single-line. The tokenizer still has to cope with the shape -- it cannot
    drop the span before reading it, or the closing backtick on a later line
    would swallow everything up to it.
    """

    assert values(f"template = `\n{SYNTHETIC_TOKEN}\n`;") == []


def test_a_single_line_span_is_still_extracted() -> None:
    """The neighbouring case, so the test above is not passing by accident."""

    assert values(f"template = `{SYNTHETIC_TOKEN}`;") == [SYNTHETIC_TOKEN]


def test_json_style_quoted_value_is_extracted() -> None:
    """JSON needs no special handling: the quoted value is a quoted string.

    The quoted *key* is dropped by :func:`has_non_secret_structure`, because
    ``"api_key"`` is a named constant and not a value. That is the right
    outcome: a key is a field name, and no configuration file puts a credential
    where the key goes.
    """

    text = '{ "api_key": "' + SYNTHETIC_TOKEN + '" }'

    assert values(text) == [SYNTHETIC_TOKEN]


def test_multiple_quoted_values_are_all_extracted() -> None:
    text = f'a = "{SYNTHETIC_TOKEN}"\nb = "{SYNTHETIC_SECRET}"'

    assert values(text) == [SYNTHETIC_TOKEN, SYNTHETIC_SECRET]


def test_adjacent_quoted_strings_on_one_line() -> None:
    assert values(f'x = "{SYNTHETIC_TOKEN}" + "{SYNTHETIC_SECRET}"') == [
        SYNTHETIC_TOKEN,
        SYNTHETIC_SECRET,
    ]


# --------------------------------------------------------------------------
# assignment right-hand sides
# --------------------------------------------------------------------------


def test_extracts_unquoted_assignment_value() -> None:
    assert values(f"TOKEN={SYNTHETIC_TOKEN}\n") == [SYNTHETIC_TOKEN]


def test_extracts_assignment_value_with_spaces_around_equals() -> None:
    assert values(f"TOKEN = {SYNTHETIC_TOKEN}\n") == [SYNTHETIC_TOKEN]


def test_assignment_value_keeps_url_punctuation() -> None:
    dsn = "postgres://appuser:pw@db.internal:5432/production"

    assert values(f"DATABASE_URL={dsn}\n") == [dsn]


def test_quoted_assignment_is_handled_by_the_quote_path() -> None:
    tokens = candidates(f'TOKEN = "{SYNTHETIC_TOKEN}"\n')

    assert [token.value for token in tokens] == [SYNTHETIC_TOKEN]
    assert tokens[0].origin == ORIGIN_QUOTED


def test_comparison_is_not_treated_as_assignment() -> None:
    assert values(f'if x == "{SYNTHETIC_TOKEN}":\n    pass\n') == [SYNTHETIC_TOKEN]


def test_assignment_inside_a_quoted_string_is_not_re_extracted() -> None:
    """Identifiers inside a literal are part of the literal, not a new value."""

    assert values(f'message = "run TOKEN={SYNTHETIC_TOKEN} now"') == [
        f"run TOKEN={SYNTHETIC_TOKEN} now"
    ]


# --------------------------------------------------------------------------
# comments
# --------------------------------------------------------------------------


def test_hash_comment_is_skipped() -> None:
    assert values(f"# TOKEN={SYNTHETIC_TOKEN}\n") == []


def test_comment_mid_line_ends_extraction() -> None:
    assert values(f'x = "short"  # TOKEN={SYNTHETIC_TOKEN}\n') == ["short"]


def test_hash_inside_a_quoted_value_is_not_a_comment() -> None:
    assert values(f'color = "{SYNTHETIC_TOKEN}"#\n') == [SYNTHETIC_TOKEN]


# --------------------------------------------------------------------------
# positions
# --------------------------------------------------------------------------


def test_line_and_column_are_one_based() -> None:
    token = candidates(f'key = "{SYNTHETIC_TOKEN}"\n')[0]

    assert token.line == 1
    # k=1 e=2 y=3 space=4 ==5 space=6 quote=7, so the value starts at column 8.
    assert token.column == 8


def test_line_numbers_advance_across_lines() -> None:
    text = "first\nsecond\n"
    tokens = candidates(f'{text}key = "{SYNTHETIC_TOKEN}"\n')

    assert tokens[0].line == 3


def test_offsets_point_at_the_value() -> None:
    text = f'key = "{SYNTHETIC_TOKEN}"'
    token = candidates(text)[0]

    assert text[token.offset : token.offset + token.length] == SYNTHETIC_TOKEN


def test_column_tracks_across_a_long_line() -> None:
    prefix = "x" * 40
    token = candidates(f'{prefix} = "{SYNTHETIC_TOKEN}"')[0]

    # 40 x's, then space, '=', space and the opening quote.
    assert token.column == len(prefix) + 5


def test_carriage_returns_are_normalized_before_positioning() -> None:
    tokens = candidates(f'a = "x"\r\nb = "{SYNTHETIC_TOKEN}"\r\n')

    assert [token.line for token in tokens] == [1, 2]
    # b=1 space=2 ==3 space=4 quote=5, so the value starts at column 6.
    assert tokens[1].column == 6


def test_candidates_are_returned_in_file_order() -> None:
    text = f'one = "{SYNTHETIC_TOKEN}"\ntwo = "{SYNTHETIC_SECRET}"\nthree = "{SYNTHETIC_TOKEN[:-4]}XYZ"'

    found = candidates(text)

    assert [token.line for token in found] == sorted(token.line for token in found)


# --------------------------------------------------------------------------
# structural filters
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "placeholder",
    [
        "EXAMPLE",
        "example-value-not-real",
        "REDACTED",
        "CHANGE_ME",
        "YOUR_KEY_HERE",
        "your-api-key-here",
        "xxxxxxxxxxxxxxxxxxxxxxxx",
        "abcdef1234567890abcdef",
        "REPLACE_ME_WITH_REAL_TOKEN",
        "dummy-token-for-testing",
        "sample-secret-do-not-use",
    ],
)
def test_placeholders_are_dropped(placeholder: str) -> None:
    assert is_placeholder(placeholder)


@pytest.mark.parametrize(
    "value",
    [
        SYNTHETIC_TOKEN,
        SYNTHETIC_SECRET,
        "postgres://app:pw@db.internal:5432/prod",
        "a3f5c9e17b2d4806be35f1c8a07d29e4",
        "akia7qwe2zx89plkj4mn",
    ],
)
def test_real_looking_values_are_not_placeholders(value: str) -> None:
    assert not is_placeholder(value)


def test_documented_example_keys_are_treated_as_placeholders() -> None:
    """The trade-off, stated explicitly.

    AWS's published example key contains the word "example", so the substring
    filter discards it. That is the correct outcome for a *heuristic* screen:
    the key is not a credential, and dropping it costs nothing.

    It is worth knowing because it means a real leaked key containing one of the
    marker words would also be dropped. Later vendor rules handle documented
    examples with an explicit allowlist instead of a substring guess, which is
    why the marker list here only contains strings that random material
    essentially cannot contain: "example" needs seven specific characters in a
    row, and it cannot occur in hex at all because 'x' is not a hex digit.
    """

    assert is_placeholder("akiaiosfodnn7example")
    assert is_placeholder("EXAMPLE")


def test_placeholder_inside_quotes_is_dropped_by_the_tokenizer() -> None:
    assert values(f'api_key = "YOUR_KEY_HERE_REPLACE_ME_1234"') == []


@pytest.mark.parametrize(
    "template",
    ["${SECRET}", "${{SECRET}}", "{{ secrets.API_KEY }}", "<%= ENV['KEY'] %>", "%(KEY)s", "@{token}"],
)
def test_template_expressions_are_detected(template: str) -> None:
    assert is_template_expression(template)


@pytest.mark.parametrize(
    "value",
    ["Bearer ${TOKEN}", "prefix-${ID}-suffix", "${", "a{G}b", "plain text value"],
)
def test_partial_templates_are_kept(value: str) -> None:
    """Literal text around an interpolation is exactly what needs scanning."""

    assert not is_template_expression(value)


def test_template_value_is_dropped_by_the_tokenizer() -> None:
    assert values('api_key = "${SERVICE_API_KEY}"') == []


@pytest.mark.parametrize(
    "value",
    ["aaaaaaaaaaaaaaaaaaaaaaaa", "abcdabcdabcdabcdabcdabcd", "abcdefghijklmnopqrstuvwx", "9876543210"],
)
def test_repetitive_and_sequential_values_are_dropped(value: str) -> None:
    assert has_repetitive_structure(value)


def test_a_digit_run_that_wraps_is_not_sequential() -> None:
    """'1, 0, 9' is not a run: the step from '0' to '9' is +9, not -1."""

    assert not has_repetitive_structure("9876543210987654321098")


@pytest.mark.parametrize("value", [SYNTHETIC_TOKEN, SYNTHETIC_SECRET, "ab", "a"])
def test_genuinely_varied_values_are_not_repetitive(value: str) -> None:
    assert not has_repetitive_structure(value)


def test_repeated_value_is_dropped_by_the_tokenizer() -> None:
    assert values('token = "aaaaaaaaaaaaaaaaaaaaaaaa"') == []


def test_empty_literal_yields_nothing() -> None:
    assert values('x = ""') == []


def test_overlong_literal_is_dropped() -> None:
    assert values('x = "' + "a" * 5000 + '"') == []


# --------------------------------------------------------------------------
# code shapes that must not be treated as values
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        # interpolation syntax, the largest single source of noise
        "{self.source_kind.label}",
        "{_FIELD_INDENT}masked     : {finding.masked_value}",
        "prefix-${ID}",
        # qualified references
        "secret_shield.models.Finding",
        "Finding.from_match",
        "self.matched_keywords",
        "SecretCategory.UNKNOWN",
        "result.sorted_findings",
        # named constants
        "DEFAULT_MIN_RAW_ENTROPY",
        "default_entropy_config",
        "strip_control_characters",
        "is_template_expression",
        "api_key",
        # documentation cross-references
        "~secret_shield.models.Finding",
        "~/",
        # regular-expression syntax
        "^[a-z0-9]+(?:[-_][a-z0-9]+)*$",
        r"\d{4}-\d{2}-\d{2}",
        "^token_[a-z]+$",
        # call syntax
        "Finding.from_match()",
        "render_text(result)",
        "Location(source_kind=SourceKind.FILE)",
        "_render_error(error)",
    ],
)
def test_code_shapes_are_not_candidates(value: str) -> None:
    assert has_non_secret_structure(value)
    assert values(f'x = "{value}"') == []


def test_a_value_spanning_lines_is_not_a_credential() -> None:
    """Key material is single-line by construction.

    This is the one filter that needs no sample and no syntax knowledge, which
    makes it the most trustworthy of the set. A value spanning lines is prose,
    a docstring or a wrapped Markdown span -- all of which score high purely
    because they use many different letters.
    """

    for value in (SYNTHETIC_TOKEN, SYNTHETIC_SECRET):
        assert has_non_secret_structure(f"first line\n{value}")
        assert has_non_secret_structure(f"{value}\r\nlast line")
        assert not has_non_secret_structure(value)


def test_an_object_literal_is_a_template() -> None:
    """Braces mark a dict or set literal, which is data *about* a value."""

    assert values('x = "{config: value}"') == []


@pytest.mark.parametrize(
    "value",
    [
        SYNTHETIC_TOKEN,
        SYNTHETIC_SECRET,
        "a3f5c9e17b2d4806be35f1c8a07d29e4",
        "MFRGGZDFMZTWQ2LKNNWG23TPOA====",
        "aB3-xY9_zQ1-mN4-pR7-tS0-uV3-wX6yZ8ab",
        "postgres://appuser:syntheticpw@db.internal:5432/production",
        "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ],
)
def test_credential_shaped_values_are_still_candidates(value: str) -> None:
    """The structural filters must not touch anything that looks like a secret."""

    assert not has_non_secret_structure(value)
    assert values(f'x = "{value}"') == [value]


def test_braced_value_is_always_a_template() -> None:
    """No generated credential contains a brace, so wrapping one is a giveaway."""

    for value in (SYNTHETIC_TOKEN, SYNTHETIC_SECRET, "a" * 40):
        assert has_non_secret_structure("{" + value)
        assert has_non_secret_structure(value + "}")


def test_dotted_value_with_data_segments_is_not_a_reference() -> None:
    """A URL has dots, but its segments are not identifiers."""

    for value in (
        "postgres://app:pw@db.internal:5432/prod",
        "https://cdn.example.com/assets/app-1.2.3.min.js",
        "redis.cache-01.internal:6379",
    ):
        assert not has_non_secret_structure(value)


def test_a_lone_caret_or_dollar_sign_does_not_condemn_a_value() -> None:
    """Strong human-chosen passwords contain '^' and '$'.

    An earlier version of this filter rejected them, which would have been a
    false negative on a genuinely strong secret. Only a full-match pattern
    counts as proof.
    """

    password = "Zt5#pQ2v!Lm8@Rx4$Kw9%Nb3^Hj7&Cd1*"

    assert "^" in password and "$" in password
    assert not has_non_secret_structure(password)
    assert values(f'password = "{password}"') == [password]


def test_underscore_rule_costs_prefixed_vendor_tokens() -> None:
    """The documented cost of the named-constant filter.

    A vendor-prefixed token is suppressed here on purpose, because a vendor rule
    will match it exactly in a later stage. Recorded as a test so that if the
    trade is ever revisited, this is the behaviour that changes.
    """

    assert has_non_secret_structure("ghp_" + "0" * 36)
    assert has_non_secret_structure("sk_live_51SyntheticSynthetic0")


def test_call_filter_costs_a_bracketed_password() -> None:
    """The documented cost of the call-shape filter.

    A password with a bracket against a letter is suppressed. Recorded for the
    same reason as the rule above: this is a deliberate trade, not an accident.
    """

    assert has_non_secret_structure("Pass(word)1234567890abcdef")

    # A bracket that is not attached to a letter is not a call, and is kept.
    assert not has_non_secret_structure("Zt5#pQ2v!Lm8@Rx4$Kw9%Nb3^Hj7&Cd1*")


def test_filters_do_not_remove_everything() -> None:
    """A sanity floor on the filters themselves.

    If these five checks ever start rejecting unbroken alphanumeric strings, the
    detector has stopped working, and every test above would still pass.
    """

    text = "\n".join(f'key_{index} = "{value}"' for index, value in enumerate(
        [
            SYNTHETIC_TOKEN,
            "a3f5c9e17b2d4806be35f1c8a07d29e4",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "MFRGGZDFMZTWQ2LKNNWG23TPOA====",
            "aB3-xY9_zQ1-mN4-pR7-tS0-uV3-wX6yZ8ab",
        ]
    ))

    assert len(values(text)) == 5


def test_has_non_secret_structure_rejects_non_strings() -> None:
    with pytest.raises(TypeError):
        has_non_secret_structure(None)  # type: ignore[arg-type]


def test_empty_and_non_string_inputs() -> None:
    assert candidates("") == []
    with pytest.raises(TypeError):
        candidates(b"bytes")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Token safety
# --------------------------------------------------------------------------


def test_token_repr_never_contains_the_raw_value() -> None:
    token = candidates(f'key = "{SYNTHETIC_TOKEN}"')[0]

    assert SYNTHETIC_TOKEN not in repr(token)
    assert "Token(line=1" in repr(token)


def test_token_exposes_length_without_exposing_value() -> None:
    token = candidates(f'key = "{SYNTHETIC_TOKEN}"')[0]

    assert token.length == len(SYNTHETIC_TOKEN)


def test_token_is_immutable() -> None:
    import dataclasses

    token = candidates(f'key = "{SYNTHETIC_TOKEN}"')[0]

    with pytest.raises(dataclasses.FrozenInstanceError):
        token.value = "changed"  # type: ignore[misc]


def test_token_carries_its_origin() -> None:
    quoted = candidates(f'x = "{SYNTHETIC_TOKEN}"')[0]
    unquoted = candidates(f"TOKEN={SYNTHETIC_TOKEN}\n")[0]

    assert quoted.origin == ORIGIN_QUOTED
    assert quoted.delimiter == '"'
    assert unquoted.origin == ORIGIN_UNQUOTED
    assert unquoted.delimiter == ""


def test_tokenizer_never_raises_on_hostile_input() -> None:
    for text in ['"', "'", "`", "\\", "#", "=", 'x="', "\x00", "\ud800", "a" * 100000, "\n" * 1000]:
        candidates(text)  # must not raise


def test_token_is_constructible_directly() -> None:
    token = Token(value="abc", line=1, column=1, offset=0, delimiter='"', origin=ORIGIN_QUOTED)

    assert token.length == 3