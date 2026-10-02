"""Unit tests for :mod:`secret_shield.detectors.context`.

Every heuristic here can suppress a real secret if it is wrong, so these tests
are as interested in what each helper *accepts* as in what it rejects. A
placeholder filter that is too eager is a silent false negative, and a silent
false negative is the failure mode this tool can least afford.
"""

from __future__ import annotations

import pytest

from secret_shield.detectors.context import (
    CONTEXT_VOCABULARY,
    assignment_name,
    is_placeholder,
    is_template_expression,
    keyword_score,
    looks_like_hash,
    normalize_for_matching,
)

SYNTHETIC_SECRET = "SYNTH7cK2mQ9wR4tB8nL3vH6jF0dS5gX1aC2eR4z"


def column_of(line: str, value: str) -> int:
    """The 1-based column at which ``value`` starts, as the engine would see it."""

    return line.index(value) + 1


# ---------------------------------------------------------------------------
# normalize_for_matching
# ---------------------------------------------------------------------------


class TestNormalizeForMatching:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("AWS_SECRET_ACCESS_KEY", "awssecretaccesskey"),
            ("aws-secret-access-key", "awssecretaccesskey"),
            ("AwsSecretAccessKey", "awssecretaccesskey"),
            ("api_key", "apikey"),
            ("", ""),
            ("!!!", ""),
        ],
    )
    def test_separators_and_case_are_erased(self, raw: str, expected: str) -> None:
        """One concept, one spelling, three common conventions."""

        assert normalize_for_matching(raw) == expected

    def test_non_strings_are_rejected(self) -> None:
        with pytest.raises(TypeError, match="expects str"):
            normalize_for_matching(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# assignment_name
# ---------------------------------------------------------------------------


class TestAssignmentName:
    @pytest.mark.parametrize(
        ("line", "value", "expected"),
        [
            ('API_KEY = "value"', "value", "API_KEY"),
            ("API_KEY=value", "value", "API_KEY"),
            ('  "api_key": "value"', "value", "api_key"),
            ("  'api_key': 'value'", "value", "api_key"),
            ("export TOKEN=value", "value", "TOKEN"),
            ('os.environ["AWS_KEY"] = "value"', "value", "AWS_KEY"),
            ("config.apiKey := value", "value", "config.apiKey"),
            ('"token" => "value"', "value", "token"),
            ('{"api_key": "value"}', "value", "api_key"),
            ("password: value", "value", "password"),
        ],
    )
    def test_the_variable_name_is_recovered_across_syntaxes(
        self, line: str, value: str, expected: str
    ) -> None:
        """Python, JSON, YAML, TOML, shell, PHP and Go all name things."""

        assert assignment_name(line, column_of(line, value)) == expected

    def test_a_dotted_name_is_returned_whole(self) -> None:
        """``this.password`` is the variable's real name, and reporting it whole
        is more useful in a finding than reporting only its last segment."""

        line = 'this.password = "value"'

        assert assignment_name(line, column_of(line, "value")) == "this.password"

    def test_a_trailing_bracket_before_the_operator_is_tolerated(self) -> None:
        line = 'os.environ["DB_PASSWORD"]="value"'

        assert assignment_name(line, column_of(line, "value")) == "DB_PASSWORD"

    @pytest.mark.parametrize(
        "line",
        [
            "the api_key value above",
            "value",
            "# a comment about value",
            '"just": "a value"',
            "my-value",
            "value=valuevalue",
        ],
    )
    def test_a_value_with_no_assignment_yields_none(self, line: str) -> None:
        """``None`` is an honest answer. Guessing a name would invent evidence."""

        assert assignment_name(line, column_of(line, "value")) is None

    def test_a_column_past_the_end_of_the_line_is_handled(self) -> None:
        assert assignment_name("key = ", 7) == "key"

    def test_a_dash_separated_name_is_accepted(self) -> None:
        line = "api-key = value"

        assert assignment_name(line, column_of(line, "value")) == "api-key"

    def test_column_one_is_valid(self) -> None:
        assert assignment_name("secret", 1) is None

    def test_a_column_below_one_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="1-based"):
            assignment_name("key = value", 0)

    @pytest.mark.parametrize("bad_column", [True, 1.0, "1", None])
    def test_a_non_integer_column_is_rejected(self, bad_column: object) -> None:
        """``True`` is an ``int`` in Python, so it needs an explicit rejection."""

        with pytest.raises(TypeError, match="column must be an int"):
            assignment_name("key = value", bad_column)  # type: ignore[arg-type]

    def test_non_string_lines_are_rejected(self) -> None:
        with pytest.raises(TypeError, match="expects str"):
            assignment_name(b"key = value", 1)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# keyword_score
# ---------------------------------------------------------------------------


class TestKeywordScore:
    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("", 0),
            ("x = 1", 0),
            ("nothing relevant here at all", 0),
            ("API_KEY = value", 1),
            ("api_key = value", 1),
            ("api-key = value", 1),
            ("apikey = value", 1),
            ("MY_API_KEY_V2 = value", 1),
            ("AWS_SECRET_ACCESS_KEY = value", 2),
            ("access_token = value", 1),
            ("private-key = value", 1),
            ("credentials: aws", 1),
            ("api-key-secret = value", 2),
            ("# api_key, token, password, secret", 4),
        ],
    )
    def test_scoring(self, line: str, expected: int) -> None:
        assert keyword_score(line) == expected

    @pytest.mark.parametrize(
        "line",
        [
            "tokenizer = 1",
            "secretary = z",
            "passwords = q",
            "tokened = False",
        ],
    )
    def test_a_word_merely_containing_a_keyword_scores_nothing(self, line: str) -> None:
        """Word boundaries, not substrings.

        Without this, ordinary source code full of words like ``tokenizer``
        would raise the confidence of unrelated findings.
        """

        assert keyword_score(line) == 0

    def test_overlapping_vocabulary_entries_count_one_concept(self) -> None:
        """``access_token`` contains both ``access-token`` and ``token``.

        It is one idea, so it is one point. Counting it twice would make the
        score a measure of vocabulary overlap rather than of context.
        """

        assert keyword_score("access_token = x") == 1

    def test_a_repeated_keyword_counts_once(self) -> None:
        assert keyword_score("api_key = a; api_key = b") == 1

    def test_the_score_counts_distinct_concepts_and_is_bounded(self) -> None:
        assert keyword_score("token password credential webhook passphrase") == 5

    def test_a_nested_vocabulary_entry_is_not_counted_twice(self) -> None:
        """The whole vocabulary scores fewer points than it has entries.

        ``api-secret`` contains ``secret`` and ``credentials`` contains
        ``credential``. Those are one concept each, so the score is below the
        entry count. This asserts the bound rather than an exact total, because
        the exact total depends on which entries overlap.
        """

        score = keyword_score(" ".join(CONTEXT_VOCABULARY))

        assert 0 < score < len(CONTEXT_VOCABULARY)

    def test_non_strings_are_rejected(self) -> None:
        with pytest.raises(TypeError, match="expects str"):
            keyword_score(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# is_placeholder
# ---------------------------------------------------------------------------


class TestIsPlaceholder:
    @pytest.mark.parametrize(
        "value",
        [
            "example",
            "EXAMPLE",
            "AKIAIOSFODNN7EXAMPLE",
            "changeme",
            "change_me",
            "change-me",
            "your-key-here",
            "your_api_key",
            "your-api-key-here",
            "redacted",
            "dummy",
            "test",
            "sample",
            "xxxxx",
            "xxxxxxxx",
            "placeholder",
            "notreal",
            "REPLACE_ME",
            "insert-key-here",
            "your-secret-here",
        ],
    )
    def test_documented_filler_is_recognised(self, value: str) -> None:
        assert is_placeholder(value)

    def test_asterisk_masks_are_recognised_by_shape_not_by_word(self) -> None:
        """``REDACTION`` is a run of one character, which
        :func:`~secret_shield.tokenizer.has_repetitive_structure` catches; here
        the point is that no placeholder *word* is needed."""

        assert not is_placeholder("*" * 12)
        from secret_shield.tokenizer import has_repetitive_structure

        assert has_repetitive_structure("*" * 12)

    @pytest.mark.parametrize(
        "value",
        [
            SYNTHETIC_SECRET,
            "ghp_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0x",
            "AKIA5H2XNSYNTHKEY09A",
            "postgres://app:SYNTHp7wQ2mK9rT4vB8nL3@db/prod",
            "tX9mK2pL7wR4",
        ],
    )
    def test_a_real_looking_credential_is_not_a_placeholder(self, value: str) -> None:
        """The cost of a hard filter: every one of these must survive."""

        assert not is_placeholder(value)

    def test_a_marker_is_needed_in_whole(self) -> None:
        """``test`` is a placeholder word but ``latest`` is not.

        Short markers are matched as whole words precisely so they cannot
        corrupt a real value that happens to contain those letters.
        """

        assert is_placeholder("test")
        assert not is_placeholder("latest")
        assert not is_placeholder("contest")

    def test_an_empty_value_is_not_a_placeholder(self) -> None:
        assert not is_placeholder("")

    def test_non_strings_are_rejected(self) -> None:
        with pytest.raises(TypeError, match="expects str"):
            is_placeholder(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# is_template_expression
# ---------------------------------------------------------------------------


class TestIsTemplateExpression:
    @pytest.mark.parametrize(
        "value",
        [
            "${VAR}",
            "${PG_PASSWORD}",
            "{{ secrets.x }}",
            "{{TOKEN}}",
            "%VAR%",
            "%DB_PASSWORD%",
            "<%= token %>",
            "@{VAR}",
            "$(pwd)",
            "{% if x %}y{% endif %}",
            "%(name)s",
            "%(name)",
        ],
    )
    def test_every_supported_syntax_is_recognised(self, value: str) -> None:
        assert is_template_expression(value)

    @pytest.mark.parametrize(
        "value",
        [
            SYNTHETIC_SECRET,
            "SYNTHp7wQ2mK9rT4vB8nL3",
            "postgres://user:pw@host/db",
            "hunter2",
            "",
        ],
    )
    def test_a_real_value_is_not_a_template(self, value: str) -> None:
        assert not is_template_expression(value)

    @pytest.mark.parametrize("value", ["${}", "{{}}", "%%", "${"])
    def test_an_empty_interpolation_is_not_a_template(self, value: str) -> None:
        """``${}`` expands to nothing, which is not evidence that a templating
        engine filled anything in."""

        assert not is_template_expression(value)

    def test_surrounding_whitespace_is_tolerated(self) -> None:
        assert is_template_expression("  ${VAR}  ")

    def test_an_interpolation_among_literal_text_is_not_a_template(self) -> None:
        """``postgres://u:${PW}@host/db`` is a real URI with one filler field.

        Treating it as a template would discard a username, a host and a
        database name along with the placeholder.
        """

        assert not is_template_expression("prefix${VAR}suffix")

    def test_a_percent_sign_inside_a_password_is_not_a_template(self) -> None:
        """``%`` is the loosest delimiter in the list, so its cost is asserted.

        A real password beginning *and* ending with ``%`` is what this rule can
        suppress. That is a deliberate, documented trade: the marker appears far
        more often in an unfilled deployment variable.
        """

        assert is_template_expression("%s3cr3t%")
        assert not is_template_expression("s3cr3t%pass")
        assert not is_template_expression("%s3cr3t")

    def test_non_strings_are_rejected(self) -> None:
        with pytest.raises(TypeError, match="expects str"):
            is_template_expression(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# looks_like_hash
# ---------------------------------------------------------------------------


class TestLooksLikeHash:
    @pytest.mark.parametrize(
        "value",
        [
            "a3f5c9e17b2d4806be35f1c8a07d29e4",  # MD5, 32
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1, 40
            "550e8400e29b41d4a716446655440000e29b41d4a716446655440000e29b41d4",  # SHA-256, 64
            "3F2504E04F8941D39A0C0305E82C3301",  # upper case
        ],
    )
    def test_a_recognised_digest_length_in_hex_is_a_hash(self, value: str) -> None:
        assert looks_like_hash(value)

    @pytest.mark.parametrize(
        "value",
        [
            SYNTHETIC_SECRET,  # right length, not hex
            "a3f5c9e17b2d4806be35f1c8a07d29",  # 31, one short
            "a3f5c9e17b2d4806be35f1c8a07d29e4a",  # 33, one long
            "z3f5c9e17b2d4806be35f1c8a07d29e4",  # 32, one non-hex letter
            "AKIA5H2XNSYNTHKEY09A",  # 20
            "",
        ],
    )
    def test_anything_else_is_not_a_hash(self, value: str) -> None:
        assert not looks_like_hash(value)

    def test_a_thirty_two_character_hex_secret_is_matched_by_this_rule(self) -> None:
        """The accepted false negative, stated as a test.

        A 32-character hex API key is indistinguishable from an MD5 sum by
        shape alone. That is why ``Rule.reject_hashes`` defaults to ``False``:
        only a rule whose owner knows the context should opt in.
        """

        value = "c4f8b2e19d7a3056f81b2d4e7a9c3056"

        assert len(value) == 32
        assert looks_like_hash(value)

    def test_non_strings_are_rejected(self) -> None:
        with pytest.raises(TypeError, match="expects str"):
            looks_like_hash(None)  # type: ignore[arg-type]
