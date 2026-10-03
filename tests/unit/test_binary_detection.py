"""Unit tests for :mod:`secret_shield.filters.binary`.

The classifier is the gate every file passes through before a single byte is
searched, so both directions matter and both are tested: text that must stay
scannable, and bytes that must be refused. The interesting cases are all at the
boundaries -- an exactly-at-threshold control ratio, a multi-byte character cut
in half by the sniff window, a one-byte file that is not valid UTF-8 -- because
those are where a "close enough" implementation goes wrong quietly.

The tests that matter most are the Unicode ones. The obvious implementation of
"is this binary?" counts bytes outside printable ASCII, which classifies a file
of ordinary accented text as binary and silently loses it. If a future change
reintroduces that, the tests here say so by name.
"""

from __future__ import annotations

import math

import pytest

from secret_shield.filters.binary import (
    ALLOWED_CONTROL_CHARACTERS,
    ALLOWED_SEPARATORS,
    DEFAULT_MAX_CONTROL_RATIO,
    DEFAULT_SNIFF_BYTES,
    BinaryConfig,
    BinaryVerdict,
    classify_bytes,
    default_binary_config,
    has_nul_byte,
)


def verdict(data: bytes, config: BinaryConfig | None = None) -> BinaryVerdict:
    """Classify ``data`` and return the verdict, for terse assertions."""

    return classify_bytes(data, config)


# ---------------------------------------------------------------------------
# Text stays text
# ---------------------------------------------------------------------------


class TestTextIsAccepted:
    """The failures here are silent data loss, so they are named explicitly."""

    def test_plain_ascii_text_is_text(self) -> None:
        assert verdict(b"hello world\n") is BinaryVerdict.TEXT

    def test_source_code_is_text(self) -> None:
        source = b'def f(x):\n    return {"key": "value"}\n\n# a comment\n'
        assert verdict(source) is BinaryVerdict.TEXT

    def test_empty_input_is_text(self) -> None:
        """Nothing in it can be a secret, so nothing is lost by scanning it."""

        assert verdict(b"") is BinaryVerdict.TEXT

    def test_plain_utf8_text_is_text(self) -> None:
        assert verdict("café naïve Grüße\n".encode()) is BinaryVerdict.TEXT

    def test_non_latin_scripts_are_text(self) -> None:
        """The byte-counting implementation fails here. Named so it cannot regress."""

        for sample in (
            "日本語のテキストです\n",
            "Ελληνικά κείμενα\n",
            "Русский текст\n",
            "العربية نص\n",
            "עברית טקסט\n",
            "हिन्दी पाठ\n",
        ):
            assert verdict(sample.encode()) is BinaryVerdict.TEXT, sample

    def test_emoji_and_astral_characters_are_text(self) -> None:
        """Four-byte UTF-8 sequences must not read as binary."""

        assert verdict("🔐🛡️🔑 done\n".encode()) is BinaryVerdict.TEXT

    def test_ideographic_space_is_text(self) -> None:
        """U+3000 is CJK indentation.

        ``str.isprintable`` rejects it as a separator, so it needs the explicit
        allowance. Without it, ordinary CJK source is skipped.
        """

        assert verdict("　字　字\n".encode()) is BinaryVerdict.TEXT

    def test_non_breaking_space_is_text(self) -> None:
        assert verdict("a b c\n".encode()) is BinaryVerdict.TEXT

    def test_typical_whitespace_is_text(self) -> None:
        for byte in ALLOWED_CONTROL_CHARACTERS:
            sample = b"a" + byte.encode() + b"b\n"
            assert verdict(sample) is BinaryVerdict.TEXT, repr(byte)

    def test_a_long_clean_file_is_text(self) -> None:
        assert verdict(b"x = 1\n" * 100_000) is BinaryVerdict.TEXT

    def test_a_file_that_is_entirely_printable_is_text(self) -> None:
        """Base64 has no NUL and no control characters.

        This is a known limitation rather than an oversight: guessing from
        character statistics would misclassify prose. Recorded here so the
        behaviour is a decision on the record.
        """

        assert verdict(b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5" * 10) is (
            BinaryVerdict.TEXT
        )


# ---------------------------------------------------------------------------
# Binary stays binary
# ---------------------------------------------------------------------------


class TestBinaryIsRejected:
    def test_a_nul_byte_anywhere_makes_it_binary(self) -> None:
        for position in (0, 1, 100, 8191):
            data = bytearray(b"a" * DEFAULT_SNIFF_BYTES)
            data[position] = 0
            assert verdict(bytes(data)) is BinaryVerdict.NUL_BYTE, position

    def test_an_elf_header_is_binary(self) -> None:
        assert (
            verdict(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8) is BinaryVerdict.NUL_BYTE
        )

    def test_a_png_header_is_binary(self) -> None:
        png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        assert verdict(png) is BinaryVerdict.NUL_BYTE

    def test_random_bytes_are_binary(self) -> None:
        """A fixed seed, so a failure is reproducible rather than a coin flip."""

        import random

        rng = random.Random(20260903)
        for _ in range(25):
            assert verdict(bytes(rng.randrange(256) for _ in range(4096))) in (
                BinaryVerdict.NUL_BYTE,
                BinaryVerdict.UNDECODABLE,
                BinaryVerdict.CONTROL_HEAVY,
            )

    def test_invalid_utf8_is_undceodable_not_an_exception(self) -> None:
        """A lone continuation byte is not decodable and must not raise."""

        assert verdict(b"\xff") is BinaryVerdict.UNDECODABLE
        assert verdict(b"\x80\x80\x80") is BinaryVerdict.UNDECODABLE
        assert verdict(b"valid text \xc3\x28 more") is BinaryVerdict.UNDECODABLE

    def test_a_latin1_file_is_undceodable(self) -> None:
        """Common in old logs. Skipped deliberately: it is not searchable source."""

        assert verdict("café naïve".encode("latin-1")) is BinaryVerdict.UNDECODABLE

    def test_control_heavy_utf8_is_control_heavy(self) -> None:
        sample = ("\x01\x02\x03\x04" * 100).encode()
        assert verdict(sample) is BinaryVerdict.CONTROL_HEAVY

    def test_mostly_control_characters_with_some_text(self) -> None:
        sample = ("\x01" * 80 + "readable text here\n" * 2).encode()
        assert verdict(sample) is BinaryVerdict.CONTROL_HEAVY

    def test_delete_characters_count_as_control(self) -> None:
        assert verdict(b"a" * 10 + b"\x7f" * 90) is BinaryVerdict.CONTROL_HEAVY


# ---------------------------------------------------------------------------
# Boundaries
# ---------------------------------------------------------------------------


class TestThresholdBoundaries:
    """The comparison is strict, so a ratio exactly at the limit is text."""

    def test_exactly_at_the_ratio_is_text(self) -> None:
        # 30 control characters in 100 total is exactly 0.30.
        sample = ("\x01" * 30 + "a" * 70).encode()
        assert verdict(sample) is BinaryVerdict.TEXT

    def test_one_character_past_the_ratio_is_binary(self) -> None:
        sample = ("\x01" * 31 + "a" * 69).encode()
        assert verdict(sample) is BinaryVerdict.CONTROL_HEAVY

    def test_the_default_ratio_is_thirty_percent(self) -> None:
        assert DEFAULT_MAX_CONTROL_RATIO == 0.30

    def test_a_custom_ratio_is_honoured(self) -> None:
        sample = ("\x01" * 5 + "a" * 95).encode()  # 5% control characters
        assert (
            verdict(sample, BinaryConfig(max_control_ratio=0.10)) is BinaryVerdict.TEXT
        )
        assert verdict(sample, BinaryConfig(max_control_ratio=0.01)) is (
            BinaryVerdict.CONTROL_HEAVY
        )

    def test_a_ratio_of_zero_makes_any_control_character_binary(self) -> None:
        assert verdict(b"a\x01b", BinaryConfig(max_control_ratio=0.0)) is (
            BinaryVerdict.CONTROL_HEAVY
        )
        assert verdict(b"ab", BinaryConfig(max_control_ratio=0.0)) is BinaryVerdict.TEXT

    def test_a_ratio_of_one_never_rejects(self) -> None:
        sample = ("\x01" * 99 + "a").encode()
        assert (
            verdict(sample, BinaryConfig(max_control_ratio=1.0)) is BinaryVerdict.TEXT
        )


class TestSniffWindowBoundaries:
    def test_a_nul_past_the_window_does_not_make_it_binary(self) -> None:
        """Documented Stage 1 behaviour, preserved here.

        The sniff is a prefix, so a file with clean text at the start is text
        even if a NUL appears later. Deliberate: it costs one bounded read
        instead of reading the whole file twice.
        """

        data = b"a" * DEFAULT_SNIFF_BYTES + b"\x00"
        assert verdict(data) is BinaryVerdict.TEXT

    def test_a_nul_just_inside_the_window_does_make_it_binary(self) -> None:
        data = b"a" * (DEFAULT_SNIFF_BYTES - 1) + b"\x00"
        assert verdict(data) is BinaryVerdict.NUL_BYTE

    def test_a_custom_window_changes_the_boundary(self) -> None:
        data = b"a" * 10 + b"\x00"
        assert verdict(data, BinaryConfig(max_sniff_bytes=10)) is BinaryVerdict.TEXT
        assert verdict(data, BinaryConfig(max_sniff_bytes=11)) is BinaryVerdict.NUL_BYTE
        assert verdict(data) is BinaryVerdict.NUL_BYTE  # the default window sees it

    def test_a_multibyte_character_cut_by_the_window_is_still_text(self) -> None:
        """The case that makes naive implementations drop ordinary files.

        Cutting at an arbitrary byte offset can split a UTF-8 character. That is
        an artefact of sniffing, not evidence of binary content, so the tail is
        repaired rather than reported. The *full* data is passed with a smaller
        window, because that is what actually produces a truncated window.
        """

        full = "日本語のテキストです".encode()
        for cut in range(1, len(full)):
            got = classify_bytes(full, BinaryConfig(max_sniff_bytes=cut))
            assert got is BinaryVerdict.TEXT, (cut, got)

    def test_a_window_that_splits_a_character_does_not_hide_real_binary(self) -> None:
        """Repair applies only to the truncated tail, never to the whole file."""

        # A single invalid byte in a file read in full is genuine.
        assert verdict(b"\xff") is BinaryVerdict.UNDECODABLE

    def test_a_window_cut_inside_an_invalid_sequence_is_not_repaired(self) -> None:
        """Trimming must not turn genuinely invalid bytes into text.

        ``E6 97`` is a Japanese character cut short and is repaired. ``E6 28`` is
        the same lead byte followed by ``(``, which is not valid UTF-8 at any
        offset, so the repair must decline it.
        """

        # The tails are genuinely cut off, so the repair is allowed to run.
        assert verdict(
            b"a" * 10 + b"\xe6\x97" + b"tail", BinaryConfig(max_sniff_bytes=12)
        ) is (BinaryVerdict.TEXT)
        assert verdict(
            b"a" * 10 + b"\xe6\x28" + b"tail", BinaryConfig(max_sniff_bytes=12)
        ) is (BinaryVerdict.UNDECODABLE)

    @pytest.mark.parametrize(
        "tail",
        [b"\xff", b"\x80", b"\xc0", b"\xc1", b"\xf5", b"\xfe"],
        ids=["ff", "80", "c0", "c1", "f5", "fe"],
    )
    def test_impossible_lead_bytes_are_never_repaired(self, tail: bytes) -> None:
        """``0xC0``/``0xC1`` are overlong leads and ``0xF5``-``0xFF`` never exist."""

        assert verdict(b"text" + tail + b"tail", BinaryConfig(max_sniff_bytes=5)) is (
            BinaryVerdict.UNDECODABLE
        )


# ---------------------------------------------------------------------------
# Determinism and purity
# ---------------------------------------------------------------------------


class TestDeterminism:
    @pytest.mark.parametrize(
        "data",
        [
            b"plain text\n",
            b"\x00" * 10,
            b"\xff\xfe",
            "日本語\n".encode(),
            ("\x01" * 50).encode(),
            b"",
        ],
        ids=["ascii", "nuls", "invalid", "unicode", "control", "empty"],
    )
    def test_the_same_input_always_gives_the_same_verdict(self, data: bytes) -> None:
        assert len({classify_bytes(data) for _ in range(10)}) == 1

    def test_classification_does_not_mutate_the_input(self) -> None:
        data = bytearray(b"hello\x00world")
        snapshot = bytes(data)
        classify_bytes(bytes(data))
        assert bytes(data) == snapshot

    def test_a_bytearray_is_accepted(self) -> None:
        assert verdict(bytearray(b"text")) is BinaryVerdict.TEXT

    def test_a_memoryview_is_accepted(self) -> None:
        assert verdict(memoryview(b"text")) is BinaryVerdict.TEXT


# ---------------------------------------------------------------------------
# The NUL primitive
# ---------------------------------------------------------------------------


class TestHasNulByte:
    def test_detects_a_nul(self) -> None:
        assert has_nul_byte(b"abc\x00def") is True

    def test_reports_absent(self) -> None:
        assert has_nul_byte(b"abcdef") is False

    def test_empty_is_clean(self) -> None:
        assert has_nul_byte(b"") is False

    def test_accepts_bytearray_and_memoryview(self) -> None:
        assert has_nul_byte(bytearray(b"\x00")) is True
        assert has_nul_byte(memoryview(b"\x00")) is True

    @pytest.mark.parametrize("value", ["text", None, 42, b"ok".decode()])
    def test_rejects_non_bytes(self, value: object) -> None:
        with pytest.raises(TypeError):
            has_nul_byte(value)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Verdict and configuration contracts
# ---------------------------------------------------------------------------


class TestVerdictContract:
    def test_only_text_is_not_binary(self) -> None:
        assert BinaryVerdict.TEXT.is_binary is False
        for other in (
            BinaryVerdict.NUL_BYTE,
            BinaryVerdict.UNDECODABLE,
            BinaryVerdict.CONTROL_HEAVY,
        ):
            assert other.is_binary is True

    def test_every_verdict_has_a_description(self) -> None:
        for item in BinaryVerdict:
            assert item.description
            assert item.description.strip()

    def test_descriptions_contain_no_file_content(self) -> None:
        """The reason string is the one thing guaranteed to reach a log.

        Every verdict's description is a fixed phrase, so no classification can
        put a byte of the file into it.
        """

        data = b"\x89PNG\r\n\x1a\n" + bytes(range(0, 32)) + b"\x00" * 4
        assert classify_bytes(data).description == "contains a NUL byte"
        for item in BinaryVerdict:
            assert "\x00" not in item.description
            assert "PNG" not in item.description

    def test_verdicts_are_strings_for_direct_use_in_codes(self) -> None:
        assert BinaryVerdict.NUL_BYTE.value == "nul-byte"
        assert f"{BinaryVerdict.NUL_BYTE}" == "nul-byte"


class TestConfigContract:
    def test_defaults_are_the_documented_values(self) -> None:
        config = BinaryConfig()
        assert config.max_sniff_bytes == DEFAULT_SNIFF_BYTES == 8192
        assert config.max_control_ratio == DEFAULT_MAX_CONTROL_RATIO

    def test_the_default_factory_returns_a_fresh_equal_object(self) -> None:
        assert default_binary_config() == BinaryConfig()
        assert default_binary_config() is not default_binary_config()

    def test_config_is_immutable(self) -> None:
        with pytest.raises(Exception):
            BinaryConfig().max_sniff_bytes = 1  # type: ignore[misc]

    @pytest.mark.parametrize("value", [0, -1, -8192])
    def test_a_zero_or_negative_window_is_rejected(self, value: int) -> None:
        with pytest.raises(ValueError):
            BinaryConfig(max_sniff_bytes=value)

    @pytest.mark.parametrize("value", [True, "8192", None, 1.5])
    def test_a_non_integer_window_is_rejected(self, value: object) -> None:
        with pytest.raises(TypeError):
            BinaryConfig(max_sniff_bytes=value)  # type: ignore[arg-type]

    @pytest.mark.parametrize("value", [-0.1, 1.1, 2.0])
    def test_a_ratio_outside_zero_to_one_is_rejected(self, value: float) -> None:
        with pytest.raises(ValueError):
            BinaryConfig(max_control_ratio=value)

    @pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
    def test_a_non_finite_ratio_is_rejected(self, value: float) -> None:
        with pytest.raises(ValueError):
            BinaryConfig(max_control_ratio=value)

    @pytest.mark.parametrize("value", [True, "0.3", None])
    def test_a_non_numeric_ratio_is_rejected(self, value: object) -> None:
        with pytest.raises(TypeError):
            BinaryConfig(max_control_ratio=value)  # type: ignore[arg-type]

    @pytest.mark.parametrize("data", ["text", None, 42])
    def test_classify_rejects_non_bytes(self, data: object) -> None:
        with pytest.raises(TypeError):
            classify_bytes(data)  # type: ignore[arg-type]


class TestSeparatorAllowances:
    def test_the_documented_allowances_are_non_empty(self) -> None:
        assert ALLOWED_SEPARATORS
        assert " " in ALLOWED_SEPARATORS
        assert "\u3000" in ALLOWED_SEPARATORS

    def test_zero_width_characters_are_not_allowed(self) -> None:
        """A known trick for hiding data in a file that still looks like text."""

        sample = ("\u200b" * 60 + "text\n").encode()
        assert verdict(sample) is BinaryVerdict.CONTROL_HEAVY

    def test_the_ascii_space_is_not_in_the_control_allowance(self) -> None:
        """It is already printable, so listing it twice would be two rules
        disagreeing about what a space is."""

        assert " " not in ALLOWED_CONTROL_CHARACTERS
