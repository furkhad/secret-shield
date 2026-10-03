"""Unit tests for the Stage 1 entropy detector.

The detector's job is to be *right about what it claims*. Most of these tests
therefore check the claim itself: severity capped, confidence hedged, raw value
absent everywhere.
"""

from __future__ import annotations

import json
import math

import pytest

from secret_shield.detectors import entropy_rule
from secret_shield.detectors.entropy_rule import (
    DEFAULT_MIN_LENGTH,
    REMEDIATION,
    RULE_ID,
    EntropyRuleConfig,
    default_entropy_config,
    detect,
    evaluate,
)
from secret_shield.entropy import normalized_entropy, shannon_entropy
from secret_shield.masking import REDACTION
from secret_shield.models import (
    Confidence,
    DetectorKind,
    SecretCategory,
    Severity,
    SourceKind,
)
from secret_shield.tokenizer import candidates

SYNTHETIC_TOKEN = "x8Kq2mNvR4pLzW7yB1cF3dH5jS6tG9uA0"
SYNTHETIC_HEX = "a3f5c9e17b2d4806be35f1c8a07d29e4"
SYNTHETIC_OTHER = "Q7wZ2mNvR4pLzX9yB1cF3dH8jS0tG5uB2"


def detect_in(text: str, **kwargs: object) -> tuple[object, ...]:
    """Tokenize ``text`` and run the detector over it."""

    return detect(candidates(text), "config/settings.py", **kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# evaluate: the gates
# --------------------------------------------------------------------------


def test_high_entropy_candidate_is_accepted() -> None:
    entropy = evaluate(SYNTHETIC_TOKEN)

    assert entropy is not None
    assert entropy == pytest.approx(shannon_entropy(SYNTHETIC_TOKEN))


def test_hex_candidate_is_accepted() -> None:
    """Hex needs both gates: its raw entropy is close to the threshold."""

    assert evaluate(SYNTHETIC_HEX) is not None
    assert normalized_entropy(SYNTHETIC_HEX) > 0.8


def test_low_entropy_candidate_is_ignored() -> None:
    assert evaluate("low entropy value") is None


def test_repeated_characters_are_ignored() -> None:
    assert evaluate("a" * 40) is None


@pytest.mark.parametrize(
    "value",
    [
        "short1",
        "x8Kq2mNvR4pLzW7yB",  # 19 characters
        "x8Kq2mNvR4pLzW7yB1",  # 20 characters
    ],
)
def test_candidates_shorter_than_the_minimum_are_ignored(value: str) -> None:
    assert len(value) < DEFAULT_MIN_LENGTH
    assert evaluate(value) is None


def test_exactly_at_the_minimum_length_is_considered() -> None:
    value = SYNTHETIC_TOKEN[:DEFAULT_MIN_LENGTH]

    assert len(value) == DEFAULT_MIN_LENGTH
    assert evaluate(value) is not None


def test_placeholder_is_ignored() -> None:
    """The tokenizer drops it, so the detector never sees it."""

    assert detect_in('key = "YOUR_KEY_HERE_REPLACE_ME_1234"') == ()


def test_english_sentence_is_ignored() -> None:
    """Prose scores 4.39 bits per character and must not survive."""

    assert shannon_entropy("the quick brown fox jumps over the lazy dog") > 4.0
    assert evaluate("the quick brown fox jumps over the lazy dog") is None


def test_multi_word_commit_message_is_ignored() -> None:
    assert evaluate("update dependencies and fix the flaky test suite again") is None


def test_two_words_are_still_a_candidate() -> None:
    """The prose guard must not fire too eagerly."""

    assert evaluate("Bearer x8Kq2mNvR4pLzW7yB1cF3dH5jS6tG") is not None


def test_database_dsn_is_a_candidate() -> None:
    assert (
        evaluate("postgres://appuser:hunter2hunter2@db.internal:5432/prod") is not None
    )


def test_natural_language_beyond_the_ceiling_is_ignored() -> None:
    """A very wide alphabet is prose, not key material."""

    wide = "".join(chr(0x4E00 + index) for index in range(400))

    assert evaluate(wide) is None


def test_evaluate_is_deterministic() -> None:
    assert evaluate(SYNTHETIC_TOKEN) == evaluate(SYNTHETIC_TOKEN)


def test_evaluate_rejects_non_strings() -> None:
    with pytest.raises(TypeError):
        evaluate(None)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


def test_defaults_match_the_documented_thresholds() -> None:
    config = default_entropy_config()

    assert config.min_length == 20
    assert config.min_raw_entropy == 3.5
    assert config.min_normalized_entropy == 0.8
    assert config.max_severity is Severity.MEDIUM


def test_raw_floor_sits_below_the_hex_ceiling() -> None:
    """Why the floor is 3.5 and not the intuitive 4.0.

    Hex has a hard mathematical ceiling of log2(16) == 4.0 bits per character,
    and real tokens land just under it. A gate at 4.0 would discard every hex
    secret, so the floor must sit below the ceiling.
    """

    assert math.log2(16) == 4.0
    assert default_entropy_config().min_raw_entropy < math.log2(16)
    assert shannon_entropy(SYNTHETIC_HEX) > default_entropy_config().min_raw_entropy
    assert shannon_entropy(SYNTHETIC_HEX) < 4.0


def test_thresholds_are_adjustable() -> None:
    strict = EntropyRuleConfig(min_raw_entropy=5.5)

    assert evaluate(SYNTHETIC_TOKEN) is not None
    assert evaluate(SYNTHETIC_TOKEN, strict) is None


def test_max_raw_entropy_rejects_very_wide_alphabets() -> None:
    narrow = EntropyRuleConfig(max_raw_entropy=4.0)

    assert evaluate(SYNTHETIC_HEX, narrow) is not None
    assert evaluate(SYNTHETIC_TOKEN, narrow) is None


@pytest.mark.parametrize(
    "value",
    [
        # Random material that happens to be inert. These are reported rather
        # than suppressed, and that is a deliberate, documented decision: a
        # hex API key and a SHA-1 commit hash are the same shape to any
        # entropy measurement. Separating them needs the vendor rules and
        # allowlists of a later stage, not a cleverer threshold.
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # git object id
        "3f2504e0-4f89-41d3-9a0c-0305e82c3301",  # uuid
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAY",  # base64 image header
    ],
)
def test_inert_random_material_is_flagged_rather_than_hidden(value: str) -> None:
    """Stage 1 over-reports by design; it must never under-report."""

    assert evaluate(value) is not None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"min_length": 0},
        {"min_raw_entropy": -1.0},
        {"min_normalized_entropy": 1.5},
        {"min_normalized_entropy": -0.1},
        {"max_raw_entropy": 1.0},
        {"max_prose_words": -1},
    ],
)
def test_configuration_validation(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        EntropyRuleConfig(**kwargs)  # type: ignore[arg-type]


def test_configuration_rejects_a_non_severity() -> None:
    with pytest.raises(TypeError):
        EntropyRuleConfig(max_severity="high")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# the severity and confidence contract
# --------------------------------------------------------------------------


def test_entropy_severity_can_never_be_raised_above_medium() -> None:
    """The central honesty guarantee of this stage."""

    with pytest.raises(ValueError, match="MEDIUM"):
        EntropyRuleConfig(max_severity=Severity.CRITICAL)
    with pytest.raises(ValueError, match="MEDIUM"):
        EntropyRuleConfig(max_severity=Severity.HIGH)


def test_findings_never_exceed_medium_severity() -> None:
    for finding in detect_in(f'a = "{SYNTHETIC_TOKEN}"\nb = "{SYNTHETIC_OTHER}"'):
        assert finding.severity <= Severity.MEDIUM


def test_findings_are_probable_confidence_only() -> None:
    """Entropy cannot raise confidence, so PROBABLE is the highest it gives."""

    for finding in detect_in(f'a = "{SYNTHETIC_TOKEN}"'):
        assert finding.confidence is Confidence.PROBABLE
        assert finding.confidence < Confidence.HIGH_CONFIDENCE


def test_findings_are_labelled_as_entropy_detections() -> None:
    finding = detect_in(f'a = "{SYNTHETIC_TOKEN}"')[0]

    assert finding.detector is DetectorKind.ENTROPY
    assert finding.rule_id == RULE_ID


def test_findings_have_an_unknown_category() -> None:
    """Entropy cannot tell you what kind of credential this is."""

    assert detect_in(f'a = "{SYNTHETIC_TOKEN}"')[0].category is SecretCategory.UNKNOWN


def test_findings_carry_review_advice() -> None:
    finding = detect_in(f'a = "{SYNTHETIC_TOKEN}"')[0]

    assert finding.remediation == REMEDIATION
    assert "rotate" in finding.remediation.lower()


def test_no_finding_is_ever_verified() -> None:
    for finding in detect_in(f'a = "{SYNTHETIC_TOKEN}"\nb = "{SYNTHETIC_OTHER}"'):
        assert finding.confidence is not Confidence.VERIFIED


# --------------------------------------------------------------------------
# what the finding carries, and what it must not
# --------------------------------------------------------------------------


def test_finding_carries_the_measured_entropy() -> None:
    finding = detect_in(f'a = "{SYNTHETIC_TOKEN}"')[0]

    assert finding.entropy == pytest.approx(shannon_entropy(SYNTHETIC_TOKEN))


def test_finding_value_is_fully_masked() -> None:
    finding = detect_in(f'a = "{SYNTHETIC_TOKEN}"')[0]

    assert finding.masked_value == REDACTION
    assert finding.value_length == len(SYNTHETIC_TOKEN)


def test_finding_fingerprints_the_candidate() -> None:
    finding = detect_in(f'a = "{SYNTHETIC_TOKEN}"')[0]

    assert len(finding.value_fingerprint) == 12


def test_same_candidate_in_two_places_shares_a_fingerprint() -> None:
    findings = detect_in(f'a = "{SYNTHETIC_TOKEN}"\nb = "{SYNTHETIC_TOKEN}"')

    assert findings[0].secret_key() == findings[1].secret_key()


def test_raw_value_is_absent_from_the_finding() -> None:
    finding = detect_in(f'a = "{SYNTHETIC_TOKEN}"')[0]

    assert SYNTHETIC_TOKEN not in finding.masked_value
    assert SYNTHETIC_TOKEN not in repr(finding)
    assert SYNTHETIC_TOKEN not in finding.to_json()
    assert SYNTHETIC_TOKEN not in json.dumps(finding.to_dict())
    assert SYNTHETIC_TOKEN not in str(finding.to_dict())


def test_no_finding_field_can_hold_the_raw_value() -> None:
    import dataclasses

    finding = detect_in(f'a = "{SYNTHETIC_TOKEN}"')[0]

    for field in dataclasses.fields(finding):
        assert SYNTHETIC_TOKEN not in str(getattr(finding, field.name))


def test_finding_records_its_position() -> None:
    finding = detect_in(f'key = "{SYNTHETIC_TOKEN}"\n')[0]

    assert finding.location.path == "config/settings.py"
    assert finding.location.line == 1
    assert finding.location.column == 8
    assert finding.location.source_kind is SourceKind.FILE
    assert finding.location.commit is None


def test_git_source_kind_can_be_supplied() -> None:
    findings = detect(
        candidates(f'a = "{SYNTHETIC_TOKEN}"'),
        "settings.py",
        source_kind=SourceKind.GIT,
        commit="a" * 40,
        commit_time=1700000000,
    )

    assert findings[0].location.source_kind is SourceKind.GIT
    assert findings[0].location.commit == "a" * 40
    assert findings[0].location.commit_time == 1700000000


# --------------------------------------------------------------------------
# ordering and edge cases
# --------------------------------------------------------------------------


def test_findings_follow_candidate_order() -> None:
    findings = detect_in(
        f'a = "{SYNTHETIC_TOKEN}"\nb = "{SYNTHETIC_OTHER}"\nc = "{SYNTHETIC_HEX}"'
    )

    assert [finding.location.line for finding in findings] == [1, 2, 3]


def test_no_candidates_yields_no_findings() -> None:
    assert detect_in("x = 1\ny = 2\n") == ()
    assert detect((), "empty.py") == ()


def test_detector_accepts_an_empty_config() -> None:
    assert evaluate(SYNTHETIC_TOKEN, None) is not None
    assert detect(candidates(f'a = "{SYNTHETIC_TOKEN}"'), "x.py", None)


def test_rule_module_exposes_its_thresholds() -> None:
    assert entropy_rule.DEFAULT_MIN_LENGTH == 20
    assert entropy_rule.DEFAULT_MIN_RAW_ENTROPY == 3.5
    assert entropy_rule.DEFAULT_MIN_NORMALIZED_ENTROPY == 0.8
    assert entropy_rule.MAX_PROSE_WORDS == 2
