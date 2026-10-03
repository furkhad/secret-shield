"""Unit tests for the rule engine: :mod:`secret_shield.detectors.base`.

The engine is where a malformed catalog turns into silently wrong output, so
most of these tests assert that bad configuration *fails loudly*. A rule that
cannot compile, an id that is not unique, a confidence of ``VERIFIED`` -- each
of those is a bug that is far cheaper to catch at import than to diagnose from a
report three stages later.
"""

from __future__ import annotations

import re
from dataclasses import FrozenInstanceError

import pytest

from secret_shield.detectors.base import (
    MAX_MATCH_LENGTH,
    DetectorKind,
    DetectorRegistry,
    RawMatch,
    Rule,
    Specificity,
    find_matches,
    findings_from,
)
from secret_shield.models import Confidence, SecretCategory, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_rule(**overrides: object) -> Rule:
    """Build a minimal valid rule, overriding whatever a test needs to change.

    The example value ``SYNTH-deadbeef`` carries the fixture marker on purpose:
    ``test-`` would not do, because ``test`` is a placeholder word and the
    placeholder filter would correctly -- and confusingly -- discard it.
    """

    fields: dict[str, object] = {
        "id": "test-rule",
        "name": "Test rule",
        "category": SecretCategory.API_KEY,
        "severity": Severity.HIGH,
        "pattern": r"SYNTH-[0-9a-f]{8}",
    }
    fields.update(overrides)
    return Rule(**fields)  # type: ignore[arg-type]


def make_match(rule: Rule | None = None, value: str = "SYNTHabc123DEF456") -> RawMatch:
    """Build a RawMatch directly, for tests that do not need the engine."""

    return RawMatch(
        rule=rule if rule is not None else make_rule(),
        value=value,
        line=1,
        column=1,
        end_line=1,
        end_column=len(value) + 1,
        start_offset=0,
        end_offset=len(value),
        entropy=4.0,
    )


def rebuild(match: RawMatch, **overrides: object) -> RawMatch:
    """Copy a match with different evidence, without repeating seven fields."""

    fields = {
        "rule": match.rule,
        "value": match.value,
        "line": match.line,
        "column": match.column,
        "end_line": match.end_line,
        "end_column": match.end_column,
        "start_offset": match.start_offset,
        "end_offset": match.end_offset,
        "entropy": match.entropy,
    }
    fields.update(overrides)
    return RawMatch(**fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Construction and validation
# ---------------------------------------------------------------------------


class TestRuleConstruction:
    def test_pattern_is_compiled_once_at_construction(self) -> None:
        """A malformed rule is rejected where it is written, not at scan time."""

        rule = make_rule()

        assert isinstance(rule.compiled, re.Pattern)
        # Repeated search calls must reuse the same compiled object.
        assert rule.compiled is rule.compiled

    def test_a_valid_rule_has_no_max_length_and_no_entropy_floor_by_default(
        self,
    ) -> None:
        rule = make_rule()

        assert rule.max_length is None
        assert rule.min_entropy is None

    def test_dotall_is_compiled_into_the_pattern(self) -> None:
        without = make_rule(pattern=r"a.b")
        with_dotall = make_rule(pattern=r"a.b", dotall=True)

        assert without.compiled.search("a\nb") is None
        assert with_dotall.compiled.search("a\nb") is not None

    def test_multiline_is_always_enabled(self) -> None:
        """``^`` and ``$`` must mean line boundaries, for context-gated rules."""

        rule = make_rule(pattern=r"^secret$")

        assert rule.compiled.search("noise\nsecret\nnoise") is not None

    def test_the_rule_is_frozen(self) -> None:
        rule = make_rule()

        with pytest.raises(FrozenInstanceError):
            rule.id = "renamed"  # type: ignore[misc]

    def test_equality_ignores_the_compiled_pattern(self) -> None:
        """Two rules with identical metadata are equal, however they compiled."""

        assert make_rule() == make_rule()

    def test_a_differing_field_breaks_equality(self) -> None:
        assert make_rule() != make_rule(severity=Severity.LOW)


class TestRuleValidation:
    """Malformed metadata must fail at construction, loudly and specifically."""

    def test_an_invalid_regex_fails_loudly(self) -> None:
        with pytest.raises(ValueError, match="invalid pattern"):
            make_rule(pattern="unclosed[group")

    def test_an_invalid_regex_error_names_the_rule_and_the_problem(self) -> None:
        """A pattern is rule metadata, not scanned content, so quoting is safe."""

        with pytest.raises(ValueError) as info:
            make_rule(id="my-rule", pattern="(?P<bad")

        message = str(info.value)
        assert "my-rule" in message
        assert "invalid pattern" in message

    @pytest.mark.parametrize(
        "bad_id",
        ["Has-Caps", "trailing-", "-leading", "double--dash", "has space", "id!bang"],
    )
    def test_a_malformed_id_is_rejected(self, bad_id: str) -> None:
        with pytest.raises(ValueError, match="lowercase"):
            make_rule(id=bad_id)

    @pytest.mark.parametrize("empty_id", ["", "   "])
    def test_an_empty_id_is_rejected(self, empty_id: str) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            make_rule(id=empty_id)

    @pytest.mark.parametrize(
        "good_id", ["aws", "aws-secret", "gh-pat-classic", "db2-uri", "stage_2"]
    )
    def test_well_formed_ids_are_accepted(self, good_id: str) -> None:
        """Segments are joined by ``-`` or ``_`` and are lower-case alnum.

        Both joiners are accepted because that is the same rule-id grammar the
        :class:`~secret_shield.models.Finding` validator uses; rejecting one of
        them here would make it impossible to reference such a rule in a
        finding.
        """

        assert make_rule(id=good_id).id == good_id

    @pytest.mark.parametrize("field", ["id", "name", "pattern"])
    def test_a_non_string_field_is_rejected(self, field: str) -> None:
        with pytest.raises(TypeError):
            make_rule(**{field: 123})

    def test_an_empty_name_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            make_rule(name="")

    def test_free_text_fields_may_be_empty_but_not_non_strings(self) -> None:
        assert make_rule(remediation="", false_positive_notes="").remediation == ""

        with pytest.raises(TypeError):
            make_rule(remediation=None)

    @pytest.mark.parametrize("field", ["category", "severity", "specificity"])
    def test_wrong_enum_types_are_rejected(self, field: str) -> None:
        with pytest.raises(TypeError, match=field):
            make_rule(**{field: "not-an-enum"})

    def test_a_rule_may_not_declare_verified_confidence(self) -> None:
        """Nothing in SecretShield can verify a credential, so no rule may claim it.

        A pattern match is evidence about shape. Verification requires asking
        the issuing service, which this tool never does, and allowing a rule to
        declare ``VERIFIED`` would let that claim be made by data alone.
        """

        with pytest.raises(ValueError, match="VERIFIED"):
            make_rule(base_confidence=Confidence.VERIFIED)

    def test_a_non_confidence_base_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="base_confidence"):
            make_rule(base_confidence="high")

    @pytest.mark.parametrize("bad_entropy", [-0.1, 8.1, 100.0])
    def test_entropy_outside_the_ceiling_is_rejected(self, bad_entropy: float) -> None:
        """Entropy above 8 bits per character is impossible for a single string."""

        with pytest.raises(ValueError, match="between 0.0 and 8.0"):
            make_rule(min_entropy=bad_entropy)

    def test_entropy_bounds_are_inclusive(self) -> None:
        assert make_rule(min_entropy=0.0).min_entropy == 0.0
        assert make_rule(min_entropy=8.0).min_entropy == 8.0

    @pytest.mark.parametrize("bad", [True, "3.0", [3.0], object()])
    def test_a_non_numeric_entropy_floor_is_rejected(self, bad: object) -> None:
        """``True`` is an ``int`` in Python, so it needs an explicit rejection."""

        with pytest.raises(TypeError, match="min_entropy"):
            make_rule(min_entropy=bad)

    def test_no_entropy_floor_is_expressed_as_none(self) -> None:
        assert make_rule(min_entropy=None).min_entropy is None

    def test_max_length_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            make_rule(max_length=0)

    @pytest.mark.parametrize("bad", [True, "40", 40.0])
    def test_a_non_integer_max_length_is_rejected(self, bad: object) -> None:
        with pytest.raises(TypeError, match="max_length"):
            make_rule(max_length=bad)

    @pytest.mark.parametrize(
        "field", ["priority", "dotall", "reject_hashes", "suppress_placeholders"]
    )
    def test_misc_flags_are_type_checked(self, field: str) -> None:
        with pytest.raises(TypeError, match=field):
            make_rule(**{field: "yes"})

    def test_keywords_must_be_a_sequence_not_a_bare_string(self) -> None:
        """A bare string is iterable, and would silently become its characters."""

        with pytest.raises(TypeError, match="keywords"):
            make_rule(keywords="api_key")

    def test_placeholders_must_be_a_sequence_not_a_bare_string(self) -> None:
        with pytest.raises(TypeError, match="placeholders"):
            make_rule(placeholders="example")

    def test_keyword_entries_must_be_non_empty_strings(self) -> None:
        with pytest.raises(ValueError, match="keywords entry"):
            make_rule(keywords=("",))

    def test_a_context_gated_rule_must_declare_keywords(self) -> None:
        """A rule that needs context and names none could never match anything."""

        with pytest.raises(
            ValueError, match="requires context but declares no keywords"
        ):
            make_rule(requires_context=True)

    def test_a_wrong_mask_policy_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="mask_policy"):
            make_rule(mask_policy="full")


class TestConfidenceFloor:
    def test_an_exact_rule_floors_at_high_confidence(self) -> None:
        rule = make_rule(specificity=Specificity.EXACT, base_confidence=None)

        assert rule.confidence_floor is Confidence.HIGH_CONFIDENCE

    def test_a_heuristic_rule_floors_at_candidate(self) -> None:
        rule = make_rule(specificity=Specificity.HEURISTIC, base_confidence=None)

        assert rule.confidence_floor is Confidence.CANDIDATE

    def test_an_explicit_base_overrides_the_specificity_derived_floor(self) -> None:
        rule = make_rule(
            specificity=Specificity.EXACT, base_confidence=Confidence.PROBABLE
        )

        assert rule.confidence_floor is Confidence.PROBABLE


class TestValueGroup:
    def test_a_rule_without_a_named_group_uses_the_whole_match(self) -> None:
        assert make_rule(pattern=r"plain").value_group is None

    def test_a_secret_group_designates_the_credential(self) -> None:
        assert make_rule(pattern=r"user:(?P<secret>\w+)").value_group == "secret"

    def test_a_value_group_designates_the_credential(self) -> None:
        assert make_rule(pattern=r"user:(?P<value>\w+)").value_group == "value"

    def test_secret_takes_precedence_when_both_are_present(self) -> None:
        rule = make_rule(pattern=r"(?P<value>\w+):(?P<secret>\w+)")

        assert rule.value_group == "secret"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestDetectorRegistry:
    def test_a_new_rule_is_registered_and_returned(self) -> None:
        registry: DetectorRegistry = DetectorRegistry()
        rule = make_rule(id="alpha")

        assert registry.register(rule) is rule
        assert registry.get("alpha") is rule
        assert len(registry) == 1

    def test_a_duplicate_id_fails_loudly(self) -> None:
        """Two rules sharing an id would double-report or shadow each other,
        depending on iteration order. Neither is acceptable."""

        registry: DetectorRegistry = DetectorRegistry([make_rule(id="alpha")])

        with pytest.raises(ValueError, match="duplicate rule id 'alpha'"):
            registry.register(make_rule(id="alpha", name="Different name"))

    def test_the_original_rule_survives_a_rejected_duplicate(self) -> None:
        registry: DetectorRegistry = DetectorRegistry(
            [make_rule(id="alpha", severity=Severity.LOW)]
        )

        with pytest.raises(ValueError):
            registry.register(make_rule(id="alpha", severity=Severity.CRITICAL))

        assert registry.get("alpha").severity is Severity.LOW

    def test_registering_a_non_rule_is_rejected(self) -> None:
        registry: DetectorRegistry = DetectorRegistry()

        with pytest.raises(TypeError, match="expects a Rule"):
            registry.register("not-a-rule")  # type: ignore[arg-type]

    def test_a_malformed_rule_fails_when_the_registry_is_built(self) -> None:
        with pytest.raises(ValueError, match="invalid pattern"):
            DetectorRegistry([make_rule(id="broken", pattern="(")])

    def test_get_raises_for_an_unknown_id(self) -> None:
        registry: DetectorRegistry = DetectorRegistry()

        with pytest.raises(KeyError, match="no rule registered with id 'nope'"):
            registry.get("nope")

    def test_find_returns_none_for_an_unknown_id(self) -> None:
        assert DetectorRegistry().find("nope") is None

    def test_ordering_is_by_priority_then_id(self) -> None:
        registry: DetectorRegistry = DetectorRegistry(
            [
                make_rule(id="zebra", priority=10),
                make_rule(id="alpha", priority=10),
                make_rule(id="middle", priority=5),
            ]
        )

        assert registry.ids() == ("middle", "alpha", "zebra")

    def test_ordering_does_not_depend_on_registration_order(self) -> None:
        """Two registries built from the same rules in opposite order agree.

        Reports are diffed between runs. If ordering depended on insertion, a
        refactor of the catalog would reorder every report.
        """

        rules = [
            make_rule(id="one", priority=10),
            make_rule(id="two", priority=20),
            make_rule(id="three", priority=20),
        ]
        forward: DetectorRegistry = DetectorRegistry(rules)
        backward: DetectorRegistry = DetectorRegistry(list(reversed(rules)))

        assert forward.ids() == backward.ids()
        # Priority first, then id alphabetically: "three" precedes "two".
        assert forward.ids() == ("one", "three", "two")

    def test_for_category_selects_and_keeps_order(self) -> None:
        registry: DetectorRegistry = DetectorRegistry(
            [
                make_rule(id="a", category=SecretCategory.AWS, priority=20),
                make_rule(id="b", category=SecretCategory.STRIPE, priority=10),
                make_rule(id="c", category=SecretCategory.AWS, priority=5),
            ]
        )

        assert [r.id for r in registry.for_category(SecretCategory.AWS)] == ["c", "a"]
        assert registry.for_category(SecretCategory.GITHUB) == ()

    def test_membership_and_iteration(self) -> None:
        rule = make_rule(id="alpha")
        registry: DetectorRegistry = DetectorRegistry([rule])

        assert "alpha" in registry
        assert "beta" not in registry
        assert list(registry) == [rule]
        assert len(registry) == 1

    def test_a_generator_of_rules_is_accepted(self) -> None:
        registry: DetectorRegistry = DetectorRegistry(
            make_rule(id=str(n)) for n in range(3)
        )

        assert len(registry) == 3

    def test_an_empty_registry_is_usable(self) -> None:
        assert len(DetectorRegistry()) == 0
        assert DetectorRegistry().ids() == ()


# ---------------------------------------------------------------------------
# RawMatch
# ---------------------------------------------------------------------------


class TestRawMatchRedaction:
    def test_repr_never_contains_the_value(self) -> None:
        """The whole point: a debugger, log line or traceback must reveal nothing."""

        value = "SYNTHsuperSecretValue9Z"
        match = make_match(value=value)

        assert value not in repr(match)
        assert value not in str(match)

    def test_repr_reports_the_position_and_the_rule(self) -> None:
        rendered = repr(make_match(value="SYNTHsuperSecretValue9Z"))

        assert "test-rule" in rendered
        assert "line=1" in rendered
        assert "column=1" in rendered

    def test_repr_reports_the_length_without_the_value(self) -> None:
        value = "SYNTHsuperSecretValue9Z"
        rendered = repr(make_match(value=value))

        assert f"length={len(value)}" in rendered
        assert str(len(value)) == "23", "guard the length assertion itself"

    def test_repr_never_shows_any_slice_of_the_value(self) -> None:
        """Not even a prefix, which is enough to identify a key in a vault."""

        value = "SYNTHsuperSecretValue9Z"

        for start in range(len(value) - 5):
            assert value[start : start + 6] not in repr(make_match(value=value))

    def test_finding_built_from_a_match_holds_no_raw_value(self) -> None:
        value = "SYNTHsuperSecretValue9Z"
        finding = make_match(value=value).to_finding("some/file.py")

        rendered = repr(finding)
        assert value not in rendered
        assert finding.masked_value != value

    def test_finding_is_attributed_to_the_pattern_detector(self) -> None:
        finding = make_match().to_finding("some/file.py")

        assert finding.detector is DetectorKind.PATTERN

    def test_finding_never_reaches_verified_confidence(self) -> None:
        finding = make_match().to_finding("some/file.py")

        assert finding.confidence is not Confidence.VERIFIED

    def test_source_kind_and_commit_reach_the_location(self) -> None:
        from secret_shield.models import SourceKind

        finding = make_match().to_finding(
            "file.py",
            source_kind=SourceKind.GIT,
            commit="a" * 40,
            commit_time=1700000000,
        )

        assert finding.location.source_kind is SourceKind.GIT
        assert finding.location.commit == "a" * 40


class TestRawMatchGeometry:
    def test_span_is_the_offset_range(self) -> None:
        match = make_match(value="0123456789")

        assert match.span == (0, 10)

    def test_span_recovers_the_matched_text_from_the_source(self) -> None:
        """Stage 4 fusion compares spans, so a span must index the real text."""

        prefix, value, suffix = "BEFORE ", "SYNTHmiddle9ZQ", " AFTER"
        text = prefix + value + suffix
        match = make_match(value=value)
        match = RawMatch(
            rule=match.rule,
            value=value,
            line=1,
            column=len(prefix) + 1,
            end_line=1,
            end_column=len(prefix) + len(value) + 1,
            start_offset=len(prefix),
            end_offset=len(prefix) + len(value),
            entropy=4.0,
        )

        start, end = match.span
        assert text[start:end] == value

    def test_a_single_line_match_does_not_overlap_lines(self) -> None:
        assert make_match().overlaps is False

    def test_a_multi_line_match_reports_the_line_overlap(self) -> None:
        match = RawMatch(
            rule=make_rule(),
            value="-----BEGIN RSA PRIVATE KEY-----",
            line=3,
            column=1,
            end_line=9,
            end_column=28,
            start_offset=40,
            end_offset=68,
            entropy=3.0,
        )

        assert match.overlaps is True

    def test_id_and_length_are_derived_from_the_rule_and_value(self) -> None:
        match = make_match(value="SYNTHabc123")

        assert match.id == "test-rule"
        assert match.length == 11


class TestRawMatchConfidence:
    def test_a_heuristic_rule_is_raised_one_step_by_evidence(self) -> None:
        rule = make_rule(
            specificity=Specificity.HEURISTIC, base_confidence=Confidence.CANDIDATE
        )
        match = make_match(rule=rule)
        match = RawMatch(
            rule=rule,
            value=match.value,
            line=1,
            column=1,
            end_line=1,
            end_column=2,
            start_offset=0,
            end_offset=1,
            entropy=4.0,
            matched_keywords=("api_key",),
        )

        assert match.confidence() is Confidence.PROBABLE

    def test_an_exact_rule_is_already_at_the_ceiling_and_cannot_be_raised(self) -> None:
        """There is nowhere above HIGH_CONFIDENCE except VERIFIED, which is
        unreachable by design. Context must not buy a false promotion."""

        rule = make_rule(specificity=Specificity.EXACT)
        match = make_match(rule=rule)
        match = RawMatch(
            rule=rule,
            value=match.value,
            line=1,
            column=1,
            end_line=1,
            end_column=2,
            start_offset=0,
            end_offset=1,
            entropy=4.0,
            matched_keywords=("api_key",),
            assignment_name="API_KEY",
        )

        assert match.confidence() is Confidence.HIGH_CONFIDENCE
        assert match.confidence() is not Confidence.VERIFIED

    def test_a_heuristic_rule_without_evidence_stays_at_its_floor(self) -> None:
        rule = make_rule(
            specificity=Specificity.HEURISTIC, base_confidence=Confidence.CANDIDATE
        )
        match = make_match(rule=rule)
        match = RawMatch(
            rule=rule,
            value=match.value,
            line=1,
            column=1,
            end_line=1,
            end_column=2,
            start_offset=0,
            end_offset=1,
            entropy=4.0,
        )

        assert match.confidence() is Confidence.CANDIDATE

    def test_an_assignment_name_alone_is_enough_evidence(self) -> None:
        rule = make_rule(
            specificity=Specificity.HEURISTIC, base_confidence=Confidence.CANDIDATE
        )
        match = make_match(rule=rule)
        match = RawMatch(
            rule=rule,
            value=match.value,
            line=1,
            column=1,
            end_line=1,
            end_column=2,
            start_offset=0,
            end_offset=1,
            entropy=4.0,
            assignment_name="DB_PASSWORD",
        )

        assert match.confidence() is Confidence.PROBABLE


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


class TestFindMatches:
    def test_a_rule_that_matches_produces_one_raw_match(self) -> None:
        matches = find_matches(
            'key = "SYNTH-deadbeef"', registry=_registry(make_rule())
        )

        assert [m.value for m in matches] == ["SYNTH-deadbeef"]

    def test_positions_are_one_based(self) -> None:
        text = 'key = "SYNTH-deadbeef"'
        matches = find_matches(text, registry=_registry(make_rule()))

        assert (matches[0].line, matches[0].column) == (1, text.index("SYNTH") + 1)

    def test_positions_are_correct_on_a_later_line(self) -> None:
        line = "third = SYNTH-deadbeef"
        matches = find_matches(
            f"first line\nsecond\n{line}\n", registry=_registry(make_rule())
        )

        assert matches[0].line == 3
        assert matches[0].column == line.index("SYNTH") + 1

    def test_positions_are_correct_after_a_blank_line(self) -> None:
        text = "\n\n\nvalue SYNTH-deadbeef"
        matches = find_matches(text, registry=_registry(make_rule()))

        assert matches[0].line == 4
        assert matches[0].column == 7

    def test_offsets_index_the_original_text(self) -> None:
        text = 'key = "SYNTH-deadbeef"'
        matches = find_matches(text, registry=_registry(make_rule()))
        start, end = matches[0].span

        assert text[start:end] == "SYNTH-deadbeef"

    def test_the_named_group_becomes_the_value_not_the_whole_match(self) -> None:
        rule = make_rule(pattern=r"password=(?P<secret>\w+)")
        matches = find_matches("password=SYNTHpw9Z", registry=_registry(rule))

        assert [m.value for m in matches] == ["SYNTHpw9Z"]

    def test_an_empty_match_is_discarded(self) -> None:
        rule = make_rule(pattern=r"empty=(?P<secret>\w*)")
        matches = find_matches("empty=", registry=_registry(rule))

        assert matches == []

    def test_an_oversized_match_is_discarded(self) -> None:
        """A rule that can match the rest of the file is an authoring bug, and is
        bounded rather than reported as a multi-megabyte finding."""

        rule = make_rule(pattern=r"(?P<secret>[a-z0-9]{%d})" % (MAX_MATCH_LENGTH + 10))
        matches = find_matches("x" * (MAX_MATCH_LENGTH + 50), registry=_registry(rule))

        assert matches == []

    def test_max_length_bounds_a_match(self) -> None:
        rule = make_rule(pattern=r"(?P<secret>[a-z0-9]+)", max_length=8)
        registry = _registry(rule)

        assert find_matches("zzz9x8y7w6vu5t", registry=registry) == []
        assert len(find_matches("zzz9x8y7", registry=registry)) == 1

    def test_an_entropy_floor_discards_a_low_entropy_match(self) -> None:
        rule = make_rule(pattern=r"(?P<secret>[a-z0-9]+)", min_entropy=3.0)
        registry = _registry(rule)

        assert find_matches("aaaaaaaaaaaa", registry=registry) == []
        assert len(find_matches("ab3d5f7h9j", registry=registry)) == 1

    def test_a_template_expression_is_discarded(self) -> None:
        rule = make_rule(pattern=r"key=(?P<secret>[^\s]+)")
        matches = find_matches("key=${SYNTH_VAR}", registry=_registry(rule))

        assert matches == []

    def test_a_placeholder_is_discarded(self) -> None:
        rule = make_rule(pattern=r"key=(?P<secret>[^\s]+)")
        matches = find_matches("key=example-example-example", registry=_registry(rule))

        assert matches == []

    def test_rule_specific_placeholders_are_honoured(self) -> None:
        rule = make_rule(pattern=r"key=(?P<secret>[^\s]+)", placeholders=("SYNTHVED",))
        registry = _registry(rule)

        assert find_matches("key=SYNTHVEDabc123", registry=registry) == []
        assert len(find_matches("key=SYNTHOTHabc123", registry=registry)) == 1

    def test_placeholder_suppression_can_be_disabled_per_rule(self) -> None:
        """``sk_test_`` contains ``test``, which is a placeholder word and also
        part of a vendor prefix. A rule that has already established what the
        value is must not be silenced by a marker inside it."""

        rule = make_rule(
            pattern=r"(?P<secret>sk_test_[A-Za-z0-9]{16,})", suppress_placeholders=False
        )

        assert (
            len(find_matches("sk_test_" + "aB3dE5fG7hJ9kL1m", registry=_registry(rule)))
            == 1
        )

    def test_repetitive_structure_is_discarded(self) -> None:
        rule = make_rule(pattern=r"key=(?P<secret>[A-Za-z0-9]+)")
        registry = _registry(rule)

        # Two identical halves: 18 characters, no information beyond 3.
        assert find_matches("key=abcabcabcabcabcabc", registry=registry) == []
        assert len(find_matches("key=ab3d5f7h9j", registry=registry)) == 1

    def test_hashes_are_only_discarded_when_a_rule_opts_in(self) -> None:
        """A 32-character hex value is a checksum far more often than a secret,
        but only a rule's owner knows which, so the default is to keep it."""

        value = "a3f5c9e17b2d4806be35f1c8a07d29e4"
        permissive = make_rule(pattern=r"(?P<secret>[a-f0-9]{32})")
        strict = make_rule(pattern=r"(?P<secret>[a-f0-9]{32})", reject_hashes=True)

        assert len(find_matches(value, registry=_registry(permissive))) == 1
        assert find_matches(value, registry=_registry(strict)) == []

    def test_mandatory_context_discards_a_match_without_a_keyword(self) -> None:
        """A bare 40-character base64 string is not an AWS secret key."""

        rule = make_rule(
            pattern=r"(?P<secret>[A-Za-z0-9]{40})",
            keywords=("aws_secret_access_key",),
            requires_context=True,
            specificity=Specificity.HEURISTIC,
        )
        registry = _registry(rule)
        value = "SYNTH7cK2mQ9wR4tB8nL3vH6jF0dS5gX1aC2eR4z"

        assert find_matches(value, registry=registry) == []
        assert (
            len(find_matches(f'aws_secret_access_key = "{value}"', registry=registry))
            == 1
        )

    def test_context_is_recorded_as_matched_keywords(self) -> None:
        rule = make_rule(
            pattern=r"(?P<secret>[A-Za-z0-9]{40})",
            keywords=("aws_secret_access_key", "aws_secret"),
            requires_context=True,
            specificity=Specificity.HEURISTIC,
        )
        matches = find_matches(
            'AWS_SECRET_ACCESS_KEY = "SYNTH7cK2mQ9wR4tB8nL3vH6jF0dS5gX1aC2eR4z"',
            registry=_registry(rule),
        )

        assert "aws_secret_access_key" in matches[0].matched_keywords

    def test_an_assignment_name_is_captured(self) -> None:
        matches = find_matches(
            'DB_PASSWORD = "SYNTH-deadbeef"', registry=_registry(make_rule())
        )

        assert matches[0].assignment_name == "DB_PASSWORD"

    def test_a_keyword_on_the_line_does_not_require_an_assignment(self) -> None:
        rule = make_rule(pattern=r"SYNTH-(?P<secret>[0-9a-f]{8})")
        matches = find_matches(
            "the api_key SYNTH-deadbeef above", registry=_registry(rule)
        )

        assert matches[0].assignment_name is None

    def test_an_assignment_name_is_read_through_an_opening_quote(self) -> None:
        """A quoted value is the commonest case, and it is the one a naive
        prefix match fails on: the text before the value ends in ``= "``."""

        rule = make_rule()
        text = 'DB_PASSWORD = "SYNTH-deadbeef"'
        matches = find_matches(text, registry=_registry(rule))

        assert matches[0].assignment_name == "DB_PASSWORD"

    def test_results_are_ordered_by_rule_priority_then_offset(self) -> None:
        """All of one rule's matches, then all of the next, regardless of
        which rule saw which byte first."""

        registry = _registry(
            make_rule(id="beta", pattern=r"SYNTH-(?P<secret>[a-f0-9]{8})", priority=20),
            make_rule(id="alpha", pattern=r"(?P<secret>[a-f0-9]{8})", priority=10),
        )
        matches = find_matches("SYNTH-deadbeef SYNTH-cafebabe", registry=registry)

        assert [m.id for m in matches] == ["alpha", "alpha", "beta", "beta"]
        assert [m.start_offset for m in matches] == [6, 21, 0, 15]

    def test_repeated_runs_are_identical(self) -> None:
        text = 'a = "SYNTH-deadbeef"\nb = "SYNTH-cafebabe"\n'
        registry = _registry(make_rule())

        first = [
            (m.id, m.line, m.column, m.value)
            for m in find_matches(text, registry=registry)
        ]
        second = [
            (m.id, m.line, m.column, m.value)
            for m in find_matches(text, registry=registry)
        ]

        assert first == second

    def test_no_raw_value_survives_into_the_returned_findings(self) -> None:
        value = "SYNTH7cK2mQ9wR4tB8nL3vH6jF0dS5gX1aC2eR4z"
        findings = findings_from(
            find_matches(f'aws_secret_access_key = "{value}"'), "x.py"
        )

        assert value not in repr(findings)

    def test_an_empty_text_yields_nothing(self) -> None:
        assert find_matches("", registry=_registry(make_rule())) == []

    def test_a_registry_with_no_rules_yields_nothing(self) -> None:
        assert find_matches("SYNTH-deadbeef", registry=DetectorRegistry()) == []

    def test_non_string_input_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="expects str"):
            find_matches(b"bytes are not str")  # type: ignore[arg-type]


class TestFindingsFrom:
    def test_each_match_becomes_one_finding(self) -> None:
        registry = _registry(make_rule())
        matches = find_matches('a = "SYNTH-deadbeef"', registry=registry)

        assert len(findings_from(matches, "f.py")) == 1

    def test_the_path_reaches_every_finding(self) -> None:
        registry = _registry(make_rule())
        findings = findings_from(
            find_matches('a = "SYNTH-deadbeef"', registry=registry), "a/b.py"
        )

        assert findings[0].location.path == "a/b.py"

    def test_an_identical_rule_and_span_is_reported_once(self) -> None:
        rule = make_rule()
        match = make_match(rule=rule)

        assert len(findings_from([match, match], "f.py")) == 1

    def test_the_same_span_from_different_rules_is_not_deduplicated(self) -> None:
        """Two rules seeing one span is fusion's problem, and fusion is deferred.

        Collapsing them here would silently discard whichever rule sorted later,
        which loses a severity and a remediation with no record of the decision.
        """

        first = make_match(rule=make_rule(id="rule-one"))
        second = make_match(rule=make_rule(id="rule-two"))

        assert len(findings_from([first, second], "f.py")) == 2

    def test_findings_are_deterministic(self) -> None:
        registry = _registry(make_rule())
        matches = find_matches(
            'a = "SYNTH-deadbeef"\nb = "SYNTH-cafebabe"', registry=registry
        )

        assert repr(findings_from(matches, "f.py")) == repr(
            findings_from(matches, "f.py")
        )

    def test_no_findings_produce_an_empty_tuple(self) -> None:
        assert findings_from([], "f.py") == ()


def _registry(*rules: Rule) -> DetectorRegistry:
    """Build a registry from rules, for tests that must not touch the catalog."""

    return DetectorRegistry(rules)
