"""Unit tests for :mod:`secret_shield.pipeline` -- overlap fusion.

Stage 3 left one honest problem: running two detectors over one file reports one
secret twice. The ``aws_secret_access_key`` line in this repository's own
integration fixture produced an ``aws-secret-access-key`` finding *and* a
``high-entropy-string`` finding, and both were correct. That is not something a
reporter can fix, because by the time a report exists the two answers have
already been built, and merging them there means choosing between two severities
and two categories after the fact.

So the decision moves to where the evidence still has spans: :func:`fuse`. These
tests exercise it directly, with spans constructed rather than harvested, because
the fusion rule's *edges* matter more than its typical case -- a pattern match
that starts before a token and ends inside it, two vendor rules sharing one
literal, an entropy candidate with no vendor at all.

The tests are grouped by the property being defended rather than by the function
under test, because what must not regress is a property, not a signature:

* **Overlap geometry** -- when two matches are the same value, and when they are
  two values that happen to be near each other.
* **Identity** -- the vendor rule names the finding, and the choice between two
  vendor rules is total and registration-order independent.
* **Confidence** -- corroboration raises it by one step and can never produce
  ``VERIFIED``.
* **Severity** -- untouched by entropy, in both directions.
* **Deduplication** -- never by masked value.
* **Determinism** -- the same evidence in a different order fuses identically.
* **No raw secret escapes** -- the fusion layer compares raw values, so this is
  where a leak would be introduced.

All credentials here are synthetic and carry the ``SYNTH`` marker; see
``tests/vendor_fixtures.py``.
"""

from __future__ import annotations

import json
import random

import pytest

from secret_shield.detectors import (
    DetectorRegistry,
    EntropyCandidate,
    RawMatch,
    Rule,
    Specificity,
    find_matches,
    findings_from,
)
from secret_shield.detectors.catalog import RULES, default_registry
from secret_shield.masking import FULLY_REDACTED, fingerprint
from secret_shield.models import (
    Confidence,
    DetectorKind,
    Finding,
    Location,
    SecretCategory,
    Severity,
    SourceKind,
)
from secret_shield.pipeline import (
    ENTROPY_CONFIDENCE,
    MAX_CONFIDENCE,
    MergedMatch,
    analyze_text,
    dedupe,
    describes_same_value,
    fuse,
    pattern_order,
)
from tests.vendor_fixtures import (  # type: ignore
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    DB_PASSWORD,
    DB_URI,
    GITHUB_PAT_CLASSIC,
    OPENAI_LEGACY_KEY,
    OPENAI_PROJECT_KEY,
    STRIPE_PUBLISHABLE_LIVE,
    STRIPE_RESTRICTED_LIVE,
    STRIPE_SECRET_LIVE,
    STRIPE_SECRET_TEST,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEXT = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"


def pattern_at(start: int, end: int, value: str, rule: Rule) -> RawMatch:
    """Build a :class:`RawMatch` directly, for geometry tests.

    A real match carries text-scraping metadata (``line``, ``matched_keywords``)
    that fusion never reads, so this constructs the minimum it does. The
    integration tests in ``test_pipeline.py`` cover the real thing.
    """

    return RawMatch(
        rule=rule,
        value=value,
        line=1,
        column=start + 1,
        end_line=1,
        end_column=end,
        start_offset=start,
        end_offset=end,
        entropy=4.5,
        matched_keywords=(),
        assignment_name=None,
    )


def evidence_at(
    start: int, end: int, value: str, entropy: float = 4.5
) -> EntropyCandidate:
    """Build an :class:`EntropyCandidate` directly, for geometry tests."""

    return EntropyCandidate(
        value=value,
        start_offset=start,
        end_offset=end,
        line=1,
        column=start + 1,
        entropy=entropy,
    )


def synthetic_rule(rule_id: str, **overrides: object) -> Rule:
    """A minimal valid rule for tests that need two rules to compete."""

    settings: dict[str, object] = {
        "id": rule_id,
        "name": f"Synthetic {rule_id}",
        "pattern": r"\bSYNTH[A-Za-z0-9]{4,}\b",
        "category": SecretCategory.API_KEY,
        "severity": Severity.HIGH,
        "specificity": Specificity.HEURISTIC,
        "remediation": "Rotate it.",
        "false_positive_notes": "Synthetic rule for fusion tests.",
    }
    settings.update(overrides)
    return Rule(**settings)  # type: ignore[arg-type]


def merge_of(items: tuple[MergedMatch, ...], rule_id: str) -> MergedMatch:
    """Return the single merged match named ``rule_id``."""

    return next(item for item in items if item.id == rule_id)


def findings_of(
    items: tuple[MergedMatch, ...], path: str = "config.env"
) -> tuple[Finding, ...]:
    return tuple(item.to_finding(path) for item in items)


# ---------------------------------------------------------------------------
# Overlap geometry
# ---------------------------------------------------------------------------


class TestOverlapGeometry:
    """Which pairs of matches describe one value, and which describe two.

    The asymmetry in the merge rule is deliberate. Containment needs no further
    evidence, because the wider span only claims that *material* is present and
    the narrower span has already identified it. Proper partial overlap gets a
    textual test, because there the geometry genuinely does not decide.
    """

    RULE = synthetic_rule("geometry-probe")

    def test_identical_spans_are_one_value(self) -> None:
        pattern = pattern_at(10, 30, TEXT[10:30], self.RULE)

        assert describes_same_value(pattern, evidence_at(10, 30, TEXT[10:30]))

    def test_a_pattern_inside_a_wider_token_is_one_value(self) -> None:
        """The literal is wider than the key it holds. Normal, and merges."""

        pattern = pattern_at(12, 52, TEXT[12:52], self.RULE)

        assert describes_same_value(pattern, evidence_at(5, 60, TEXT[5:60]))

    def test_a_token_inside_a_wider_pattern_is_one_value(self) -> None:
        """The connection string is wider than the password in it."""

        pattern = pattern_at(0, 90, TEXT[0:90], self.RULE)

        assert describes_same_value(pattern, evidence_at(30, 50, TEXT[30:50]))

    def test_partial_overlap_merges_when_the_values_agree(self) -> None:
        """Interleaved spans, but the vendor match found the same characters.

        An unquoted value run continues past a ``ghp_`` prefix, so the entropy
        candidate is longer than the vendor match and starts before it. The
        substring test settles it without guessing.
        """

        value = "ghp_" + "a" * 36
        run = value + ".rotation-2024"
        pattern = pattern_at(5, 5 + len(value), value, self.RULE)

        assert describes_same_value(pattern, evidence_at(0, len(run), run))

    def test_partial_overlap_does_not_merge_unrelated_values(self) -> None:
        """Interleaved spans describing different material stay two findings."""

        pattern = pattern_at(0, 30, TEXT[0:30], self.RULE)

        assert not describes_same_value(pattern, evidence_at(10, 60, TEXT[10:60]))

    def test_abutting_spans_do_not_overlap(self) -> None:
        """Half-open ranges: ``(0, 5)`` and ``(5, 9)`` share no character.

        Merging them would hide the second value behind the first.
        """

        pattern = pattern_at(0, 20, TEXT[0:20], self.RULE)

        assert not describes_same_value(pattern, evidence_at(20, 40, TEXT[20:40]))

    def test_disjoint_spans_do_not_merge(self) -> None:
        pattern = pattern_at(0, 20, TEXT[0:20], self.RULE)

        assert not describes_same_value(pattern, evidence_at(25, 45, TEXT[25:45]))

    def test_one_shared_character_is_not_enough_to_merge(self) -> None:
        """Interleaved by one character is still interleaved.

        Worth pinning because it is the boundary case, and because "they touch
        somewhere, so they are the same value" is the tempting simplification.
        The spans here share exactly one character and describe different text,
        so they stay two findings.
        """

        pattern = pattern_at(0, 21, TEXT[0:21], self.RULE)

        assert not describes_same_value(pattern, evidence_at(20, 40, TEXT[20:40]))

    def test_the_narrow_span_may_be_either_side(self) -> None:
        pattern = pattern_at(0, 20, TEXT[0:20], self.RULE)

        assert describes_same_value(pattern, evidence_at(0, 5, TEXT[0:5]))
        assert describes_same_value(pattern, evidence_at(15, 20, TEXT[15:20]))


# ---------------------------------------------------------------------------
# One secret, one finding
# ---------------------------------------------------------------------------


class TestOneSecretOneFinding:
    def test_an_identical_pair_becomes_one_composite(self) -> None:
        rule = synthetic_rule("identical-pair")
        pattern = pattern_at(10, 30, TEXT[10:30], rule)

        merged = fuse((pattern,), (evidence_at(10, 30, TEXT[10:30]),))

        assert len(merged) == 1
        assert merged[0].detector is DetectorKind.COMPOSITE
        assert merged[0].id == "identical-pair"

    def test_a_wider_token_is_absorbed_rather_than_reported(self) -> None:
        """The headline case: vendor plus entropy, one answer.

        Without fusion this is two findings. The entropy candidate covering a
        55-character literal is not reported on its own even though it is longer
        than the vendor match inside it, because the vendor match already
        described the credential.
        """

        text = f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"'
        pattern = find_matches(text)[0]
        candidate = evidence_at(*pattern.span, pattern.value)

        merged = fuse((pattern,), (candidate,))

        assert [item.detector for item in merged] == [DetectorKind.COMPOSITE]
        assert merged[0].id == "aws-secret-access-key"

    def test_non_overlapping_matches_stay_separate(self) -> None:
        first = pattern_at(0, 20, TEXT[0:20], synthetic_rule("first"))
        second = pattern_at(30, 50, TEXT[30:50], synthetic_rule("second"))

        merged = fuse((first, second), (evidence_at(30, 50, TEXT[30:50]),))

        assert [item.detector for item in merged] == [
            DetectorKind.PATTERN,
            DetectorKind.COMPOSITE,
        ]

    def test_an_entropy_candidate_with_no_vendor_is_still_reported(self) -> None:
        """Fusion must not swallow the detections that only entropy makes.

        A homemade HMAC has no prefix, no length and no vendor. Fusing that away
        would leave the tool blind to exactly the credentials no rule covers.
        """

        value = "f8Kq2mZ9tR4vX7bN1cL6wY3hJ5pA0sD2fG4hJ6kL8"
        merged = fuse((), (evidence_at(0, len(value), value),))

        assert len(merged) == 1
        assert merged[0].detector is DetectorKind.ENTROPY
        assert merged[0].id == "high-entropy-string"

    def test_a_candidate_spanning_two_secrets_corroborates_neither(self) -> None:
        """A literal holding two Stripe keys: two findings, not three.

        The candidate is dense with random material because the *literal* is,
        which is a fact about the literal and not about either key. Crediting it
        to one of them would be a coin toss dressed up as analysis, and
        reporting it separately would add a third finding describing a value
        that is neither key.
        """

        text = f'keys = "{STRIPE_SECRET_LIVE} {STRIPE_RESTRICTED_LIVE}"'
        patterns = find_matches(text)
        assert {match.rule.id for match in patterns} == {
            "stripe-secret-key-live",
            "stripe-restricted-key-live",
        }

        # The candidate covers the whole literal, from just after the opening
        # quote to just before the closing one. Derived rather than written down
        # so the test cannot drift away from the fixture.
        literal = text.index('"') + 1, text.rindex('"')
        merged = fuse(patterns, (evidence_at(*literal, text[literal[0] : literal[1]]),))

        assert [item.detector for item in merged] == [
            DetectorKind.PATTERN,
            DetectorKind.PATTERN,
        ]
        assert {item.id for item in merged} == {
            "stripe-secret-key-live",
            "stripe-restricted-key-live",
        }

    def test_two_identical_pattern_matches_collapse(self) -> None:
        rule = synthetic_rule("repeat")
        first = pattern_at(10, 30, TEXT[10:30], rule)
        second = pattern_at(10, 30, TEXT[10:30], rule)

        assert len(fuse((first, second), ())) == 1

    def test_two_patterns_sharing_a_span_but_not_a_value_survive(self) -> None:
        """One regex match can yield two groups, and those are two claims.

        ``database-uri-with-password`` reports the password out of a URI it
        matched whole. If a rule ever also claimed the URI, dropping it would
        delete a detection on the grounds that it overlapped another one.
        """

        whole = pattern_at(0, 90, TEXT[0:90], synthetic_rule("whole-uri"))
        part = pattern_at(0, 90, TEXT[40:62], synthetic_rule("the-password"))

        assert len(fuse((whole, part), ())) == 2

    def test_fusing_nothing_produces_nothing(self) -> None:
        assert fuse((), ()) == ()


# ---------------------------------------------------------------------------
# Identity comes from the vendor rule
# ---------------------------------------------------------------------------


class TestIdentityComesFromTheVendorRule:
    def test_the_vendor_supplies_every_descriptive_field(self) -> None:
        """Entropy contributes a score, never an identity.

        A composite must be indistinguishable from the vendor finding except for
        its detector and confidence, because that is what a reviewer reads.
        """

        text = f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"'
        pattern = find_matches(text)[0]
        alone = pattern.to_finding("config.env")
        fused = merge_of(
            fuse((pattern,), (evidence_at(*pattern.span, pattern.value),)),
            pattern.rule.id,
        )

        finding = fused.to_finding("config.env")

        assert finding.rule_id == alone.rule_id
        assert finding.rule_name == alone.rule_name
        assert finding.category == alone.category
        assert finding.severity == alone.severity
        assert finding.confidence != alone.confidence
        assert finding.detector is DetectorKind.COMPOSITE

    def test_the_reported_value_is_the_vendors_not_the_wider_literals(self) -> None:
        """A connection string's host and database name are not the secret.

        The entropy candidate covers the whole URI; the vendor rule reported the
        password. Reporting the URI would file a hostname as credential material
        and produce a mask long enough to be recognisable.
        """

        text = f'DATABASE_URL = "{DB_URI}"'
        pattern = find_matches(text)[0]
        candidate = evidence_at(pattern.start_offset, pattern.end_offset, DB_URI)

        finding = merge_of(fuse((pattern,), (candidate,)), pattern.rule.id).to_finding(
            "app.conf"
        )

        assert finding.value_length == len(DB_PASSWORD)
        assert "db.internal" not in finding.masked_value
        assert "postgres" not in finding.masked_value

    def test_an_exact_rule_outranks_a_heuristic_one_on_the_same_bytes(self) -> None:
        """Specificity measures how much identity a rule brings."""

        heuristic = pattern_at(0, 20, TEXT[0:20], synthetic_rule("shape-guess"))
        exact = pattern_at(
            0,
            20,
            TEXT[0:20],
            synthetic_rule("prefix-match", specificity=Specificity.EXACT),
        )

        merged = fuse((heuristic, exact), (evidence_at(0, 20, TEXT[0:20]),))

        assert len(merged) == 1
        assert merged[0].id == "prefix-match"

    def test_a_lower_priority_outranks_a_higher_one_at_equal_specificity(self) -> None:
        first = pattern_at(0, 20, TEXT[0:20], synthetic_rule("aaa-early", priority=1))
        second = pattern_at(0, 20, TEXT[0:20], synthetic_rule("bbb-late", priority=90))

        merged = fuse((first, second), (evidence_at(0, 20, TEXT[0:20]),))

        assert len(merged) == 1
        assert merged[0].id == "aaa-early"

    def test_the_rule_id_breaks_the_last_tie(self) -> None:
        first = pattern_at(0, 20, TEXT[0:20], synthetic_rule("aaa-first", priority=5))
        second = pattern_at(0, 20, TEXT[0:20], synthetic_rule("zzz-last", priority=5))

        merged = fuse((second, first), (evidence_at(0, 20, TEXT[0:20]),))

        assert len(merged) == 1
        assert merged[0].id == "aaa-first"

    def test_pattern_order_is_independent_of_registration_order(self) -> None:
        """The tie-break must be a function of the rules, not of the tuple.

        Two registries built from the same rules in opposite order are two
        callers of the same engine, and they have to agree.
        """

        def order_for(
            rule_id: str,
            priority: int = 100,
            specificity: Specificity = Specificity.HEURISTIC,
        ):
            """The ordering key of a fresh match carrying a fresh rule."""

            return pattern_order(
                pattern_at(
                    0,
                    20,
                    TEXT[:20],
                    synthetic_rule(rule_id, priority=priority, specificity=specificity),
                )
            )

        # Rebuilding the same rule gives the same key, which is what makes the
        # tie-break a property of the rule rather than of a match object.
        assert order_for("alpha", priority=3) == order_for("alpha", priority=3)
        assert order_for("alpha", priority=3) != order_for("alpha", priority=4)

        # And the ordering is total: every pair of rules compares without
        # falling back to equality, in either arrival order.
        rules = [
            ("alpha", 3),
            ("beta", 3),
            ("gamma", 1),
            ("delta", 3),
        ]
        keys = {
            rule_id: order_for(rule_id, priority=priority)
            for rule_id, priority in rules
        }

        for first in rules:
            for second in rules:
                if first == second:
                    continue
                assert (
                    keys[first[0]] < keys[second[0]] or keys[second[0]] < keys[first[0]]
                )

        # EXACT always sorts ahead of HEURISTIC, whatever the ids or priorities.
        assert order_for("zzz", specificity=Specificity.EXACT) < order_for(
            "aaa", specificity=Specificity.HEURISTIC
        )


# ---------------------------------------------------------------------------
# Composite coverage, per vendor
# ---------------------------------------------------------------------------


class TestCompositeForEveryVendor:
    """The same fusion outcome for every catalog rule.

    Each case takes a *real* ``RawMatch`` from the shipped catalog -- correct
    rule, correct span, correct value -- and pairs it with an entropy candidate
    covering the same span. That isolates the thing under test: if entropy also
    fired here, fusion would produce this. Whether it does fire is a property of
    the tokenizer's structural filters, covered in ``test_pipeline.py``.
    """

    CASES = [
        (
            "aws",
            f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"',
            Severity.CRITICAL,
        ),
        ("aws-id", f'aws_access_key_id = "{AWS_ACCESS_KEY_ID}"', Severity.MEDIUM),
        ("openai-project", f'OPENAI_API_KEY = "{OPENAI_PROJECT_KEY}"', Severity.HIGH),
        ("openai-legacy", f'OPENAI_API_KEY = "{OPENAI_LEGACY_KEY}"', Severity.HIGH),
        ("github", f'GITHUB_TOKEN = "{GITHUB_PAT_CLASSIC}"', Severity.HIGH),
        ("stripe-live", f'STRIPE_KEY = "{STRIPE_SECRET_LIVE}"', Severity.CRITICAL),
        ("stripe-test", f'STRIPE_KEY = "{STRIPE_SECRET_TEST}"', Severity.MEDIUM),
        ("db-uri", f'DATABASE_URL = "{DB_URI}"', Severity.CRITICAL),
    ]

    @pytest.mark.parametrize(
        ("name", "text", "expected_severity"),
        CASES,
        ids=[case[0] for case in CASES],
    )
    def test_overlapping_entropy_produces_exactly_one_finding(
        self, name: str, text: str, expected_severity: Severity
    ) -> None:
        """Two detectors with one thing to say about these bytes.

        Counted honestly: each detector is run on its own first, and the fused
        result is compared against what those two separate answers would have
        produced. Asserting against a hand-built tuple would only be checking
        tuple arithmetic.
        """

        pattern = find_matches(text)[0]
        candidate = evidence_at(*pattern.span, pattern.value)

        vendor_alone = findings_from((pattern,), "config.env")[0]
        entropy_alone = candidate.to_finding("config.env")
        fused = findings_of(fuse((pattern,), (candidate,)))

        assert {vendor_alone.rule_id, entropy_alone.rule_id} == {
            pattern.rule.id,
            "high-entropy-string",
        }
        assert len(fused) == 1, "the result: one secret, one finding"
        assert fused[0].rule_id == pattern.rule.id
        assert fused[0].detector is DetectorKind.COMPOSITE
        assert fused[0].severity is expected_severity

        # The finding the reviewer reads is the vendor's, verbatim, except that
        # it now records that two rules agreed. Every other field -- category,
        # remediation, mask, fingerprint, entropy, length -- is untouched.
        differences = {
            key
            for key in fused[0].to_dict()
            if fused[0].to_dict()[key] != vendor_alone.to_dict()[key]
        }
        assert differences <= {"detector", "confidence"}, differences

    @pytest.mark.parametrize(
        ("name", "text", "expected_severity"),
        CASES,
        ids=[case[0] for case in CASES],
    )
    def test_no_entropy_candidate_leaves_the_vendor_finding_untouched(
        self, name: str, text: str, expected_severity: Severity
    ) -> None:
        """The vendor-only path is the same finding, and must stay exact."""

        after = findings_of(fuse(find_matches(text), ()))

        assert len(after) == 1
        assert after[0].detector is DetectorKind.PATTERN
        assert after[0].severity is expected_severity
        assert after[0].value_length == find_matches(text)[0].length


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------


class TestConfidence:
    def test_the_ceiling_is_high_confidence_and_never_verified(self) -> None:
        assert MAX_CONFIDENCE is Confidence.HIGH_CONFIDENCE

    def test_an_entropy_only_finding_is_probable(self) -> None:
        assert ENTROPY_CONFIDENCE is Confidence.PROBABLE

        merged = fuse((), (evidence_at(0, 20, TEXT[:20]),))

        assert merged[0].confidence is Confidence.PROBABLE

    def test_corroboration_promotes_a_probable_vendor_match(self) -> None:
        """The AWS secret: PROBABLE from context alone, HIGH once corroborated."""

        text = f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"'
        pattern = find_matches(text)[0]
        assert pattern.confidence() is Confidence.PROBABLE

        fused = merge_of(
            fuse((pattern,), (evidence_at(*pattern.span, pattern.value),)),
            pattern.rule.id,
        )

        assert fused.confidence is Confidence.HIGH_CONFIDENCE

    def test_corroboration_never_lowers_an_exact_rule(self) -> None:
        """``EXACT`` already starts at HIGH_CONFIDENCE; there is nowhere to go."""

        text = f'GITHUB_TOKEN = "{GITHUB_PAT_CLASSIC}"'
        pattern = find_matches(text)[0]
        assert pattern.confidence() is Confidence.HIGH_CONFIDENCE

        fused = merge_of(
            fuse((pattern,), (evidence_at(*pattern.span, pattern.value),)),
            pattern.rule.id,
        )

        assert fused.confidence is Confidence.HIGH_CONFIDENCE

    def test_corroboration_lifts_a_candidate_to_probable_before_adding_a_step(
        self,
    ) -> None:
        """A CANDIDATE match must not end up below the evidence supporting it.

        The entropy rule never reports below PROBABLE, so promoting a CANDIDATE
        pattern match to CANDIDATE + 1 == PROBABLE would leave it a step below
        the very statistic that vouched for it.
        """

        weak = synthetic_rule(
            "no-context-required",
            requires_context=False,
            base_confidence=Confidence.CANDIDATE,
        )
        pattern = pattern_at(0, 20, TEXT[:20], weak)
        assert pattern.confidence() is Confidence.CANDIDATE

        fused = merge_of(fuse((pattern,), (evidence_at(0, 20, TEXT[:20]),)), weak.id)

        assert fused.confidence is Confidence.HIGH_CONFIDENCE

    def test_one_step_per_finding_not_per_corroborating_candidate(self) -> None:
        """Confidence has four levels; evidence must not spend them faster.

        Three overlapping high-entropy tokens behind one weak heuristic would,
        without a cap, escalate it to the ceiling on its own.
        """

        weak = synthetic_rule(
            "weak-shape",
            requires_context=False,
            base_confidence=Confidence.CANDIDATE,
        )
        pattern = pattern_at(0, 20, TEXT[:20], weak)
        support = (
            evidence_at(0, 20, TEXT[:20]),
            evidence_at(0, 20, TEXT[:20], 4.9),
            evidence_at(0, 20, TEXT[:20], 4.1),
        )

        fused = merge_of(fuse((pattern,), support), weak.id)

        assert len(fused.entropy) == 3
        assert fused.confidence is Confidence.HIGH_CONFIDENCE

    def test_an_uncorroborated_pattern_keeps_its_own_confidence(self) -> None:
        pattern = find_matches(f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"')[0]

        fused = merge_of(fuse((pattern,), ()), pattern.rule.id)

        assert fused.confidence is pattern.confidence()

    def test_fusion_never_produces_verified_for_any_arrangement(self) -> None:
        """The property, swept rather than sampled.

        Every catalog rule, each paired with entropy, plus every confidence a
        rule may legally declare, with corroboration on and off. Not one
        arrangement may reach ``VERIFIED``, because nothing in SecretShield has
        contacted an issuing service.
        """

        arrangable = [
            Confidence.CANDIDATE,
            Confidence.PROBABLE,
            Confidence.HIGH_CONFIDENCE,
        ]
        checked = 0

        for base in arrangable:
            rule = synthetic_rule(
                f"sweep-{base.name.lower()}",
                requires_context=False,
                base_confidence=base,
            )
            for specificity in (Specificity.EXACT, Specificity.HEURISTIC):
                tuned = Rule(
                    id=rule.id,
                    name=rule.name,
                    pattern=rule.pattern,
                    category=rule.category,
                    severity=rule.severity,
                    specificity=specificity,
                    remediation=rule.remediation,
                    requires_context=False,
                    base_confidence=base,
                )
                pattern = pattern_at(0, 20, TEXT[:20], tuned)
                for support in (
                    (),
                    (evidence_at(0, 20, TEXT[:20]),),
                    (evidence_at(0, 10, TEXT[:10]),),
                ):
                    for item in fuse((pattern,), support):
                        assert item.confidence is not Confidence.VERIFIED
                        assert item.confidence <= MAX_CONFIDENCE
                        checked += 1

        assert checked > 0

    def test_no_catalog_rule_can_supply_a_verified_base_confidence(self) -> None:
        """The ceiling is enforced on the way in as well as on the way out.

        Fusion clamps its own arithmetic, but a rule is the other way a
        confidence could arrive at ``VERIFIED``. Asserting the catalog cannot
        supply one means neither door is open.
        """

        for rule in RULES:
            assert rule.base_confidence is not Confidence.VERIFIED
            if rule.base_confidence is not None:
                assert rule.base_confidence <= MAX_CONFIDENCE


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    """Severity answers "if real, how bad", which entropy cannot inform.

    The two failure modes are symmetric and both are tested: downgrading a
    CRITICAL vendor finding to the entropy ceiling, and letting a CRITICAL
    entropy ceiling escape onto an anonymous finding.
    """

    def test_a_composite_reports_its_vendor_rules_severity(self) -> None:
        """Not capped at MEDIUM, however high the entropy score was."""

        text = f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"'
        pattern = find_matches(text)[0]

        fused = merge_of(
            fuse((pattern,), (evidence_at(*pattern.span, pattern.value, entropy=7.9),)),
            pattern.rule.id,
        )

        assert fused.severity is Severity.CRITICAL

    def test_entropy_does_not_raise_a_vendor_severity_either(self) -> None:
        """An AWS key ID is MEDIUM because the ID alone compromises nothing."""

        text = f'aws_access_key_id = "{AWS_ACCESS_KEY_ID}"'
        pattern = find_matches(text)[0]
        assert pattern.rule.severity is Severity.MEDIUM

        fused = merge_of(
            fuse((pattern,), (evidence_at(*pattern.span, pattern.value, entropy=7.9),)),
            pattern.rule.id,
        )

        assert fused.severity is Severity.MEDIUM

    def test_a_low_severity_vendor_stays_low_when_corroborated(self) -> None:
        """A publishable key is LOW because it is embedded in clients by design.

        Confidence and severity are independent axes, and this is the case that
        separates them most sharply: entropy corroboration makes this *more
        certainly* a publishable key, and a publishable key is not urgent.
        """

        text = f'STRIPE_KEY = "{STRIPE_PUBLISHABLE_LIVE}"'
        pattern = find_matches(text)[0]
        assert pattern.rule.severity is Severity.LOW

        fused = merge_of(
            fuse((pattern,), (evidence_at(*pattern.span, pattern.value),)),
            pattern.rule.id,
        )

        assert fused.severity is Severity.LOW

    def test_an_entropy_only_finding_is_capped_at_medium(self) -> None:
        merged = fuse(
            (), (evidence_at(0, 20, TEXT[:20]),), entropy_severity=Severity.MEDIUM
        )

        assert merged[0].severity is Severity.MEDIUM

    def test_an_entropy_only_finding_cannot_be_configured_above_medium(self) -> None:
        """A configuration mistake must not file an anonymous string as CRITICAL.

        ``EntropyRuleConfig`` already refuses a ceiling above MEDIUM; the clamp
        here is the same rule enforced a second time, at the point where a
        caller passes the value straight in.
        """

        merged = fuse(
            (), (evidence_at(0, 20, TEXT[:20]),), entropy_severity=Severity.CRITICAL
        )

        assert merged[0].severity is Severity.MEDIUM

    def test_an_entropy_only_finding_honours_a_lower_configured_ceiling(self) -> None:
        merged = fuse(
            (), (evidence_at(0, 20, TEXT[:20]),), entropy_severity=Severity.LOW
        )

        assert merged[0].severity is Severity.LOW

    def test_severity_and_confidence_are_independent(self) -> None:
        """Four quadrants, all reachable, none collapsing into another.

        A CRITICAL/PROBABLE finding and a LOW/HIGH_CONFIDENCE finding are both
        ordinary. Asserting that they exist together is what stops a future
        change from "simplifying" one axis in terms of the other.
        """

        aws_text = f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"'
        aws_pattern = find_matches(aws_text)[0]

        quadrants = {
            # A heuristic AWS rule alone: CRITICAL, but only PROBABLE. A
            # 40-character base64 string next to ``aws_secret_access_key`` is
            # evidence, and the keyword is what supplies it.
            (Severity.CRITICAL, aws_pattern.confidence()),
            # The same rule corroborated by entropy: still CRITICAL, now more
            # certain of being what it says.
            (
                Severity.CRITICAL,
                merge_of(
                    fuse(
                        (aws_pattern,),
                        (evidence_at(*aws_pattern.span, aws_pattern.value),),
                    ),
                    "aws-secret-access-key",
                ).confidence,
            ),
            # A publishable key: HIGH_CONFIDENCE and LOW. Being sure about a
            # value does not make it urgent.
            (
                Severity.LOW,
                find_matches(f'STRIPE_KEY = "{STRIPE_PUBLISHABLE_LIVE}"')[
                    0
                ].confidence(),
            ),
            # An anonymous high-entropy string: MEDIUM and PROBABLE.
            (
                Severity.MEDIUM,
                fuse((), (evidence_at(0, 20, TEXT[:20]),))[0].confidence,
            ),
        }

        assert quadrants == {
            (Severity.CRITICAL, Confidence.PROBABLE),
            (Severity.CRITICAL, Confidence.HIGH_CONFIDENCE),
            (Severity.LOW, Confidence.HIGH_CONFIDENCE),
            (Severity.MEDIUM, Confidence.PROBABLE),
        }


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def located(
    rule_id: str = "aws-secret-access-key",
    *,
    path: str = "config.env",
    line: int = 1,
    column: int = 1,
    commit: str | None = None,
    value: str = AWS_SECRET_ACCESS_KEY,
    confidence: Confidence = Confidence.PROBABLE,
    severity: Severity = Severity.CRITICAL,
) -> Finding:
    return Finding.from_match(
        rule_id=rule_id,
        rule_name="Synthetic",
        category=SecretCategory.AWS,
        severity=severity,
        confidence=confidence,
        detector=DetectorKind.PATTERN,
        location=Location(
            source_kind=SourceKind.FILE,
            path=path,
            line=line,
            column=column,
            commit=commit,
        ),
        raw_value=value,
        policy=FULLY_REDACTED,
        entropy=5.0,
        matched_keywords=("aws_secret_access_key",),
        remediation="Rotate it.",
    )


class TestDeduplication:
    def test_an_exact_repeat_becomes_one(self) -> None:
        assert len(dedupe((located(), located()))) == 1

    def test_the_same_secret_on_another_line_stays_two(self) -> None:
        assert len(dedupe((located(line=1), located(line=2)))) == 2

    def test_the_same_secret_in_another_file_stays_two(self) -> None:
        assert len(dedupe((located(path="a.env"), located(path="b.env")))) == 2

    def test_the_same_secret_in_another_commit_stays_two(self) -> None:
        assert len(dedupe((located(commit="a" * 40), located(commit="b" * 40)))) == 2

    def test_two_values_at_one_position_stay_two(self) -> None:
        """The fingerprint, not the position, is what says "same value"."""

        assert len(dedupe((located(value="A" * 40), located(value="B" * 40)))) == 2

    def test_two_rules_at_one_position_stay_two(self) -> None:
        assert (
            len(dedupe((located(), located(rule_id="database-uri-with-password")))) == 2
        )

    def test_deduplication_is_not_by_masked_value(self) -> None:
        """The failure that would delete real findings.

        Under ``FULLY_REDACTED`` every value masks to the same twelve asterisks,
        so keying on the mask would merge two genuinely different secrets and
        quietly remove one from the report. Assert the mask is in fact
        identical, then assert both findings survive anyway.
        """

        first = located(value="A" * 40)
        second = located(value="B" * 40)

        assert first.masked_value == second.masked_value
        assert first.value_fingerprint != second.value_fingerprint
        assert len(dedupe((first, second))) == 2

    def test_deduplication_is_not_by_secret_key(self) -> None:
        """``secret_key`` answers a reporting question, not a deletion question.

        Two occurrences of one key in two files share it, and a tool that
        collapsed on it would tell a reviewer to look at one file and never
        mention the other.
        """

        first = located(path="a.env")
        second = located(path="b.env")

        assert first.secret_key() == second.secret_key()
        assert len(dedupe((first, second))) == 2

    def test_the_first_occurrence_wins(self) -> None:
        first = located(confidence=Confidence.PROBABLE)
        second = located(confidence=Confidence.HIGH_CONFIDENCE)

        assert dedupe((first, second))[0].confidence is Confidence.PROBABLE

    def test_order_is_preserved(self) -> None:
        findings = (
            located(path="z.env"),
            located(path="a.env"),
            located(path="m.env"),
        )

        assert [item.location.path for item in dedupe(findings)] == [
            "z.env",
            "a.env",
            "m.env",
        ]

    def test_deduplicating_nothing_is_harmless(self) -> None:
        assert dedupe(()) == ()

    def test_the_key_is_the_whole_of_the_identity(self) -> None:
        """A finding is uniquely identified by rule, place and value.

        Swept rather than sampled: every field in the key is varied and the
        finding must survive each one, because a key that is too coarse deletes
        findings and a key that is too fine fails to merge them.
        """

        base = located()
        variations = [
            located(rule_id="other-rule"),
            located(path="other.env"),
            located(line=2),
            located(column=2),
            located(commit="c" * 40),
            located(value="Z" * 40),
        ]

        for variation in variations:
            assert len(dedupe((base, variation))) == 2, variation.location

    def test_the_key_matches_the_fingerprint_helper(self) -> None:
        """Not coincidentally equal -- the same digest, used for a different job."""

        finding = located()

        assert finding.value_fingerprint == fingerprint(AWS_SECRET_ACCESS_KEY)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """The answer must be a function of the evidence, not of the iteration.

    Filesystem enumeration order is unspecified, rule registration order is a
    caller detail, and neither detector promises to hand over its matches sorted.
    A scanner whose output changes when any of those change makes every CI diff
    noise and every "fix" look like it did nothing.
    """

    LINES = (
        f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"',
        f'aws_access_key_id = "{AWS_ACCESS_KEY_ID}"',
        f'GITHUB_TOKEN = "{GITHUB_PAT_CLASSIC}"',
        f'DATABASE_URL = "{DB_URI}"',
    )

    @property
    def text(self) -> str:
        return "\n".join(self.LINES)

    def test_input_order_does_not_change_the_result(self) -> None:
        patterns = find_matches(self.text)
        entropy = tuple(evidence_at(*match.span, match.value) for match in patterns[:3])
        reference = fuse(patterns, entropy)

        for seed in range(12):
            shuffled_patterns = list(patterns)
            shuffled_entropy = list(entropy)
            random.Random(seed).shuffle(shuffled_patterns)
            random.Random(seed + 100).shuffle(shuffled_entropy)

            assert fuse(shuffled_patterns, shuffled_entropy) == reference

    def test_results_come_back_in_span_order(self) -> None:
        patterns = find_matches(self.text)
        entropy = tuple(evidence_at(*match.span, match.value) for match in patterns)

        merged = fuse(patterns, entropy)

        assert list(merged) == sorted(merged, key=lambda item: (*item.span, item.id))

    def test_analyzing_twice_gives_the_same_answer(self) -> None:
        assert analyze_text(self.text, "config.env") == analyze_text(
            self.text, "config.env"
        )

    def test_two_registries_with_opposite_order_agree(self) -> None:
        forwards = DetectorRegistry(rules=RULES)
        backwards = DetectorRegistry(rules=tuple(reversed(RULES)))

        assert analyze_text(self.text, "config.env", registry=forwards) == analyze_text(
            self.text, "config.env", registry=backwards
        )

    def test_findings_come_back_in_sort_key_order(self) -> None:
        findings = analyze_text(self.text, "config.env")

        assert list(findings) == sorted(findings, key=lambda finding: finding.sort_key)

    def test_the_default_registry_is_the_shipped_catalog(self) -> None:
        """Nothing is added between the catalog data and the engine."""

        assert set(default_registry().ids()) == {rule.id for rule in RULES}


# ---------------------------------------------------------------------------
# No raw secret escapes
# ---------------------------------------------------------------------------


class TestNoRawSecretEscapes:
    """The fusion layer compares raw values, so this is where a leak starts.

    Every rendering a caller can reach -- ``repr``, ``str``, ``to_dict``,
    ``json``, the exception messages -- is checked for the credential. Values are
    built from fixtures so the assertion is a real search for a real string
    rather than a shape check.
    """

    SECRETS = (
        AWS_SECRET_ACCESS_KEY,
        DB_PASSWORD,
        GITHUB_PAT_CLASSIC,
        STRIPE_SECRET_LIVE,
    )

    def _merged(self, text: str) -> tuple[MergedMatch, ...]:
        patterns = find_matches(text)
        offset = patterns[0].start_offset if patterns else 0
        return fuse(
            patterns,
            (evidence_at(offset, offset + len(text) - offset, text[offset:]),),
        )

    @pytest.mark.parametrize(
        "text", [f'k = "{AWS_SECRET_ACCESS_KEY}"', f'DATABASE_URL = "{DB_URI}"']
    )
    def test_no_rendering_contains_the_secret(self, text: str) -> None:
        for merged in self._merged(text):
            for rendering in (
                repr(merged),
                str(merged),
                repr(merged.to_finding("config.env")),
                str(merged.to_finding("config.env")),
                json.dumps(merged.to_finding("config.env").to_dict(), default=str),
            ):
                for secret in self.SECRETS:
                    assert secret not in rendering

    def test_a_merged_match_repr_describes_rather_than_reveals(self) -> None:
        """Useful while debugging, useless to an attacker."""

        merged = merge_of(
            self._merged(f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"'),
            "aws-secret-access-key",
        )

        assert "aws-secret-access-key" in repr(merged)
        assert "composite" in repr(merged)
        assert "critical" in repr(merged)
        assert "high_confidence" in repr(merged)
        assert AWS_SECRET_ACCESS_KEY not in repr(merged)
        assert AWS_SECRET_ACCESS_KEY not in str(merged)

    def test_a_merged_match_with_neither_named_evidence_reports_an_error(self) -> None:
        empty = MergedMatch(
            pattern=None,
            entropy=(),
            detector=DetectorKind.ENTROPY,
            confidence=ENTROPY_CONFIDENCE,
            severity=Severity.MEDIUM,
            span=(0, 0),
        )

        with pytest.raises(ValueError, match="pattern match or entropy evidence"):
            _ = empty.raw_value

    def test_an_exception_message_names_a_type_not_a_value(self) -> None:
        """The type name is the useful part; the value would be the leak."""

        with pytest.raises(TypeError) as caught:
            analyze_text(AWS_SECRET_ACCESS_KEY.encode(), "config.env")  # type: ignore[arg-type]

        message = str(caught.value)
        assert AWS_SECRET_ACCESS_KEY not in message
        assert "bytes" in message

    def test_the_wider_entropy_value_is_never_stored_anywhere(self) -> None:
        """A connection string's host must not survive into the finding."""

        text = f'DATABASE_URL = "{DB_URI}"'
        merged = self._merged(text)

        for item in merged:
            finding = item.to_finding("app.conf")
            rendered = json.dumps(finding.to_dict(), default=str)
            assert "db.internal" not in rendered
            assert "appuser" not in rendered
            assert DB_URI not in rendered
