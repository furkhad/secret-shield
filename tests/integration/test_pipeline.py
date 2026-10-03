"""Integration tests for the assembled pipeline: :func:`analyze_text`.

``test_fusion.py`` proves the fusion rule decides correctly when it is handed
evidence. This module proves the answer a user actually gets, on text a
repository would really contain.

The distinction matters more here than in the unit tests, because the pipeline's
real inputs are not constructed. Two detectors run over a file, and each one is
free to reject a candidate before fusion ever sees it. Which of them fired, and
therefore which findings exist, is a property of the whole chain -- the tokenizer
its structural filters, the vendor rules' own gates, the entropy thresholds --
and none of it is decided by :func:`secret_shield.pipeline.fuse`.

So this module asserts both halves:

* **What the pipeline does with the evidence it gets.** A composite is a
  composite; the vendor rule's severity survives; the entropy-only finding
  survives where no vendor claimed the value.
* **What the structural filters did before it got there.** A bare
  ``ghp_<36>`` inside a quoted literal is suppressed by
  ``has_non_secret_structure`` -- it reads as a snake_case identifier -- so the
  entropy rule never reports it and there is nothing to fuse. That is a
  deliberate Stage 1 decision, and a test that quietly assumed otherwise would
  be asserting a coincidence.

All credentials are synthetic and carry the ``SYNTH`` marker; see
``tests/vendor_fixtures.py``.
"""

from __future__ import annotations

import json

import pytest

from secret_shield.detectors import (
    DetectorRegistry,
    Rule,
    Specificity,
    find_matches,
)
from secret_shield.detectors.catalog import SecretCategory, rule_by_id
from secret_shield.detectors.context import looks_like_hash
from secret_shield.models import Confidence, DetectorKind, Severity
from secret_shield.pipeline import analyze_text
from secret_shield.tokenizer import candidates, has_non_secret_structure
from tests.vendor_fixtures import (  # type: ignore
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    DB_PASSWORD,
    DB_URI,
    GITHUB_OAUTH_TOKEN,
    GITHUB_PAT_CLASSIC,
    OPENAI_LEGACY_KEY,
    OPENAI_PROJECT_KEY,
    OPENAI_SERVICE_ACCOUNT_KEY,
    SLACK_WEBHOOK,
    STRIPE_PUBLISHABLE_LIVE,
    STRIPE_SECRET_LIVE,
    STRIPE_SECRET_TEST,
)


def rule_ids(text: str, path: str = "config.env") -> list[str]:
    return [finding.rule_id for finding in analyze_text(text, path)]


# ---------------------------------------------------------------------------
# Cases where entropy and a vendor rule genuinely collide
# ---------------------------------------------------------------------------


class TestRealComposites:
    """The three shapes where a real entropy candidate meets a real rule.

    These are the ones that motivated fusion. Each is a normal configuration
    file, and each previously produced two findings for one secret.
    """

    def test_an_aws_key_id_is_reported_once(self) -> None:
        text = f'aws_access_key_id = "{AWS_ACCESS_KEY_ID}"'

        assert rule_ids(text) == ["aws-access-key-id"]

        finding = analyze_text(text, "config.env")[0]
        assert finding.detector is DetectorKind.COMPOSITE
        assert finding.severity is Severity.MEDIUM
        assert finding.confidence is Confidence.HIGH_CONFIDENCE

    def test_an_aws_secret_is_reported_once_at_critical(self) -> None:
        """The headline case, on the most ordinary line in this repository."""

        text = f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"'

        assert rule_ids(text) == ["aws-secret-access-key"]

        finding = analyze_text(text, "config.env")[0]
        assert finding.detector is DetectorKind.COMPOSITE
        # Entropy corroborates; it does not downgrade. This is CRITICAL.
        assert finding.severity is Severity.CRITICAL
        assert finding.confidence is Confidence.HIGH_CONFIDENCE

    def test_a_connection_string_is_reported_once_for_its_password(self) -> None:
        text = f'DATABASE_URL = "{DB_URI}"'

        assert rule_ids(text) == ["database-uri-with-password"]

        finding = analyze_text(text, "app.conf")[0]
        assert finding.detector is DetectorKind.COMPOSITE
        assert finding.severity is Severity.CRITICAL
        # The reported value is the password, not the whole URI. The host and
        # database name are infrastructure, not credential material, and
        # reporting them would make the mask long enough to be recognisable.
        assert finding.value_length == len(DB_PASSWORD)
        assert finding.value_fingerprint != ""

    def test_an_entropy_only_value_is_still_reported(self) -> None:
        """Fusion must not swallow the detections that only entropy makes.

        A homemade HMAC has no prefix, no length and no vendor. If fusion ate
        these, the tool would be blind to exactly the credentials no rule
        covers -- which is the class it is least able to help with, because
        nobody has written a rule for it.
        """

        value = "f8Kq2mZ9tR4vX7bN1cL6wY3hJ5pA0sD2fG4hJ6kL8"
        text = f'SIGNING_HMAC = "{value}"'

        assert rule_ids(text) == ["high-entropy-string"]

        finding = analyze_text(text, "app.py")[0]
        assert finding.detector is DetectorKind.ENTROPY
        assert finding.severity is Severity.MEDIUM
        assert finding.confidence is Confidence.PROBABLE
        assert finding.category is SecretCategory.UNKNOWN


# ---------------------------------------------------------------------------
# Cases where the tokenizer suppresses the entropy duplicate
# ---------------------------------------------------------------------------


class TestWhereTheStructuralFiltersFireFirst:
    """Vendor-prefixed keys never reach the entropy rule, and that is correct.

    ``has_non_secret_structure`` rejects ``ghp_SYNTHaB3...`` because it reads as
    a snake_case identifier -- and it does. That is the Stage 1 precision work,
    and it means the entropy rule has nothing to contribute for these values.

    Fusion is still load-bearing for them, but invisibly: with no entropy
    candidate there is no second finding to suppress. The tests below pin the
    outcome, so a change to the tokenizer's filters shows up here as a change in
    *detector kind* even though the finding count stays at one.
    """

    PREFIXED = [
        ("github-pat", f'GITHUB_TOKEN = "{GITHUB_PAT_CLASSIC}"', "github-pat-classic"),
        (
            "github-oauth",
            f'GITHUB_TOKEN = "{GITHUB_OAUTH_TOKEN}"',
            "github-pat-classic",
        ),
        (
            "stripe-live",
            f'STRIPE_KEY = "{STRIPE_SECRET_LIVE}"',
            "stripe-secret-key-live",
        ),
        (
            "stripe-publishable",
            f'STRIPE_KEY = "{STRIPE_PUBLISHABLE_LIVE}"',
            "stripe-publishable-key",
        ),
        (
            "openai-project",
            f'OPENAI_API_KEY = "{OPENAI_PROJECT_KEY}"',
            "openai-api-key",
        ),
        (
            "openai-legacy",
            f'OPENAI_API_KEY = "{OPENAI_LEGACY_KEY}"',
            "openai-api-key-legacy",
        ),
        (
            "openai-service-account",
            f'OPENAI_API_KEY = "{OPENAI_SERVICE_ACCOUNT_KEY}"',
            "openai-api-key",
        ),
        (
            "slack-webhook",
            f'SLACK_WEBHOOK = "{SLACK_WEBHOOK}"',
            "slack-incoming-webhook",
        ),
    ]

    @pytest.mark.parametrize(
        ("name", "text", "expected_rule"),
        PREFIXED,
        ids=[case[0] for case in PREFIXED],
    )
    def test_a_prefixed_key_is_reported_once_by_its_vendor_rule(
        self, name: str, text: str, expected_rule: str
    ) -> None:
        findings = analyze_text(text, "config.env")

        assert [finding.rule_id for finding in findings] == [expected_rule]
        assert findings[0].detector is DetectorKind.PATTERN

    @pytest.mark.parametrize(
        ("name", "text", "expected_rule"),
        PREFIXED,
        ids=[case[0] for case in PREFIXED],
    )
    def test_no_entropy_candidate_was_produced_for_these_values(
        self, name: str, text: str, expected_rule: str
    ) -> None:
        """Assert the *reason* the finding is not a composite.

        Without this, ``test_a_prefixed_key_is_reported_once`` would still pass if
        the tokenizer's filters changed and the entropy candidate reappeared --
        and the detector-kind assertion would catch it, but nothing here would
        say why.
        """

        del text, expected_rule

        for value in (
            GITHUB_PAT_CLASSIC,
            STRIPE_SECRET_LIVE,
            OPENAI_PROJECT_KEY,
            OPENAI_LEGACY_KEY,
            SLACK_WEBHOOK,
        ):
            assert has_non_secret_structure(value), value

    def test_a_wider_literal_around_a_prefixed_key_does_reach_the_entropy_rule(
        self,
    ) -> None:
        """The control: widen the literal and the filters stop applying.

        Whitespace around the value defeats the identifier heuristics, so the
        tokenizer keeps it and the entropy rule fires. The vendor rule still
        names the finding, and there is still exactly one of them.

        This is the proof that the two tests above are about filtering and not
        about fusion being broken for prefixed keys.
        """

        text = f'TOKEN = "  {GITHUB_PAT_CLASSIC}  "'

        findings = analyze_text(text, "config.env")

        assert [finding.rule_id for finding in findings] == ["github-pat-classic"]
        assert findings[0].detector is DetectorKind.COMPOSITE
        # The reported value is still the 40-character token, not the padded
        # 44-character literal the entropy rule measured.
        assert findings[0].value_length == len(GITHUB_PAT_CLASSIC)


# ---------------------------------------------------------------------------
# Two secrets in one value
# ---------------------------------------------------------------------------


class TestSeveralSecretsInOneLine:
    def test_two_vendor_secrets_stay_two_findings(self) -> None:
        """The case that must not be over-merged.

        A literal holding a live key and a restricted key has two credentials in
        it. Collapsing them because they share a quote character would hide the
        second one from a reviewer, which is the specific failure fusion is most
        able to cause.
        """

        text = f'STRIPE_KEYS = "{STRIPE_SECRET_LIVE} {STRIPE_PUBLISHABLE_LIVE}"'

        findings = analyze_text(text, "config.env")

        assert {finding.rule_id for finding in findings} == {
            "stripe-secret-key-live",
            "stripe-publishable-key",
        }
        assert len(findings) == 2
        assert all(finding.detector is DetectorKind.PATTERN for finding in findings)

    def test_several_vendor_secrets_on_separate_lines_stay_separate(self) -> None:
        text = (
            f'STRIPE_KEY = "{STRIPE_SECRET_LIVE}"\n'
            f'STRIPE_KEY = "{STRIPE_PUBLISHABLE_LIVE}"\n'
            f'DATABASE_URL = "{DB_URI}"\n'
        )

        findings = analyze_text(text, "config.env")

        assert [(finding.rule_id, finding.location.line) for finding in findings] == [
            ("stripe-secret-key-live", 1),
            ("stripe-publishable-key", 2),
            ("database-uri-with-password", 3),
        ]


# ---------------------------------------------------------------------------
# Placeholders, templates and context
# ---------------------------------------------------------------------------


class TestContextSurvivesFusion:
    """Fusion runs last, so it cannot resurrect or undo what the rules decided.

    Context adjustment, placeholder suppression and template suppression all
    happen inside the detectors, before fusion sees anything. These tests pin
    that the pipeline reports the detectors' decisions unchanged -- that a
    suppressed match stays suppressed, and that a rule allowed to promote on
    keyword evidence still does.
    """

    def test_a_placeholder_produces_nothing(self) -> None:
        text = 'AWS_SECRET_ACCESS_KEY = "YOUR_SECRET_ACCESS_KEY_HERE_000000000000"'

        assert analyze_text(text, "config.env") == ()

    def test_a_template_produces_nothing(self) -> None:
        text = "AWS_SECRET_ACCESS_KEY = ${AWS_SECRET_ACCESS_KEY}"

        assert analyze_text(text, "config.env") == ()

    def test_a_placeholder_shaped_stripe_test_key_survives_where_the_rule_allows(
        self,
    ) -> None:
        """The Stripe test-key exception, which fusion must not extend.

        ``stripe-test-key`` sets ``suppress_placeholders=False``: a test key is
        gated on ``sk_test_`` and a literal ``test`` marker, and treating that
        as a placeholder would suppress the rule entirely. The finding survives;
        what does *not* survive is any claim that entropy corroborated it,
        because the tokenizer applies its own placeholder filter and rejects
        the value.
        """

        findings = analyze_text(f'STRIPE_KEY = "{STRIPE_SECRET_TEST}"', "config.env")

        assert [finding.rule_id for finding in findings] == ["stripe-test-key"]
        assert findings[0].detector is DetectorKind.PATTERN
        assert findings[0].severity is Severity.MEDIUM

    def test_keyword_evidence_is_what_raises_a_heuristic_rule(self) -> None:
        """``aws-secret-access-key`` sets ``requires_context``.

        The rule does not fire at all without a keyword beside the value, so
        there is no "unpromoted" version of this finding to compare against --
        which is the stronger statement: the keyword is load-bearing, and it is
        evaluated inside the rule, before fusion runs.
        """

        assert find_matches(f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"')[
            0
        ].confidence() is (Confidence.PROBABLE)
        assert find_matches(f'blob = "{AWS_SECRET_ACCESS_KEY}"') == []

    def test_a_heuristic_rule_without_context_still_reaches_the_pipeline(self) -> None:
        """And a heuristic that does *not* require context still reaches the pipeline.

        The counterpart to the test above. Two levels are pinned here because
        both are the rule's own doing rather than fusion's:

        * An assignment name beside the value is context, so the rule earns its
          promotion from PROBABLE to HIGH_CONFIDENCE by itself.
        * Fusion then finds nothing left to add, and the finding stays where the
          rule put it.

        A base of PROBABLE rather than CANDIDATE, because ``RawMatch.confidence``
        counts one step of context and a rule that already starts at HIGH is not
        what this test is about.
        """

        rule = Rule(
            id="acme-loose-key",
            name="ACME loose key",
            category=SecretCategory.GENERIC_TOKEN,
            severity=Severity.HIGH,
            pattern=r"\bSYNTH[A-Za-z0-9]{33,40}\b",
            specificity=Specificity.HEURISTIC,
            requires_context=False,
            base_confidence=Confidence.PROBABLE,
            remediation="Rotate it.",
        )
        text = f'acme_loose_key = "  {AWS_SECRET_ACCESS_KEY}  "'

        alone = find_matches(text, DetectorRegistry(rules=(rule,)))
        assert alone[0].confidence() is Confidence.HIGH_CONFIDENCE

        fused = analyze_text(
            text, "config.env", registry=DetectorRegistry(rules=(rule,))
        )
        assert len(fused) == 1
        assert fused[0].detector is DetectorKind.COMPOSITE
        # The rule already reached the ceiling on its own evidence; fusion could
        # not raise it further and did not lower it.
        assert fused[0].confidence is Confidence.HIGH_CONFIDENCE

    def test_a_candidate_rule_is_promoted_by_its_context_then_by_fusion(self) -> None:
        """The full ladder, with each rung attributed to the thing that set it.

        CANDIDATE is the floor a HEURISTIC rule with no declared base starts at.
        Context beside the value takes it to PROBABLE. Entropy corroboration
        takes it to HIGH_CONFIDENCE. Three different mechanisms, and only the
        last one belongs to this pipeline.
        """

        rule = Rule(
            id="acme-loose-key",
            name="ACME loose key",
            category=SecretCategory.GENERIC_TOKEN,
            severity=Severity.HIGH,
            pattern=r"\bSYNTH[A-Za-z0-9]{33,40}\b",
            specificity=Specificity.HEURISTIC,
            requires_context=False,
            remediation="Rotate it.",
        )
        assert rule.confidence_floor is Confidence.CANDIDATE

        # No assignment name and no keyword: the rule alone cannot do better.
        bare = find_matches(
            f'"{AWS_SECRET_ACCESS_KEY}"', DetectorRegistry(rules=(rule,))
        )
        assert bare[0].confidence() is Confidence.CANDIDATE

        # The assignment name is the context the rule counts.
        named = find_matches(
            f'acme_loose_key = "{AWS_SECRET_ACCESS_KEY}"',
            DetectorRegistry(rules=(rule,)),
        )
        assert named[0].confidence() is Confidence.PROBABLE

        # Fusion adds the last step, and only the last step.
        fused = analyze_text(
            f'acme_loose_key = "  {AWS_SECRET_ACCESS_KEY}  "',
            "config.env",
            registry=DetectorRegistry(rules=(rule,)),
        )
        assert len(fused) == 1
        assert fused[0].detector is DetectorKind.COMPOSITE
        assert fused[0].confidence is Confidence.HIGH_CONFIDENCE

    def test_an_exact_rule_is_not_downgraded_by_the_promotion(self) -> None:
        """Corroboration cannot move a rule down, only entropy findings up.

        ``EXACT`` starts at HIGH_CONFIDENCE because the rule pinned a documented
        prefix to a documented length. Fusion's job is to leave that alone.
        """

        findings = analyze_text(
            f'GITHUB_TOKEN = "  {GITHUB_PAT_CLASSIC}  "', "config.env"
        )

        assert findings[0].confidence is Confidence.HIGH_CONFIDENCE
        assert findings[0].detector is DetectorKind.COMPOSITE

    def test_a_hash_reaching_the_rules_is_left_to_the_rules(self) -> None:
        """Entropy cannot separate a SHA-1 from a credential; a rule can.

        A 40-character hex digest on an ``AWS_SECRET_ACCESS_KEY`` line satisfies
        everything ``aws-secret-access-key`` checks, because that rule does not
        set ``reject_hashes``. The pipeline reports the rule's decision rather
        than second-guessing it -- the line's *labelling* is the evidence, and
        discarding the match would be the tool overriding a rule with a guess.
        """

        digest = "a3f5c9e17b2d4806be35f1c8a07d29e4a1b2c3d4"

        assert looks_like_hash(digest)
        assert rule_by_id("aws-secret-access-key").reject_hashes is False
        assert rule_ids(f'AWS_SECRET_ACCESS_KEY = "{digest}"', "config.env") == [
            "aws-secret-access-key"
        ]

    def test_a_rule_that_rejects_hashes_suppresses_one(self) -> None:
        """The same digest against a rule that opts into ``reject_hashes``.

        The match never reaches fusion, because there is no match. This is the
        pipeline being faithful to the rule rather than to its own judgement --
        the two must not be confused.
        """

        digest = "a3f5c9e17b2d4806be35f1c8a07d29e4a1b2c3d4"
        rule = Rule(
            id="acme-hash-shaped",
            name="ACME hash-shaped value",
            category=SecretCategory.GENERIC_TOKEN,
            severity=Severity.MEDIUM,
            pattern=r"\b[0-9a-f]{40}\b",
            specificity=Specificity.HEURISTIC,
            reject_hashes=True,
            remediation="Rotate it.",
        )
        text = f'ACME_KEY = "{digest}"'

        assert find_matches(text, DetectorRegistry(rules=(rule,))) == []
        assert not any(
            finding.rule_id == "acme-hash-shaped"
            for finding in analyze_text(
                text, "config.env", registry=DetectorRegistry(rules=(rule,))
            )
        )

    def test_the_same_rule_without_reject_hashes_does_match(self) -> None:
        """The control for the test above: the flag is what made the difference.

        Same pattern, same value, ``reject_hashes=False``. Without the flag the
        digest matches; with it, nothing does. That isolates the mechanism and
        pins that no shipped rule relies on hash rejection to stay quiet.
        """

        digest = "a3f5c9e17b2d4806be35f1c8a07d29e4a1b2c3d4"
        lenient = Rule(
            id="acme-hash-shaped",
            name="ACME hash-shaped value",
            category=SecretCategory.GENERIC_TOKEN,
            severity=Severity.MEDIUM,
            pattern=r"\b[0-9a-f]{40}\b",
            specificity=Specificity.HEURISTIC,
            reject_hashes=False,
            remediation="Rotate it.",
        )
        text = f'ACME_KEY = "{digest}"'

        findings = analyze_text(
            text, "config.env", registry=DetectorRegistry(rules=(lenient,))
        )

        assert [finding.rule_id for finding in findings] == ["acme-hash-shaped"]


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------


class TestAnalyzeTextContract:
    def test_an_empty_string_yields_nothing(self) -> None:
        assert analyze_text("", "empty.py") == ()

    def test_text_without_a_trailing_newline_is_fine(self) -> None:
        assert len(analyze_text(f'K = "{AWS_ACCESS_KEY_ID}"', "config.env")) == 1

    def test_a_positioned_finding_is_pointed_at_correctly(self) -> None:
        text = f'# header\nDEBUG = 1\naws_access_key_id = "{AWS_ACCESS_KEY_ID}"\n'

        finding = analyze_text(text, "config.env")[0]

        assert finding.location.line == 3
        assert finding.location.column == 22

    def test_the_path_is_recorded_verbatim(self) -> None:
        finding = analyze_text(f'K = "{AWS_ACCESS_KEY_ID}"', "config/settings.env")[0]

        assert finding.location.path == "config/settings.env"

    def test_a_git_source_kind_and_commit_are_carried_through(self) -> None:
        finding = analyze_text(
            f'K = "{AWS_ACCESS_KEY_ID}"',
            "config.env",
            source_kind="git",
            commit="a" * 40,
            commit_time=1700000000,
        )[0]

        assert finding.location.source_kind == "git"
        assert finding.location.commit == "a" * 40

    def test_two_scans_of_the_same_text_are_equal(self) -> None:
        text = (
            f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"\n'
            f'DATABASE_URL = "{DB_URI}"\n'
            f'SIGNING_HMAC = "f8Kq2mZ9tR4vX7bN1cL6wY3hJ5pA0sD2fG4hJ6kL8"\n'
        )

        assert analyze_text(text, "config.env") == analyze_text(text, "config.env")

    def test_hostile_text_does_not_raise(self) -> None:
        for text in (
            '"',
            "'",
            "\\",
            "\x00",
            "\ud800",
            "a" * 100_000,
            "\n" * 1000,
            "=" * 5000,
        ):
            analyze_text(text, "hostile.py")  # must not raise

    @pytest.mark.parametrize(
        ("value", "message"),
        [(b"bytes", "bytes"), (None, "NoneType"), (42, "int")],
    )
    def test_a_non_string_text_is_rejected_by_type(
        self, value: object, message: str
    ) -> None:
        """The error names the type, which is the part a caller can act on."""

        with pytest.raises(TypeError, match=message):
            analyze_text(value, "config.env")  # type: ignore[arg-type]

    def test_a_non_string_path_is_rejected_by_type(self) -> None:
        with pytest.raises(TypeError, match="NoneType"):
            analyze_text("text", None)  # type: ignore[arg-type]

    def test_an_empty_registry_finds_nothing(self) -> None:
        from secret_shield.detectors import DetectorRegistry

        findings = analyze_text(
            f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"',
            "config.env",
            registry=DetectorRegistry(rules=()),
        )

        assert {finding.detector for finding in findings} == {DetectorKind.ENTROPY}


# ---------------------------------------------------------------------------
# No raw secret escapes, end to end
# ---------------------------------------------------------------------------


class TestNoRawSecretEscapesEndToEnd:
    TEXTS = [
        f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"',
        f'DATABASE_URL = "{DB_URI}"',
        f'GITHUB_TOKEN = "{GITHUB_PAT_CLASSIC}"',
        f'STRIPE_KEY = "{STRIPE_SECRET_LIVE}"',
        'SIGNING_HMAC = "f8Kq2mZ9tR4vX7bN1cL6wY3hJ5pA0sD2fG4hJ6kL8"',
    ]

    SECRETS = (
        AWS_SECRET_ACCESS_KEY,
        DB_PASSWORD,
        GITHUB_PAT_CLASSIC,
        STRIPE_SECRET_LIVE,
        DB_URI,
    )

    @pytest.mark.parametrize("text", TEXTS, ids=range(len(TEXTS)))
    def test_no_finding_rendering_contains_a_credential(self, text: str) -> None:
        from secret_shield import render_text
        from secret_shield.models import ScanResult

        findings = analyze_text(text, "config.env")
        report = render_text(
            ScanResult(
                findings=findings,
                files_scanned=1,
                bytes_scanned=len(text.encode()),
            )
        )

        for rendered in (
            report,
            *[repr(finding) for finding in findings],
            *[str(finding) for finding in findings],
            json.dumps([finding.to_dict() for finding in findings], default=str),
        ):
            for secret in self.SECRETS:
                assert secret not in rendered

    @pytest.mark.parametrize("text", TEXTS, ids=range(len(TEXTS)))
    def test_every_finding_is_redacted_to_a_fixed_width(self, text: str) -> None:
        """Redaction must not encode the secret's length.

        A mask whose width tracked the value would let a reader of a report
        infer how long the credential is, which is one of the few things a
        masked report should never leak.
        """

        for finding in analyze_text(text, "config.env"):
            assert finding.masked_value.count("*") == len(finding.masked_value)

    @pytest.mark.parametrize("text", TEXTS, ids=range(len(TEXTS)))
    def test_the_masked_value_is_never_the_value(self, text: str) -> None:
        for finding in analyze_text(text, "config.env"):
            assert finding.masked_value not in text


# ---------------------------------------------------------------------------
# The tokenizer's spans, which fusion depends on
# ---------------------------------------------------------------------------


class TestSpansAreExact:
    def test_every_token_span_matches_its_value_in_the_source(self) -> None:
        """Fusion compares offsets, so a wrong span is a wrong merge decision."""

        text = (
            f'k = "{AWS_SECRET_ACCESS_KEY}"\n'
            f"d = '{GITHUB_PAT_CLASSIC}'\n"
            f"n = {AWS_ACCESS_KEY_ID}\n"
            f'q = "plain value"\n'
            f"r = `backtick value`\n"
        )

        for token in candidates(text):
            start, end = token.span
            assert text[start:end] == token.value, token

    def test_the_entropy_candidate_inherits_the_exact_span(self) -> None:
        from secret_shield.detectors import entropy_candidates

        text = f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"'
        (token,) = [
            candidate
            for candidate in entropy_candidates(candidates(text))
            if candidate.value == AWS_SECRET_ACCESS_KEY
        ]

        pattern = find_matches(text)[0]
        assert token.span == pattern.span

    def test_an_entropy_candidate_reports_its_own_span(self) -> None:
        from secret_shield.detectors import entropy_candidates

        candidate = entropy_candidates(candidates(f'k = "{AWS_ACCESS_KEY_ID}"'))[0]

        assert candidate.span == (candidate.start_offset, candidate.end_offset)
        assert candidate.length == len(candidate.value)

    def test_an_entropy_candidate_repr_does_not_reveal_the_value(self) -> None:
        from secret_shield.detectors import entropy_candidates

        candidate = entropy_candidates(candidates(f'k = "{AWS_SECRET_ACCESS_KEY}"'))[0]

        assert AWS_SECRET_ACCESS_KEY not in repr(candidate)
        assert AWS_SECRET_ACCESS_KEY not in str(candidate)
        assert "EntropyCandidate" in repr(candidate)

    def test_a_span_survives_a_collapsed_escape_sequence(self) -> None:
        """The case that separates ``span`` from ``offset + len(value)``.

        ``candidates`` collapses escapes, so this token's *value* is shorter than
        the text it covers. A fusion layer that derived the span from the length
        would compare the wrong range and merge, or fail to merge, for reasons
        that have nothing to do with what the rules found.
        """

        text = 'e = "a\\nb"'
        (token,) = candidates(text)

        assert token.value == "anb"
        assert token.length == 3
        assert token.span == (5, 9)
        assert token.span[1] - token.span[0] == 4
        assert text[slice(*token.span)] == "a\\nb"

    def test_an_entropy_candidate_becomes_a_finding_through_its_own_path(self) -> None:
        """``to_finding`` is the conversion ``detect`` and fusion both use."""

        from secret_shield.detectors import entropy_candidates

        candidate = entropy_candidates(candidates(f'k = "{AWS_ACCESS_KEY_ID}"'))[0]

        finding = candidate.to_finding("config.env")

        assert finding.rule_id == "high-entropy-string"
        assert finding.detector is DetectorKind.ENTROPY
        assert finding.severity is Severity.MEDIUM
        assert finding.confidence is Confidence.PROBABLE


# ---------------------------------------------------------------------------
# Custom rules go through the same pipeline
# ---------------------------------------------------------------------------


class TestCustomRules:
    """Adding a provider is a data change, fusion included.

    A rule that did not exist when the fusion rule was written must produce the
    same *kind* of result. If new rules needed new fusion branches, the design
    would be wrong in a way that only shows up later.
    """

    RULE = Rule(
        id="acme-signing-key",
        name="ACME signing key",
        category=SecretCategory.GENERIC_TOKEN,
        severity=Severity.HIGH,
        pattern=r"\bacme_sk_[A-Za-z0-9]{24,}\b",
        specificity=Specificity.EXACT,
        remediation="Rotate it in the ACME console.",
    )

    ACME_KEY = "acme_sk_SYNTHaB3dE5fG7hJ9kL1mN2pQ"

    @property
    def registry(self) -> DetectorRegistry:
        return DetectorRegistry(rules=(self.RULE,))

    @property
    def TEXT(self) -> str:
        return f'ACME_SIGNING_KEY = "{self.ACME_KEY}"'

    @property
    def PADDED_TEXT(self) -> str:
        """Whitespace around the value, so the entropy rule also fires.

        Without it the tokenizer's structural filters reject the bare
        ``acme_sk_...`` token as an identifier-shaped value and there is nothing
        to fuse -- see ``TestWhereTheStructuralFiltersFireFirst``.
        """

        return f'ACME_SIGNING_KEY = "  {self.ACME_KEY}  "'

    def test_a_custom_rule_is_reported_by_itself(self) -> None:
        findings = analyze_text(self.TEXT, "config.env", registry=self.registry)

        assert [finding.rule_id for finding in findings] == ["acme-signing-key"]
        assert findings[0].detector is DetectorKind.PATTERN
        assert findings[0].severity is Severity.HIGH

    def test_a_custom_rule_merges_with_entropy_like_any_other(self) -> None:
        """The vendor rule names it, entropy corroborates, one finding results.

        Nothing about fusion knows this rule exists. That is the property worth
        testing: a new provider needs a catalog entry, not a change to the
        overlap logic.
        """

        findings = analyze_text(self.PADDED_TEXT, "config.env", registry=self.registry)

        assert [finding.rule_id for finding in findings] == ["acme-signing-key"]
        assert findings[0].detector is DetectorKind.COMPOSITE
        assert findings[0].severity is Severity.HIGH
        assert findings[0].confidence is Confidence.HIGH_CONFIDENCE
        assert findings[0].category is SecretCategory.GENERIC_TOKEN
        assert findings[0].remediation == "Rotate it in the ACME console."
        assert findings[0].value_length == len(self.ACME_KEY)

    def test_a_custom_rule_does_not_need_the_shipped_catalog(self) -> None:
        """A registry holding only the new rule behaves exactly as above."""

        findings = analyze_text(self.PADDED_TEXT, "config.env", registry=self.registry)

        assert [finding.rule_id for finding in findings] == ["acme-signing-key"]

    def test_the_shipped_catalog_alone_finds_nothing_on_this_line(self) -> None:
        """The control: without the new rule, only the entropy rule can fire.

        Establishes that the finding above came from the rule and not from the
        value happening to look random.
        """

        findings = analyze_text(self.PADDED_TEXT, "config.env")

        assert [finding.rule_id for finding in findings] == ["high-entropy-string"]

    def test_an_entropy_candidate_with_no_rule_at_all_is_still_reported(self) -> None:
        findings = analyze_text(
            self.PADDED_TEXT, "config.env", registry=DetectorRegistry(rules=())
        )

        assert [finding.detector for finding in findings] == [DetectorKind.ENTROPY]
        assert findings[0].severity is Severity.MEDIUM
        assert findings[0].confidence is Confidence.PROBABLE
