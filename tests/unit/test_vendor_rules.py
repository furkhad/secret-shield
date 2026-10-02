"""Tests for the vendor catalog: :mod:`secret_shield.detectors.catalog`.

Two halves, and the second matters more than the first.

*Positives* prove each rule fires on the shape a vendor issues. *Negatives*
prove it stays quiet on everything else, because a secret scanner earns trust
by not crying wolf. A catalog with no negative fixtures is a catalog nobody can
turn on in CI.

Every fixture is synthetic and carries the marker ``SYNTH``; see
``tests/vendor_fixtures.py``.
"""

from __future__ import annotations

import pytest

import vendor_fixtures as fx
from secret_shield.detectors.base import DetectorRegistry, find_matches, findings_from
from secret_shield.detectors.catalog import RULES, default_registry, rule_by_id
from secret_shield.models import Confidence, SecretCategory, Severity

REGISTRY = default_registry()


def fired(text: str) -> list[str]:
    """Rule ids that fired on ``text``, in deterministic order."""

    return [match.id for match in find_matches(text, registry=REGISTRY)]


def assert_fires(text: str, expected: str) -> None:
    """Assert exactly one rule fires, and that it is the expected one.

    "Exactly one" is the assertion that matters. Two rules matching one span
    means one credential reported twice, which is the catalog's most likely
    self-inflicted bug.
    """

    assert fired(text) == [expected]


def assert_silent(text: str, forbidden: str, *, note: str = "") -> None:
    """Assert ``forbidden`` does not fire, allowing other rules to."""

    fired_ids = fired(text)
    assert forbidden not in fired_ids, f"{note or forbidden!r} fired on {text!r}: {fired_ids}"


# ---------------------------------------------------------------------------
# Catalog integrity
# ---------------------------------------------------------------------------


class TestCatalogIntegrity:
    def test_every_rule_has_a_unique_id(self) -> None:
        ids = [rule.id for rule in RULES]

        assert len(ids) == len(set(ids))

    def test_every_rule_is_documented(self) -> None:
        """A rule with no false-positive notes has not thought about its costs."""

        for rule in RULES:
            assert rule.name.strip(), rule.id
            assert rule.remediation.strip(), f"{rule.id} has no remediation"
            assert len(rule.false_positive_notes) > 40, f"{rule.id} has no FP notes"

    def test_no_rule_claims_an_unknown_category(self) -> None:
        """``UNKNOWN`` exists for rules whose category is not yet agreed, and
        every shipped rule has been agreed."""

        for rule in RULES:
            assert rule.category is not SecretCategory.UNKNOWN, rule.id

    def test_no_rule_claims_verified_confidence(self) -> None:
        """SecretShield never contacts an issuing service, so no rule may
        promise more than a shape match."""

        for rule in RULES:
            assert rule.confidence_floor is not Confidence.VERIFIED, rule.id
            assert rule.base_confidence is not Confidence.VERIFIED, rule.id

    def test_every_rule_is_reachable_by_id(self) -> None:
        for rule in RULES:
            assert rule_by_id(rule.id) is rule

    def test_rule_by_id_rejects_an_unknown_id(self) -> None:
        with pytest.raises(KeyError, match="no catalog rule with id"):
            rule_by_id("no-such-rule")

    def test_the_registry_returns_a_fresh_copy_each_time(self) -> None:
        """A caller registering an extra rule must not affect anyone else."""

        first = default_registry()
        count = len(first)
        first.register(
            rule_by_id("aws-access-key-id").__class__(
                id="local-extra",
                name="Local",
                category=SecretCategory.API_KEY,
                severity=Severity.LOW,
                pattern=r"nope",
            )
        )

        assert len(first) == count + 1
        assert len(default_registry()) == count

    def test_evaluation_order_is_stable_across_rebuilds(self) -> None:
        assert default_registry().ids() == default_registry().ids()

    def test_every_category_the_catalog_claims_is_represented(self) -> None:
        categories = {rule.category for rule in RULES}

        assert categories == {
            SecretCategory.AWS,
            SecretCategory.DATABASE,
            SecretCategory.GITHUB,
            SecretCategory.OPENAI,
            SecretCategory.PRIVATE_KEY,
            SecretCategory.SLACK,
            SecretCategory.STRIPE,
        }

    def test_only_the_aws_secret_rule_gates_on_context(self) -> None:
        """Context gating is a blunt instrument and is used exactly once.

        Every other rule's pattern already identifies a vendor, so gating those
        on a nearby keyword would throw away real detections for no precision
        gain.
        """

        gated = {rule.id for rule in RULES if rule.requires_context}

        assert gated == {"aws-secret-access-key"}


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------


class TestAws:
    @pytest.mark.parametrize(
        "value",
        [fx.AWS_ACCESS_KEY_ID, fx.AWS_TEMP_CREDENTIAL_ID],
        ids=["access-key-id", "temporary-credential-id"],
    )
    def test_a_well_formed_key_id_is_detected(self, value: str) -> None:
        assert_fires(f'aws_access_key_id = "{value}"', "aws-access-key-id")

    @pytest.mark.parametrize(
        "value",
        [
            "AKIAIOSFODNN7EXAMPLE",  # published in AWS's own documentation
            "AKIAAAAAAAAAAAAAAAAA",  # one repeated character
            "AKIA",
            "AKIA5H2XNSYNTHKEY09",  # 19
            "akia5h2xnsynthkey09a",  # lower case
            "AKIA5H2XNSYNTHKEY09AB",  # 21
        ],
        ids=["documentation-example", "repeated-char", "prefix-only", "too-short", "lower-case", "too-long"],
    )
    def test_a_malformed_or_documented_key_id_is_not_detected(self, value: str) -> None:
        assert_silent(f'aws_access_key_id = "{value}"', "aws-access-key-id")

    @pytest.mark.parametrize(
        ("value", "note"),
        [
            ("AIDAIOSFODNN7SYNTHQ", "account id"),
            ("AROAIOSFODNN7SYNTHQ", "role id"),
            ("ANPAIOSFODNN7SYNTHQ", "policy id"),
            ("ASCAIOSFODNN7SYNTHQ", "certificate authority id"),
        ],
    )
    def test_non_credential_aws_identifiers_are_not_detected(self, value: str, note: str) -> None:
        """AWS issues several ``A???`` prefixed identifiers. Only ``AKIA`` and
        ``ASIA`` are access keys; the rest identify objects and are published
        in ARNs, IAM policies and CloudTrail records. Matching them would bury
        the two that matter."""

        assert_silent(f'arn_value = "{value}"', "aws-access-key-id", note=note)

    def test_a_secret_with_context_is_detected(self) -> None:
        line = f'aws_secret_access_key = "{fx.AWS_SECRET_ACCESS_KEY}"'

        assert_fires(line, "aws-secret-access-key")

    @pytest.mark.parametrize(
        "line",
        [
            'value = "{secret}"',
            'data = "{secret}"',
            'creds = "{secret}"',
            'aws_access_key_id = "{secret}"',
            'token = "{secret}"',
        ],
        ids=["uninformative", "data", "creds", "wrong-aws-identifier", "wrong-concept"],
    )
    def test_a_bare_forty_character_string_is_never_an_aws_secret(self, line: str) -> None:
        """The single most important negative test in this module.

        Forty characters of ``[A-Za-z0-9/+=]`` is indistinguishable from a
        base64 SHA-1, a compiled asset hash or an ordinary high-entropy string.
        Reporting it as AWS secret material on shape alone would bury every
        other rule in the catalog, so the rule refuses without a nearby
        identifier naming it.
        """

        text = line.format(secret=fx.AWS_SECRET_ACCESS_KEY)

        assert_silent(text, "aws-secret-access-key")

    @pytest.mark.parametrize(
        "identifier",
        [
            "aws_secret_access_key",
            "AWS_SECRET_ACCESS_KEY",
            "aws-secret-access-key",
            "AwsSecretAccessKey",
        ],
    )
    def test_every_spelling_of_the_identifier_is_accepted(self, identifier: str) -> None:
        text = f'{identifier} = "{fx.AWS_SECRET_ACCESS_KEY}"'

        assert_fires(text, "aws-secret-access-key")

    def test_the_secret_key_must_be_exactly_forty_characters(self) -> None:
        assert_silent(f'aws_secret_access_key = "{fx.AWS_SECRET_ACCESS_KEY[:39]}"', "aws-secret-access-key")
        assert_silent(f'aws_secret_access_key = "{fx.AWS_SECRET_ACCESS_KEY}z"', "aws-secret-access-key")

    def test_the_contextual_evidence_raises_the_confidence_one_step(self) -> None:
        """It stays PROBABLE, not HIGH. A shape match in a variable named
        ``aws_secret_access_key`` is strong, and is still not proof."""

        findings = findings_from(
            find_matches(f'aws_secret_access_key = "{fx.AWS_SECRET_ACCESS_KEY}"', registry=REGISTRY),
            "deploy.env",
        )

        assert findings[0].confidence is Confidence.PROBABLE
        assert findings[0].severity is Severity.CRITICAL

    def test_severity_and_confidence_are_independent(self) -> None:
        """The clearest demonstration in the catalog.

        The AWS secret is CRITICAL impact and only PROBABLE likelihood. The
        access key *identifier* is certain and MEDIUM, because half a
        credential cannot authenticate on its own. Swapping the two would be
        the classic mistake of treating severity as a likelihood.
        """

        key_id = findings_from(
            find_matches(f'aws_access_key_id = "{fx.AWS_ACCESS_KEY_ID}"', registry=REGISTRY), "a.py"
        )[0]
        secret = findings_from(
            find_matches(f'aws_secret_access_key = "{fx.AWS_SECRET_ACCESS_KEY}"', registry=REGISTRY),
            "a.py",
        )[0]

        assert key_id.confidence is Confidence.HIGH_CONFIDENCE
        assert key_id.severity is Severity.MEDIUM

        assert secret.confidence is Confidence.PROBABLE
        assert secret.severity is Severity.CRITICAL


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------


class TestOpenAi:
    @pytest.mark.parametrize(
        "value",
        [fx.OPENAI_PROJECT_KEY, fx.OPENAI_SERVICE_ACCOUNT_KEY],
        ids=["project", "service-account"],
    )
    def test_current_prefixes_are_detected(self, value: str) -> None:
        assert_fires(f'OPENAI_API_KEY = "{value}"', "openai-api-key")

    def test_the_legacy_format_is_detected_by_its_own_rule(self) -> None:
        assert_fires(f'key = "{fx.OPENAI_LEGACY_KEY}"', "openai-api-key-legacy")

    def test_a_legacy_key_is_reported_exactly_once(self) -> None:
        """The two OpenAI rules must have disjoint patterns."""

        assert len(fired(f'key = "{fx.OPENAI_LEGACY_KEY}"')) == 1

    @pytest.mark.parametrize(
        "value",
        [
            "sk-SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4bC6dE",  # 47, one short
            "sk-SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4bC6dE8fz",  # 49, one long
            "sk-SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0x-Y2zA4bC6dE8f",  # 48, but one is a dash
        ],
        ids=["one-short", "one-long", "dash-inside"],
    )
    def test_a_malformed_legacy_key_is_not_detected(self, value: str) -> None:
        """The 48-character length is documented, so pinning it exactly is what
        makes a truncated or mangled key detectable rather than merely
        suspicious."""

        assert_silent(f'key = "{value}"', "openai-api-key-legacy")

    @pytest.mark.parametrize("prefix", ["sk-proj-", "sk-svcacct-"])
    def test_a_current_prefix_with_too_short_a_body_is_not_detected(self, prefix: str) -> None:
        assert_silent(f'key = "{prefix}SYNTHaB3dE5f"', "openai-api-key")

    @pytest.mark.parametrize(
        "value",
        [
            "sk-exampleexampleexampleexampleexampleexample12",
            "sk-EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE",
            "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "sk-changemechangemechangemechangemechangeme",
        ],
    )
    def test_placeholders_are_not_detected(self, value: str) -> None:
        assert_silent(f'OPENAI_API_KEY = "{value}"', "openai-api-key-legacy")

    @pytest.mark.parametrize("prefix", ["sk-", "sk_"])
    def test_a_stripe_key_is_not_an_openai_key(self, prefix: str) -> None:
        """Stripe's prefixes carry an underscore immediately after ``sk``."""

        assert_silent(f'key = "{prefix}live_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8"', "openai-api-key")
        assert_silent(f'key = "{prefix}live_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8"', "openai-api-key-legacy")


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


class TestGitHub:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (fx.GITHUB_PAT_CLASSIC, "github-pat-classic"),
            (fx.GITHUB_OAUTH_TOKEN, "github-pat-classic"),
            (fx.GITHUB_USER_SERVER_TOKEN, "github-pat-classic"),
            (fx.GITHUB_APP_TOKEN, "github-app-token"),
            (fx.GITHUB_REFRESH_TOKEN, "github-app-token"),
            (fx.GITHUB_FINE_GRAINED_PAT, "github-pat-fine-grained"),
        ],
        ids=["pat", "oauth", "user-server", "app", "refresh", "fine-grained"],
    )
    def test_every_token_family_is_detected(self, value: str, expected: str) -> None:
        assert_fires(f"GITHUB_TOKEN = {value}", expected)

    def test_the_app_token_is_less_severe_than_a_personal_token(self) -> None:
        """``ghs_`` and ``ghr_`` are issued for one integration; ``ghp_`` is
        issued to a person and carries that person's access."""

        pat = findings_from(find_matches(f"t = {fx.GITHUB_PAT_CLASSIC}", registry=REGISTRY), "a.py")[0]
        app = findings_from(find_matches(f"t = {fx.GITHUB_APP_TOKEN}", registry=REGISTRY), "a.py")[0]

        assert pat.severity is Severity.HIGH
        assert app.severity is Severity.MEDIUM

    @pytest.mark.parametrize(
        "value",
        [
            "ghp_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0",  # 35
            "ghp_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xA",  # 37
            "ghx_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0x",  # unknown prefix
            "gh-SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xaB",  # missing underscore
            "ghp_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0_aB",  # underscore in the body
        ],
        ids=["too-short", "too-long", "unknown-prefix", "no-underscore", "underscore-in-body"],
    )
    def test_a_malformed_classic_token_is_not_detected(self, value: str) -> None:
        assert_silent(f"t = {value}", "github-pat-classic")

    def test_a_token_of_zeros_is_not_detected(self) -> None:
        """A real prefix followed only by zeros is a documentation fixture."""

        assert_silent('t = "ghp_' + "0" * 36 + '"', "github-pat-classic")

    def test_a_fine_grained_token_that_is_too_short_is_not_detected(self) -> None:
        assert_silent('t = "github_pat_SYNTHaB3d"', "github-pat-fine-grained")

    @pytest.mark.parametrize(
        "value",
        [
            "ghp_YOUR_TOKEN_HERE_YOUR_TOKEN_HERE_12",
            "ghp_REPLACEME_REPLACEME_REPLACE_ME123",
            "ghp_exampleexampleexampleexampleex12",
        ],
    )
    def test_placeholders_are_not_detected(self, value: str) -> None:
        assert_silent(f"t = {value}", "github-pat-classic")

    def test_the_fine_grained_rule_does_not_shadow_the_classic_rule(self) -> None:
        assert_silent(f"t = {fx.GITHUB_PAT_CLASSIC}", "github-pat-fine-grained")
        assert_silent(f"t = {fx.GITHUB_FINE_GRAINED_PAT}", "github-pat-classic")


# ---------------------------------------------------------------------------
# Stripe
# ---------------------------------------------------------------------------


class TestStripe:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (fx.STRIPE_SECRET_LIVE, "stripe-secret-key-live"),
            (fx.STRIPE_RESTRICTED_LIVE, "stripe-restricted-key-live"),
            (fx.STRIPE_SECRET_TEST, "stripe-test-key"),
            (fx.STRIPE_RESTRICTED_TEST, "stripe-test-key"),
            (fx.STRIPE_PUBLISHABLE_LIVE, "stripe-publishable-key"),
            (fx.STRIPE_PUBLISHABLE_TEST, "stripe-publishable-key"),
        ],
        ids=["sk-live", "rk-live", "sk-test", "rk-test", "pk-live", "pk-test"],
    )
    def test_every_stripe_key_family_is_detected(self, value: str, expected: str) -> None:
        assert_fires(f'STRIPE_KEY = "{value}"', expected)

    def test_live_and_test_keys_are_distinguished(self) -> None:
        assert_silent(f'k = "{fx.STRIPE_SECRET_LIVE}"', "stripe-test-key")
        assert_silent(f'k = "{fx.STRIPE_SECRET_TEST}"', "stripe-secret-key-live")

    def test_the_publishable_key_is_low_severity_because_it_is_public_by_design(self) -> None:
        """A publishable key is embedded in client applications on purpose and
        appears in every browser that has ever used the site. Reporting it as
        HIGH would be crying wolf about the least sensitive thing in the
        catalog.
        """

        finding = findings_from(
            find_matches(f'k = "{fx.STRIPE_PUBLISHABLE_LIVE}"', registry=REGISTRY), "a.py"
        )[0]

        assert finding.severity is Severity.LOW
        assert finding.confidence is Confidence.HIGH_CONFIDENCE

    def test_stripe_severity_spans_the_full_range_at_equal_confidence(self) -> None:
        """Four rules, four severities, one confidence.

        This is the sharpest available statement that severity measures impact
        and confidence measures likelihood, and that neither can be derived
        from the other.
        """

        expected = {
            fx.STRIPE_SECRET_LIVE: Severity.CRITICAL,
            fx.STRIPE_RESTRICTED_LIVE: Severity.HIGH,
            fx.STRIPE_SECRET_TEST: Severity.MEDIUM,
            fx.STRIPE_PUBLISHABLE_LIVE: Severity.LOW,
        }
        findings = [
            findings_from(find_matches(f'k = "{value}"', registry=REGISTRY), "a.py")[0]
            for value in expected
        ]

        assert {f.severity for f in findings} == set(expected.values())
        assert {f.confidence for f in findings} == {Confidence.HIGH_CONFIDENCE}

    def test_a_test_key_is_still_reported_despite_containing_a_placeholder_word(self) -> None:
        """``test`` is a placeholder word *and* part of a Stripe prefix.

        A rule whose own pattern has already established what the value is must
        not be silenced by a marker inside it, or every Stripe test key in
        every repository would be invisible.
        """

        assert "test" in fx.STRIPE_SECRET_TEST
        assert_fires(f'k = "{fx.STRIPE_SECRET_TEST}"', "stripe-test-key")

    @pytest.mark.parametrize(
        "value",
        [
            fx.STRIPE_SECRET_LIVE_PREFIX + "SYNTHaB3dE5fG7",  # 15 characters, one short
            "sk_prod_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8",  # unknown environment
            fx.STRIPE_SECRET_LIVE_PREFIX + "SYNTHaB3dE5fG7h_J9kL1mN2pQ4rS6tU8",  # underscore in body
            fx.STRIPE_SECRET_LIVE_PREFIX,  # prefix only
        ],
        ids=["too-short", "bad-environment", "underscore-in-body", "prefix-only"],
    )
    def test_a_malformed_stripe_key_is_not_detected(self, value: str) -> None:
        """Each value is assembled from a prefix and a body that are never
        adjacent in this file, for the reason given on
        :data:`vendor_fixtures.STRIPE_BODY`."""

        assert_silent(f'k = "{value}"', "stripe-secret-key-live")

    def test_a_publishable_key_is_not_a_secret_key(self) -> None:
        assert_silent(f'k = "{fx.STRIPE_PUBLISHABLE_LIVE}"', "stripe-secret-key-live")
        assert_silent(f'k = "{fx.STRIPE_SECRET_LIVE}"', "stripe-publishable-key")


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


class TestSlack:
    def test_a_well_formed_webhook_is_detected(self) -> None:
        assert_fires(f'SLACK_WEBHOOK = "{fx.SLACK_WEBHOOK}"', "slack-incoming-webhook")

    def test_the_webhook_is_medium_because_it_can_only_post(self) -> None:
        """An incoming webhook cannot read history or act as a user. Calling it
        HIGH would overstate what possession of one actually yields."""

        finding = findings_from(
            find_matches(f'url = "{fx.SLACK_WEBHOOK}"', registry=REGISTRY), "a.py"
        )[0]

        assert finding.severity is Severity.MEDIUM

    @pytest.mark.parametrize(
        ("url", "note"),
        [
            (
                "https://hooks.example.com/services/T8N4QK7SYNTH01/B2W6R9Y3U5V1/"
                "7dKpSYNTHbG4hJ6nF8qW2zX5cV1",
                "another host",
            ),
            (
                "http://hooks.slack.com/services/T8N4QK7SYNTH01/B2W6R9Y3U5V1/"
                "7dKpSYNTHbG4hJ6nF8qW2zX5cV1",
                "plain http",
            ),
            (
                "https://hooks.slack.com/services/T8N4QK7SYNTH01/B2W6R9Y3U5V1/short",
                "token too short",
            ),
            ("https://hooks.slack.com/", "no path at all"),
            ("https://hooks.slack.com/services/T1/B2/c3", "segments too short"),
        ],
    )
    def test_an_unrelated_or_malformed_url_is_not_detected(self, url: str, note: str) -> None:
        assert_silent(f"url = {url!r}", "slack-incoming-webhook", note=note)

    def test_the_webhook_is_not_reported_as_a_bare_url_by_entropy(self) -> None:
        """A Slack webhook carries its secret in the path, with no userinfo and
        no query. The tokenizer's bare-URL filter would suppress it, which is
        only safe because this rule exists to catch it.
        """

        from secret_shield.tokenizer import has_non_secret_structure

        assert has_non_secret_structure(fx.SLACK_WEBHOOK)
        assert fired(fx.SLACK_WEBHOOK) == ["slack-incoming-webhook"]


# ---------------------------------------------------------------------------
# Private keys
# ---------------------------------------------------------------------------


class TestPrivateKeys:
    @pytest.mark.parametrize(
        "header",
        [
            "RSA PRIVATE KEY",
            "DSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "PGP PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "RSA PRIVATE KEY BLOCK",
            "PGP PRIVATE KEY BLOCK",
        ],
    )
    def test_every_documented_header_is_detected(self, header: str) -> None:
        text = f"-----BEGIN {header}-----\nSYNTHbody\n-----END {header}-----"

        assert_fires(text, "private-key-block")

    def test_the_whole_block_is_captured_when_the_footer_is_present(self) -> None:
        matches = find_matches(fx.PRIVATE_KEY_BLOCK, registry=REGISTRY)

        assert len(matches) == 1
        assert matches[0].overlaps is True
        assert matches[0].end_line > matches[0].line

    def test_a_truncated_key_is_still_reported(self) -> None:
        """A paste cut off mid-block is the case that matters most, and a rule
        that required the footer would miss it entirely."""

        matches = find_matches(fx.PRIVATE_KEY_TRUNCATED, registry=REGISTRY)

        assert len(matches) == 1
        assert matches[0].overlaps is False

    @pytest.mark.parametrize(
        "header",
        [
            "CERTIFICATE",
            "PUBLIC KEY",
            "RSA PUBLIC KEY",
            "CERTIFICATE REQUEST",
            "NEW CERTIFICATE REQUEST",
        ],
        ids=["certificate", "public-key", "rsa-public", "csr", "new-csr"],
    )
    def test_a_public_artefact_is_never_a_private_key_finding(self, header: str) -> None:
        """Public keys and certificates are designed to be published. Turning
        them into CRITICAL private-key findings would be the most damaging
        false positive this catalog could produce."""

        text = f"-----BEGIN {header}-----\nSYNTHbody\n-----END {header}-----"

        assert_silent(text, "private-key-block")

    def test_the_finding_is_critical_and_fully_redacted(self) -> None:
        finding = findings_from(find_matches(fx.PRIVATE_KEY_BLOCK, registry=REGISTRY), "id_rsa")[0]

        assert finding.severity is Severity.CRITICAL
        assert finding.masked_value.count("*") == 12

    def test_no_part_of_the_key_body_reaches_the_finding(self) -> None:
        findings = findings_from(find_matches(fx.PRIVATE_KEY_BLOCK, registry=REGISTRY), "id_rsa")

        assert fx.PRIVATE_KEY_BODY not in repr(findings)
        assert fx.PRIVATE_KEY_BODY[:32] not in repr(findings)


# ---------------------------------------------------------------------------
# Database URIs
# ---------------------------------------------------------------------------


class TestDatabaseUris:
    @pytest.mark.parametrize(
        "uri",
        [
            f"postgres://appuser:{fx.DB_PASSWORD}@db.internal:5432/production",
            f"postgresql://appuser:{fx.DB_PASSWORD}@db.internal:5432/production",
            f"mysql://appuser:{fx.DB_PASSWORD}@db.internal:3306/billing",
            f"mongodb://appuser:{fx.DB_PASSWORD}@db.internal:27017/inventory",
            f"mongodb+srv://appuser:{fx.DB_PASSWORD}@cluster0.example.net/inventory",
            f"redis://appuser:{fx.DB_PASSWORD}@cache.internal:6379/0",
        ],
    )
    def test_every_supported_scheme_is_detected(self, uri: str) -> None:
        assert_fires(f'DATABASE_URL = "{uri}"', "database-uri-with-password")

    def test_the_finding_reports_the_password_not_the_whole_uri(self) -> None:
        """Redaction must not disclose the host or the database name.

        A masked value that read ``postgres://user:********@db.internal`` would
        hand a reader half the reconnaissance they need, for no benefit.
        """

        match = find_matches(f'DATABASE_URL = "{fx.DB_URI}"', registry=REGISTRY)[0]

        assert match.value == fx.DB_PASSWORD
        assert "db.internal" not in match.value
        assert "production" not in match.value

    @pytest.mark.parametrize(
        "uri",
        [
            "postgres://appuser@db.internal:5432/production",  # no password
            "postgres://db.internal:5432/production",  # host and port only
            "postgres://db.internal/production",  # host only
            "mysql://root@127.0.0.1/billing",
            "redis://cache.internal:6379",
            "mongodb://db.internal:27017/inventory",
        ],
        ids=[
            "no-password",
            "host-and-port-only",
            "host-only",
            "mysql-no-password",
            "redis-no-password",
            "mongodb-no-password",
        ],
    )
    def test_a_uri_without_a_password_is_not_a_secret(self, uri: str) -> None:
        """Half of a connection string identifies a service, not a person."""

        assert_silent(f'DATABASE_URL = "{uri}"', "database-uri-with-password")

    @pytest.mark.parametrize(
        "password",
        [
            "${PG_PASSWORD}",
            "{{ secrets.db_password }}",
            "{{DB_PASSWORD}}",
            "%DB_PASSWORD%",
            "<%= ENV['DB_PW'] %>",
            "@{DB_PASSWORD}",
            "$(cat /run/secrets/db_password)",
        ],
    )
    def test_an_unfilled_interpolation_is_not_a_password(self, password: str) -> None:
        """The URI around it is real and the password is not, which is the one
        case where suppressing the whole value is the right answer rather than
        a loss."""

        assert_silent(f'DATABASE_URL = "postgres://appuser:{password}@db/prod"', "database-uri-with-password")

    @pytest.mark.parametrize(
        "password",
        [
            "changeme",
            "CHANGEME",
            "change_me",
            "your-password-here",
            "xxxxxxxxxxxx",
            "abc",  # below the four-character floor
            "ab",  # below the four-character floor
        ],
    )
    def test_placeholder_and_trivial_passwords_are_not_reported(self, password: str) -> None:
        assert_silent(f'DATABASE_URL = "postgres://appuser:{password}@db/prod"', "database-uri-with-password")

    def test_a_weak_but_real_password_is_still_reported(self) -> None:
        """``password`` used as a password is a terrible credential, and a
        terrible credential is still a credential.

        Deciding that a value is too weak to bother reporting is a policy
        question about password strength, and answering it inside a secret
        scanner would quietly narrow the tool's job. If a reviewer does not want
        to see findings like this, that belongs in a report filter, not in
        detection.
        """

        assert_fires('DATABASE_URL = "postgres://appuser:password@db/prod"', "database-uri-with-password")

    def test_a_percent_encoded_password_is_detected(self) -> None:
        """``@`` must be percent-encoded inside a password, so the encoded form
        is what a correct client actually writes."""

        uri = "postgres://appuser:SYNTHp%40ssw0rd%21@db.internal:5432/prod"

        assert_fires(f'DATABASE_URL = "{uri}"', "database-uri-with-password")

    def test_the_encoded_password_is_reported_in_its_encoded_form(self) -> None:
        uri = "postgres://appuser:SYNTHp%40ssw0rd%21@db.internal:5432/prod"
        match = find_matches(f'DATABASE_URL = "{uri}"', registry=REGISTRY)[0]

        assert match.value == "SYNTHp%40ssw0rd%21"

    @pytest.mark.parametrize(
        "uri",
        [
            "https://appuser:SYNTHp7wQ2mK9rT4vB8nL3@api.example.com/v1",  # not a database scheme
            "ftp://appuser:SYNTHp7wQ2mK9rT4vB8nL3@files.example.com/x",
        ],
    )
    def test_a_non_database_scheme_is_not_reported(self, uri: str) -> None:
        assert_silent(f'url = "{uri}"', "database-uri-with-password")

    def test_the_finding_is_critical(self) -> None:
        finding = findings_from(find_matches(f'DATABASE_URL = "{fx.DB_URI}"', registry=REGISTRY), "a.py")[0]

        assert finding.severity is Severity.CRITICAL


# ---------------------------------------------------------------------------
# Cross-cutting
# ---------------------------------------------------------------------------


class TestCatalogCrossCutting:
    def test_severities_span_the_whole_range(self) -> None:
        """A catalog where every rule is CRITICAL has not made a judgement."""

        assert {rule.severity for rule in RULES} >= {
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        }

    def test_exact_rules_are_the_majority_and_heuristics_are_the_exception(self) -> None:
        exact = [rule for rule in RULES if rule.specificity is not None]
        from secret_shield.detectors.base import Specificity

        assert exact
        assert sum(1 for r in RULES if r.specificity is Specificity.EXACT) >= len(RULES) - 1

    def test_a_document_containing_many_secrets_is_reported_consistently(self) -> None:
        """Several vendors in one file, one match each, deterministic order."""

        text = "\n".join(
            [
                f'aws_access_key_id = "{fx.AWS_ACCESS_KEY_ID}"',
                f'OPENAI_API_KEY = "{fx.OPENAI_PROJECT_KEY}"',
                f"GITHUB_TOKEN = {fx.GITHUB_PAT_CLASSIC}",
                f'STRIPE_KEY = "{fx.STRIPE_SECRET_LIVE}"',
                f'DATABASE_URL = "{fx.DB_URI}"',
                f'SLACK_WEBHOOK = "{fx.SLACK_WEBHOOK}"',
                fx.PRIVATE_KEY_BLOCK,
            ]
        )

        expected = [
            "aws-access-key-id",
            "openai-api-key",
            "github-pat-classic",
            "stripe-secret-key-live",
            "slack-incoming-webhook",
            "private-key-block",
            "database-uri-with-password",
        ]

        assert fired(text) == expected
        assert fired(text) == expected

    def test_no_raw_value_from_any_fixture_reaches_a_finding(self) -> None:
        """The load-bearing purity test for the catalog as a whole."""

        values = [
            fx.AWS_ACCESS_KEY_ID,
            fx.AWS_SECRET_ACCESS_KEY,
            fx.OPENAI_LEGACY_KEY,
            fx.OPENAI_PROJECT_KEY,
            fx.GITHUB_PAT_CLASSIC,
            fx.GITHUB_FINE_GRAINED_PAT,
            fx.STRIPE_SECRET_LIVE,
            fx.SLACK_WEBHOOK,
            fx.DB_PASSWORD,
            fx.PRIVATE_KEY_BODY,
        ]
        text = "\n".join(
            [
                f'aws_secret_access_key = "{fx.AWS_SECRET_ACCESS_KEY}"',
                f'OPENAI_API_KEY = "{fx.OPENAI_PROJECT_KEY}"',
                f"GITHUB_TOKEN = {fx.GITHUB_PAT_CLASSIC}",
                f'STRIPE_KEY = "{fx.STRIPE_SECRET_LIVE}"',
                f'SLACK_WEBHOOK = "{fx.SLACK_WEBHOOK}"',
                f'DATABASE_URL = "{fx.DB_URI}"',
                fx.PRIVATE_KEY_BLOCK,
            ]
        )
        findings = findings_from(find_matches(text, registry=REGISTRY), "secrets.txt")
        rendered = repr(findings)

        for value in values:
            assert value not in rendered, value
            assert value[:24] not in rendered, value[:24]

    def test_an_empty_catalog_finds_nothing(self) -> None:
        text = "\n".join([f'DATABASE_URL = "{fx.DB_URI}"', fx.PRIVATE_KEY_BLOCK])

        assert find_matches(text, registry=DetectorRegistry()) == []
