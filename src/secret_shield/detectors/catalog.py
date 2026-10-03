"""The vendor rule catalog.

Everything in this module is data. Adding a provider means appending a
:class:`~secret_shield.detectors.base.Rule` to :data:`RULES`; no code in
:mod:`secret_shield.detectors.base` names a vendor, so nothing here needs an
engine change to take effect.

**Every value in this file is a synthetic fixture or a published format
description.** No credential in this catalog was copied from a production
system, and none can authenticate against anything. The test suite builds its
own fixtures rather than importing them from here, so that a rule and its
positive examples are written independently of each other.

How to read the metadata
------------------------

``severity`` is **impact if the match is real**. ``specificity`` and
``base_confidence`` are about **how likely the match is to be a real secret**.
The two are independent, and this catalog exercises that independence hard:

* ``stripe-publishable-key`` is LOW and ``stripe-secret-key-live`` is CRITICAL,
  because a publishable key is embedded in client applications *by design* and
  a live secret key can move money.
* ``aws-secret-access-key`` is CRITICAL but only PROBABLE, because a
  40-character base64 string in a variable named ``aws_secret_access_key`` is
  strong evidence and still not proof.
* ``aws-access-key-id`` is MEDIUM, not CRITICAL: an access key *identifier*
  alone cannot authenticate, so its impact is bounded even though it is
  certainly a real one.

What no rule here can do
------------------------

Nothing in this module contacts a service, and nothing can raise confidence
above ``HIGH_CONFIDENCE``. A match means a value has the shape a vendor issues.
It never means the value is live, still valid, or belongs to the repository's
owner. Only an out-of-band check against the issuing service could establish
that, and SecretShield will not do it.
"""

from __future__ import annotations

from typing import Final

from ..masking import FULLY_REDACTED
from ..models import Confidence, SecretCategory, Severity
from .base import DetectorRegistry, Rule, Specificity

__all__ = ["RULES", "default_registry", "rule_by_id"]


_ROTATE = (
    "Treat this as exposed. Rotate the credential at the issuing service, move "
    "the replacement into a secret manager or environment variable, and remove "
    "the original from this repository's history."
)

_REVOKE = (
    "Revoke this credential at the issuing service rather than rotating it, "
    "then remove it from this repository's history. A revoked credential is "
    "safe to have leaked; a rotated one that was committed is not."
)


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------
#
# AWS splits a credential pair in two. The access key *identifier* is public by
# design -- it appears in IAM policies, CloudTrail records and billing exports,
# and on its own it grants nothing. The secret access key is the half that
# matters, and it is a 40-character opaque string with no distinguishing shape.
#
# That asymmetry drives every decision in this section. The identifier has a
# documented prefix and length, so it is matched exactly. The secret does not,
# so a bare 40-character base64-looking run is deliberately NOT reported.


AWS_ACCESS_KEY_ID = Rule(
    id="aws-access-key-id",
    name="AWS access key ID",
    category=SecretCategory.AWS,
    severity=Severity.MEDIUM,
    pattern=r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    specificity=Specificity.EXACT,
    keywords=("aws_access_key_id", "aws_access_key", "access_key_id"),
    min_entropy=2.5,
    priority=10,
    false_positive_notes=(
        "AWS publishes AKIAIOSFODNN7EXAMPLE in its own documentation, and it "
        "is suppressed as a placeholder. AIDA, AROA and ANVA account, role and "
        "policy identifiers are excluded on purpose: they are not credentials, "
        "and matching them would bury the real ones. IAM user ARNs and "
        "CloudTrail records contain identifiers legitimately."
    ),
    remediation=(
        "An access key identifier is only half of a credential and cannot "
        "authenticate on its own, but it tells an attacker which account to "
        "target. Check for a matching secret access key on the same line or in "
        "the same file, and rotate the pair if one is present."
    ),
)

AWS_SECRET_ACCESS_KEY = Rule(
    id="aws-secret-access-key",
    name="AWS secret access key",
    category=SecretCategory.AWS,
    severity=Severity.CRITICAL,
    pattern=r"\b[A-Za-z0-9/+=]{40}\b",
    specificity=Specificity.HEURISTIC,
    base_confidence=Confidence.CANDIDATE,
    keywords=(
        "aws_secret_access_key",
        "aws_secret_key",
        "aws_secret",
        "secret_access_key",
    ),
    requires_context=True,
    min_entropy=3.0,
    priority=11,
    false_positive_notes=(
        "The pattern alone is deliberately inert. A 40-character "
        "[A-Za-z0-9/+=] run is indistinguishable from a SHA-1 in base64, a "
        "compiled asset hash, a certificate fingerprint or an ordinary "
        "high-entropy string, and matching it on shape alone would bury every "
        "other rule in the catalog. The rule therefore fires only when a "
        "strong identifier -- aws_secret_access_key and its spellings -- "
        "appears on the same line, which is what a human naming a variable "
        "honestly would write. "
        "The cost of that choice is a real secret stored under an uninformative "
        "name such as CREDS or VALUE, which this rule will miss; Stage 1's "
        "entropy screen still reports those as MEDIUM/PROBABLE candidates."
    ),
    remediation=(
        "An AWS secret access key grants full access to whatever its IAM user "
        "can reach, including billing and, via iam:PassRole, the ability to "
        "escalate. Disable or delete the key at "
        "https://console.aws.amazon.com/iam/home#/security_credentials and "
        "issue a replacement with a least-privilege policy attached to a role "
        "rather than a long-lived user."
    ),
)


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------
#
# Three documented prefixes, split across two rules.
#
# The legacy `sk-` form is pinned to exactly 48 alphanumerics because that
# length is documented, and pinning it is what makes a truncated key detectable
# rather than merely suspicious. The project and service-account forms have no
# published length, so they are bounded from below only -- guessing a length
# would either miss real keys or start matching prose.
#
# The legacy form gets its own rule so that its severity and remediation can be
# tuned if OpenAI retires the format, without touching the current-prefix
# rules. That separation also keeps the patterns disjoint: overlapping
# alternatives in two rules would report one credential twice, which is a bug,
# not redundancy.


OPENAI_API_KEY = Rule(
    id="openai-api-key",
    name="OpenAI API key (project or service account)",
    category=SecretCategory.OPENAI,
    severity=Severity.HIGH,
    pattern=(
        r"\bsk-proj-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_\-])"
        r"|\bsk-svcacct-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_\-])"
    ),
    specificity=Specificity.EXACT,
    keywords=("openai_api_key", "openai_key", "openai", "api_key"),
    min_entropy=3.0,
    priority=20,
    false_positive_notes=(
        "Neither form has a published length, so a lower bound of 20 "
        "characters stands in; shorter values are more likely to be "
        "documentation than keys. The unbounded upper is deliberate -- greedy "
        "matching to the end of the run plus a negative lookahead makes the "
        "match maximal without a cap that could truncate a long key. "
        "These patterns cannot match the legacy `sk-` form, because the "
        "character after `sk-` would have to be alphanumeric and `proj-` is "
        "not; see openai-api-key-legacy for that. Stripe's `sk_live_` and "
        "`sk_test_` keys match neither, as they carry an underscore after `sk`."
    ),
    remediation=_ROTATE,
)

OPENAI_LEGACY_API_KEY = Rule(
    id="openai-api-key-legacy",
    name="OpenAI API key (legacy format)",
    category=SecretCategory.OPENAI,
    severity=Severity.HIGH,
    pattern=r"\bsk-[A-Za-z0-9]{48}\b",
    specificity=Specificity.EXACT,
    keywords=("openai_api_key", "openai_key", "openai", "api_key"),
    min_entropy=3.0,
    priority=21,
    false_positive_notes=(
        "Kept as a separate rule so its severity and remediation can be "
        "tuned independently if OpenAI retires the format, without disturbing "
        "the current-prefix rules. The pattern is disjoint from openai-api-key "
        "by construction, so a legacy key is reported once and only once: "
        "`sk-` followed by `proj-` or `svcacct-` cannot match here, because "
        "the fourth character would have to be alphanumeric."
    ),
    remediation=_ROTATE,
)


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------
#
# GitHub issues several token families with distinct prefixes. All six are
# matched, but they are not equivalent in impact, and severity is where that
# shows up: a classic personal access token carries broad user-level access,
# while a server or refresh token is issued for one narrow integration.


GITHUB_CLASSIC_PAT = Rule(
    id="github-pat-classic",
    name="GitHub personal access token (classic)",
    category=SecretCategory.GITHUB,
    severity=Severity.HIGH,
    pattern=r"\bgh[pou]_[A-Za-z0-9]{36}\b",
    specificity=Specificity.EXACT,
    keywords=("github_token", "github_pat", "gh_token", "github"),
    min_entropy=2.5,
    priority=30,
    false_positive_notes=(
        "Covers ghp_ (personal), gho_ (OAuth) and ghu_ (user-to-server), "
        "which are all user-scoped and all 36 characters after the prefix. "
        "The length is documented, so a truncated token does not match. "
        "Fixtures made of a real prefix followed by zeros are suppressed by "
        "the entropy floor."
    ),
    remediation=_REVOKE,
)

GITHUB_FINE_GRAINED_PAT = Rule(
    id="github-pat-fine-grained",
    name="GitHub fine-grained personal access token",
    category=SecretCategory.GITHUB,
    severity=Severity.HIGH,
    pattern=r"\bgithub_pat_[A-Za-z0-9_]{22,}(?![A-Za-z0-9_])",
    specificity=Specificity.EXACT,
    keywords=("github_token", "github_pat", "gh_token", "github"),
    min_entropy=2.5,
    priority=31,
    false_positive_notes=(
        "The fine-grained format is `github_pat_` followed by 82 characters "
        "containing underscores, which this rule's alphabet permits. That "
        "exact length is treated as a lower bound rather than pinned, because "
        "a wrong pin would silently miss every future-format token."
    ),
    remediation=_REVOKE,
)

GITHUB_APP_TOKEN = Rule(
    id="github-app-token",
    name="GitHub app or refresh token",
    category=SecretCategory.GITHUB,
    severity=Severity.MEDIUM,
    pattern=r"\bgh[sr]_[A-Za-z0-9]{36}\b",
    specificity=Specificity.EXACT,
    keywords=("github_token", "github_app", "gh_token", "github"),
    min_entropy=2.5,
    priority=32,
    false_positive_notes=(
        "Covers ghs_ (server-to-server) and ghr_ (refresh). Both are issued "
        "for one integration rather than to a person, and both are narrower "
        "in practice than a classic PAT, which is why this is MEDIUM where "
        "github-pat-classic is HIGH. Still worth revoking: a leaked server "
        "token is enough to push commits and read private repositories."
    ),
    remediation=_REVOKE,
)


# ---------------------------------------------------------------------------
# Stripe
# ---------------------------------------------------------------------------
#
# Stripe publishes no key lengths, so every pattern here uses a lower bound of
# 16 characters and an unbounded upper. Pinning an unverified length would be
# the more confident choice and the wrong one.
#
# The three-way severity split is the point of this section. All four rules are
# equally certain that they have found a Stripe key; they differ entirely in
# what that key is worth, which is exactly the difference between severity and
# confidence.


STRIPE_SECRET_KEY_LIVE = Rule(
    id="stripe-secret-key-live",
    name="Stripe live secret key",
    category=SecretCategory.STRIPE,
    severity=Severity.CRITICAL,
    pattern=r"\bsk_live_[A-Za-z0-9]{16,}(?![A-Za-z0-9])",
    specificity=Specificity.EXACT,
    keywords=("stripe", "secret_key", "stripe_key"),
    min_entropy=2.5,
    priority=40,
    false_positive_notes=(
        "Stripe does not publish key lengths, so the body is matched with a "
        "16-character lower bound rather than a pinned length. Test keys are a "
        "separate rule and do not match here."
    ),
    remediation=(
        "A live secret key can read customer data, issue refunds and move "
        "money. Roll the key in the Stripe dashboard, which is safe to do "
        "without downtime, and move the replacement into your secret manager "
        "rather than into source control."
    ),
)

STRIPE_RESTRICTED_KEY_LIVE = Rule(
    id="stripe-restricted-key-live",
    name="Stripe live restricted key",
    category=SecretCategory.STRIPE,
    severity=Severity.HIGH,
    pattern=r"\brk_live_[A-Za-z0-9]{16,}(?![A-Za-z0-9])",
    specificity=Specificity.EXACT,
    keywords=("stripe", "restricted_key", "stripe_key"),
    min_entropy=2.5,
    priority=41,
    false_positive_notes=(
        "Restricted keys are issued with a scoped permission set, so they are "
        "HIGH rather than CRITICAL. That is a judgement about typical "
        "configuration, not a guarantee: a restricted key created with broad "
        "permissions is as damaging as a secret key."
    ),
    remediation=(
        "Review which permissions this restricted key was granted before "
        "revoking it. If the scope is wider than the integration needs, "
        "narrow it rather than relying on the 'restricted' in its name."
    ),
)

STRIPE_TEST_KEY = Rule(
    id="stripe-test-key",
    name="Stripe test-mode key",
    category=SecretCategory.STRIPE,
    severity=Severity.MEDIUM,
    pattern=r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}(?![A-Za-z0-9])",
    specificity=Specificity.EXACT,
    keywords=("stripe", "stripe_key", "test_key"),
    min_entropy=2.5,
    suppress_placeholders=False,
    priority=42,
    false_positive_notes=(
        "Test-mode keys are published in Stripe's own documentation and are "
        "not secrets, so this is MEDIUM rather than CRITICAL: the finding is "
        "usually a documentation reference, and the useful part is learning that "
        "the project has a Stripe integration at all. "
        "suppress_placeholders is disabled here because `test` is a placeholder "
        "word and also part of the vendor prefix; a rule whose own pattern "
        "proves what the value is must not be silenced by a marker inside it."
    ),
    remediation=(
        "A test-mode key does not authenticate against live data, so this is "
        "usually a documentation reference rather than a leak. Confirm no "
        "live key is configured alongside it, and keep test fixtures out of "
        "the production config path entirely."
    ),
)

STRIPE_PUBLISHABLE_KEY = Rule(
    id="stripe-publishable-key",
    name="Stripe publishable key",
    category=SecretCategory.STRIPE,
    severity=Severity.LOW,
    pattern=r"\bpk_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9])",
    specificity=Specificity.EXACT,
    keywords=("stripe", "publishable_key", "stripe_key"),
    min_entropy=2.5,
    suppress_placeholders=False,
    priority=43,
    false_positive_notes=(
        "This is reported at LOW severity on purpose. A publishable key is "
        "embedded in client-side code by Stripe's own design and is not a "
        "secret; it appears in every browser that has ever used the site. The "
        "finding exists so that an inventory of what Stripe keys exist is "
        "complete, not because anyone is exposed. "
        "Expect this rule to match legitimately in any repository with a Stripe "
        "front end."
    ),
    remediation=(
        "No action required: a publishable key is designed to be public. This "
        "is listed so that a key inventory is complete. If a secret key or "
        "restricted key is also present, that is the finding that matters."
    ),
)


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


SLACK_WEBHOOK = Rule(
    id="slack-incoming-webhook",
    name="Slack incoming webhook URL",
    category=SecretCategory.SLACK,
    severity=Severity.MEDIUM,
    pattern=(
        r"https://hooks\.slack\.com/services/"
        r"T[A-Za-z0-9]{8,}(?=[/A-Za-z0-9])/B[A-Za-z0-9]{8,}(?=[/A-Za-z0-9])/"
        r"[A-Za-z0-9]{20,}(?![A-Za-z0-9])"
    ),
    specificity=Specificity.EXACT,
    keywords=("slack", "webhook", "slack_webhook"),
    priority=50,
    false_positive_notes=(
        "The T/B/token path structure is documented, so a Slack URL with a "
        "different path shape does not match. MEDIUM rather than HIGH because "
        "an incoming webhook can post messages to a channel but cannot read "
        "history, enumerate channels, or act as a user. "
        "Fake but structurally plausible webhook URLs appear in documentation, "
        "and are not distinguishable from real ones without contacting Slack, "
        "which SecretShield does not do."
    ),
    remediation=_REVOKE,
)


# ---------------------------------------------------------------------------
# Private keys
# ---------------------------------------------------------------------------
#
# One rule for every header type, because the set is a fixed enumeration and
# six near-identical rules would only make ordering harder to reason about.
# `PUBLIC KEY` and `CERTIFICATE` are absent by construction: the pattern
# requires the literal words `PRIVATE KEY`, so a public certificate can never
# become a private-key finding.
#
# The optional body group is greedy by default, so the engine tries to consume
# the whole block first and falls back to the bare header when the footer is
# missing. That means a truncated key -- a paste cut off mid-block -- is still
# reported, which is the case that matters.


PRIVATE_KEY = Rule(
    id="private-key-block",
    name="Private key block",
    category=SecretCategory.PRIVATE_KEY,
    severity=Severity.CRITICAL,
    pattern=(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]{0,40000}?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)?"
    ),
    specificity=Specificity.EXACT,
    priority=60,
    mask_policy=FULLY_REDACTED,
    false_positive_notes=(
        "Matches RSA, DSA, EC, OPENSSH, PGP and ENCRYPTED private key headers. "
        "`-----BEGIN PUBLIC KEY-----` and `-----BEGIN CERTIFICATE-----` do not "
        "match and must not, because public keys and certificates are designed "
        "to be published and including them would drown the private ones. "
        "The body is bounded at 40000 characters so that a missing footer "
        "cannot turn one unterminated header into a whole-file match. "
        "Documentation that shows a key header without a body is still reported, "
        "which is the intended trade: a header with no key after it is far more "
        "often a real leak than an article discussing key formats."
    ),
    remediation=(
        "A private key grants whoever holds it the ability to impersonate its "
        "owner: sign code, sign artefacts, decrypt anything encrypted to the "
        "matching public key. Generate a replacement key pair, re-sign or "
        "re-encrypt whatever the old one protected, revoke the old key at the "
        "issuing authority, and purge the block from repository history."
    ),
)


# ---------------------------------------------------------------------------
# Database connection strings
# ---------------------------------------------------------------------------
#
# One rule, because the evidence is identical across schemes: a recognised
# database scheme, a username, and a password. Severity does not vary by engine
# because the impact does not -- a production database credential is a
# production database credential.
#
# The password is captured as a named group so the finding reports the password
# rather than the whole URI. That matters for redaction: the masked value should
# not reveal a host and database name, which are not secrets and are often
# useful reconnaissance for whoever reads a report.


DATABASE_URI = Rule(
    id="database-uri-with-password",
    name="Database connection string with password",
    category=SecretCategory.DATABASE,
    severity=Severity.CRITICAL,
    pattern=(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)"
        r"://[^\s:/@\[\]]+:(?P<secret>[^\s:/@]{4,})@[^\s:/@]+"
    ),
    specificity=Specificity.EXACT,
    keywords=("database_url", "db_url", "dsn", "connection_string"),
    priority=70,
    false_positive_notes=(
        "A URI without a password component does not match: `postgres://host"
        ":5432/db` and `mysql://root@127.0.0.1/db` are both rejected, because "
        "the pattern requires `user:password@`. A password shorter than four "
        "characters is treated as filler rather than a credential. "
        "An unfilled interpolation, as in `postgres://u:${PG_PASS}@host/db`, "
        "matches the pattern and is then suppressed as a template, so the "
        "username, host and database name are not reported as a secret. "
        "A raw `@` inside a password is not valid URI syntax and must be "
        "percent-encoded; an unencoded one truncates the captured password, "
        "which loses the value but does not leak it."
    ),
    remediation=(
        "A database password in source control usually grants far more than "
        "the application needs. Rotate it, then reduce the new account's "
        "privileges to exactly what the application queries, and load it from "
        "the environment or a secret manager instead of committing a URI."
    ),
)


#: Every shipped rule. Order here does not matter: the registry sorts by
#: ``(priority, id)`` so that ordering is a property of the data, not of the
#: source layout.
RULES: Final[tuple[Rule, ...]] = (
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    OPENAI_API_KEY,
    OPENAI_LEGACY_API_KEY,
    GITHUB_CLASSIC_PAT,
    GITHUB_FINE_GRAINED_PAT,
    GITHUB_APP_TOKEN,
    STRIPE_SECRET_KEY_LIVE,
    STRIPE_RESTRICTED_KEY_LIVE,
    STRIPE_TEST_KEY,
    STRIPE_PUBLISHABLE_KEY,
    SLACK_WEBHOOK,
    PRIVATE_KEY,
    DATABASE_URI,
)

#: Identifier used by the self-scan test and by reports that need to name the
#: shipped rule set.
CATALOG_VERSION: Final[str] = "2"


def default_registry() -> DetectorRegistry:
    """Return a fresh registry containing every shipped rule.

    A new registry is built per call so that a caller which registers an extra
    rule cannot mutate the catalog seen by anyone else.

    Raises:
        ValueError: If the catalog itself is malformed, which would be a bug in
            this module rather than in the caller's input.
    """

    return DetectorRegistry(RULES)


def rule_by_id(rule_id: str) -> Rule:
    """Return one shipped rule by id.

    Raises:
        KeyError: If the catalog has no such rule.
    """

    for rule in RULES:
        if rule.id == rule_id:
            return rule
    raise KeyError(f"no catalog rule with id {rule_id!r}")
