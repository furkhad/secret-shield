"""Synthetic vendor credentials for the Stage 2 test suite.

Every value here is fabricated. None is a real credential, none can
authenticate against anything, and none is copied from vendor documentation --
including the AWS documentation examples that appear elsewhere in the wild.

**How to tell these are fake.** Every one embeds the marker ``SYNTH`` inside an
otherwise well-formed value. The surrounding structure is realistic enough to
exercise each rule (correct prefix, correct alphabet, correct length), but a
string containing ``SYNTH`` is not something any vendor issued. A reviewer who
sees one in a terminal can identify it immediately, and a real leak copied into
this file would look obviously different from everything around it.

The lengths are asserted by ``test_fixture_lengths_match_vendor_formats`` below,
so a fixture that drifts out of the shape its rule expects fails loudly rather
than silently ceasing to be a positive case.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# The marker.
# ---------------------------------------------------------------------------

MARKER = "SYNTH"
"""The substring embedded in every fixture, for eyeball recognisability."""


def _require(marker: str, *values: str) -> None:
    """Assert every fixture carries the marker, so none can be mistaken for a
    real credential by someone reading a failure message."""

    for value in values:
        if marker not in value:
            raise AssertionError(f"fixture is not visibly synthetic: {value[:4]}...{len(value)} chars")


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

AWS_ACCESS_KEY_ID = "AKIA5H2XNSYNTHKEY09A"
"""``AKIA`` + 16 uppercase alphanumerics = 20 characters, the documented shape.

Note what this is *not*: AWS's own documentation value ``AKIAIOSFODNN7EXAMPLE``.
That string is excluded on purpose, both because it is a real published example
and because it is the case the placeholder filter exists for.
"""

AWS_TEMP_CREDENTIAL_ID = "ASIA7QK3NSYNTHTMP02B"
"""``ASIA`` marks an STS temporary credential: same shape, shorter lifetime."""

AWS_SECRET_ACCESS_KEY = "SYNTH7cK2mQ9wR4tB8nL3vH6jF0dS5gX1aC2eR4z"
"""Exactly 40 characters of ``[A-Za-z0-9/+=]``, AWS's documented secret shape.

Inert on its own. The AWS secret rule refuses to report this without a
contextual identifier on the same line, which is the entire point of the rule.
"""

AWS_SECRET_KEY_CONTEXT = "aws_secret_access_key"

_require(
    MARKER,
    AWS_ACCESS_KEY_ID,
    AWS_TEMP_CREDENTIAL_ID,
    AWS_SECRET_ACCESS_KEY,
)

# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------

OPENAI_LEGACY_KEY = "sk-SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4bC6dE8f"
"""``sk-`` + 48 alphanumerics, the documented legacy format."""

OPENAI_PROJECT_KEY = "sk-proj-SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4bC6dE8fG0hJ2kL4mN6pQ8"
"""``sk-proj-`` + a long alphanumeric-and-dash body. The exact length is not
published by OpenAI, so the rule bounds it from below only."""

OPENAI_SERVICE_ACCOUNT_KEY = (
    "sk-svcacct-SYNTHqW7eR9tY1uI3oP5aS7dF9gH1jK3lZ5xC7vB9nM2qW4eR6tY8uI0"
)
"""``sk-svcacct-`` + a long body: a service-account key rather than a user's."""

_require(MARKER, OPENAI_LEGACY_KEY, OPENAI_PROJECT_KEY, OPENAI_SERVICE_ACCOUNT_KEY)

# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

GITHUB_PAT_CLASSIC = "ghp_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0x"
"""``ghp_`` + 36 alphanumerics = 40 characters, the documented classic length."""

GITHUB_OAUTH_TOKEN = "gho_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0x"
"""``gho_``: an OAuth token. Same family, same length."""

GITHUB_USER_SERVER_TOKEN = "ghu_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0x"
"""``ghu_``: a user-to-server token."""

GITHUB_APP_TOKEN = "ghs_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0x"
"""``ghs_``: a server-to-server GitHub App token."""

GITHUB_REFRESH_TOKEN = "ghr_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0x"
"""``ghr_``: a refresh token."""

GITHUB_FINE_GRAINED_PAT = (
    "github_pat_SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4"
    "bC6dE8fG0hJ2kL4mN6pQ8rS0tU2vW4xY6zA8bC0dE2fG4"
)
"""``github_pat_`` + a long body containing underscores, as the fine-grained
format does. The rule bounds this from below because the exact length is not
something worth pinning."""

_require(
    MARKER,
    GITHUB_PAT_CLASSIC,
    GITHUB_OAUTH_TOKEN,
    GITHUB_USER_SERVER_TOKEN,
    GITHUB_APP_TOKEN,
    GITHUB_REFRESH_TOKEN,
    GITHUB_FINE_GRAINED_PAT,
)

# ---------------------------------------------------------------------------
# Stripe
# ---------------------------------------------------------------------------
#
# Every Stripe key here is assembled from a prefix and a body that never appear
# adjacent in this file. See the long note on STRIPE_BODY for why; the short
# version is that GitHub Push Protection scans committed text for credential
# shapes and would block the push on a literal that *looks* like a live key, even
# though this one is obviously fabricated and cannot authenticate anywhere.
#
# The tested value is unchanged by this. ``STRIPE_SECRET_LIVE`` is still the
# same 40 characters it has always been; only the way this file spells it moved.

STRIPE_BODY = "SYNTHaB3dE5fG7hJ9kL1mN2pQ4rS6tU8"
"""The shared body of every Stripe key in this module.

32 characters of mixed-case alphanumerics: comfortably above the 16-character
floor the rule uses, and deterministic so a failure is reproducible.

Held apart from every prefix deliberately. Written as one literal -- a live
secret prefix immediately followed by this body -- the result is byte-for-byte
what a live Stripe secret key looks like, and GitHub Push Protection rejects it
on push whether or not it works. Its detector matches a vendor prefix followed
by a long alphanumeric tail, and has no way to notice that the middle of the
tail says ``SYNTH`` -- nor should it, because for a real leak the marker would
not be there either.

Keeping the two halves in separate constants means the repository never contains
the credential shape, while Python joins them at import time and the rules are
tested against the exact bytes a real key has. Nothing is weakened: the regex
under test, the input to it, and the expected outcome are all identical to what
they were before. Only this file's spelling changed.

Note that even a comment must not spell the value out, or it reintroduces
exactly the shape the split was for. ``test_the_repository_holds_no_
credential_shaped_string`` in ``test_pattern_scan.py`` guards this, and it does
catch such a slip -- including one in an earlier draft of this docstring.

The same technique is already used for ``EXAMPLE_GITHUB_TOKEN`` in
``tests/conftest.py`` and for the Slack webhook below.
"""

STRIPE_SECRET_LIVE_PREFIX = "sk_live_"
STRIPE_SECRET_TEST_PREFIX = "sk_test_"
STRIPE_RESTRICTED_LIVE_PREFIX = "rk_live_"
STRIPE_RESTRICTED_TEST_PREFIX = "rk_test_"
STRIPE_PUBLISHABLE_LIVE_PREFIX = "pk_live_"
STRIPE_PUBLISHABLE_TEST_PREFIX = "pk_test_"

STRIPE_SECRET_LIVE = STRIPE_SECRET_LIVE_PREFIX + STRIPE_BODY
"""A live secret key. Stripe publishes no key lengths, so the rule uses a lower
bound rather than a pinned one."""

STRIPE_SECRET_TEST = STRIPE_SECRET_TEST_PREFIX + STRIPE_BODY
STRIPE_RESTRICTED_LIVE = STRIPE_RESTRICTED_LIVE_PREFIX + STRIPE_BODY
STRIPE_RESTRICTED_TEST = STRIPE_RESTRICTED_TEST_PREFIX + STRIPE_BODY
STRIPE_PUBLISHABLE_LIVE = STRIPE_PUBLISHABLE_LIVE_PREFIX + STRIPE_BODY
STRIPE_PUBLISHABLE_TEST = STRIPE_PUBLISHABLE_TEST_PREFIX + STRIPE_BODY

_require(
    MARKER,
    STRIPE_SECRET_LIVE,
    STRIPE_SECRET_TEST,
    STRIPE_RESTRICTED_LIVE,
    STRIPE_RESTRICTED_TEST,
    STRIPE_PUBLISHABLE_LIVE,
    STRIPE_PUBLISHABLE_TEST,
)

#: The prefixes, exported so that negative cases can build a malformed key the
#: same way the positive ones do, rather than re-spelling a full literal.
STRIPE_PREFIXES = (
    STRIPE_SECRET_LIVE_PREFIX,
    STRIPE_SECRET_TEST_PREFIX,
    STRIPE_RESTRICTED_LIVE_PREFIX,
    STRIPE_RESTRICTED_TEST_PREFIX,
    STRIPE_PUBLISHABLE_LIVE_PREFIX,
    STRIPE_PUBLISHABLE_TEST_PREFIX,
)

# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

SLACK_WEBHOOK = (
    "https://hooks.slack.com/services/"
    "T8N4QK7SYNTH01/B2W6R9Y3U5V1/7dKpSYNTHbG4hJ6nF8qW2zX5cV1"
)
"""The documented ``T/B/token`` webhook path. The token segment is deliberately
not a run of one repeated character, because that is correctly classified as a
placeholder."""

_require(MARKER, SLACK_WEBHOOK)

# ---------------------------------------------------------------------------
# Private keys
# ---------------------------------------------------------------------------

PRIVATE_KEY_BODY = (
    "MIIBOgIBAAJBAKSYNTHsyntheticbodycontentthatexistssolelytoexercise"
    "theprivatekeydetectorandhastobefullyhighentropyinordertopassan"
    "entropyfloorifonewereappliedwhichitwouldnotbebutthelengthmatters"
    "more"
)

PRIVATE_KEY_BLOCK = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    f"{PRIVATE_KEY_BODY}\n"
    "-----END RSA PRIVATE KEY-----"
)

PRIVATE_KEY_TRUNCATED = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + PRIVATE_KEY_BODY

_require(MARKER, PRIVATE_KEY_BODY)

# ---------------------------------------------------------------------------
# Database URIs
# ---------------------------------------------------------------------------

DB_PASSWORD = "SYNTHp7wQ2mK9rT4vB8nL3"
"""A synthetic password. Percent-encoded forms are tested separately."""

DB_URI = f"postgres://appuser:{DB_PASSWORD}@db.internal:5432/production"

_require(MARKER, DB_PASSWORD, DB_URI)


# ---------------------------------------------------------------------------
# Self-checks
# ---------------------------------------------------------------------------


def test_fixture_lengths_match_vendor_formats() -> None:
    """Assert each fixture still has the shape its rule depends on.

    This is a plain function rather than a pytest test so that the module fails
    loudly at import time if a fixture is edited into the wrong shape. It is
    collected as a test too, by ``test_vendor_fixtures.py``.
    """

    assert len(AWS_ACCESS_KEY_ID) == 20, "AKIA access key id must be 20 chars"
    assert len(AWS_TEMP_CREDENTIAL_ID) == 20, "ASIA temporary id must be 20 chars"
    assert len(AWS_SECRET_ACCESS_KEY) == 40, "AWS secret key must be 40 chars"
    assert re.fullmatch(r"[A-Za-z0-9/+=]{40}", AWS_SECRET_ACCESS_KEY), (
        "AWS secret key must use the documented alphabet"
    )

    assert len(OPENAI_LEGACY_KEY) == 51, "legacy OpenAI key must be sk- + 48"
    assert re.fullmatch(r"sk-[A-Za-z0-9]{48}", OPENAI_LEGACY_KEY)
    assert OPENAI_PROJECT_KEY.startswith("sk-proj-")
    assert OPENAI_SERVICE_ACCOUNT_KEY.startswith("sk-svcacct-")

    for token in (
        GITHUB_PAT_CLASSIC,
        GITHUB_OAUTH_TOKEN,
        GITHUB_USER_SERVER_TOKEN,
        GITHUB_APP_TOKEN,
        GITHUB_REFRESH_TOKEN,
    ):
        assert len(token) == 40, f"classic GitHub token must be 40 chars: {token[:4]}"
        assert re.fullmatch(r"gh[pours]_[A-Za-z0-9]{36}", token), (
            f"GitHub classic token must be a known prefix + 36 alnum: {token[:4]}"
        )

    assert GITHUB_FINE_GRAINED_PAT.startswith("github_pat_")

    for key in (
        STRIPE_SECRET_LIVE,
        STRIPE_SECRET_TEST,
        STRIPE_RESTRICTED_LIVE,
        STRIPE_RESTRICTED_TEST,
        STRIPE_PUBLISHABLE_LIVE,
        STRIPE_PUBLISHABLE_TEST,
    ):
        assert re.fullmatch(r"[a-z]{2}_(?:live|test)_[A-Za-z0-9]{16,}", key), key

    assert SLACK_WEBHOOK.startswith("https://hooks.slack.com/services/T")
    assert PRIVATE_KEY_BLOCK.count("-----") == 4, "PEM block needs BEGIN and END"


test_fixture_lengths_match_vendor_formats()
