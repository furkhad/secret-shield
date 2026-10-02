"""Context heuristics: the cheap signals that separate data from filler.

Entropy and patterns answer "what does this value look like?". They cannot
answer "is this the kind of thing a person would leave in a repository?", and
that second question is where most false positives live. Documentation is full
of credentials that were never issued, templating systems are full of values
that get filled in later, and variable names carry an enormous amount of
information about what a value is for.

Five small helpers live here. Each is a pure function of its arguments,
each is documented with what it rejects *and what it costs*, and each is cheap
enough to run on every match.

Nothing in this module grows a rule engine. It cannot decide a severity, it
cannot reach the network, and it cannot invent a threshold. Its whole job is
to answer yes/no questions that the catalog asks.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = [
    "CONTEXT_VOCABULARY",
    "HASH_LENGTHS",
    "assignment_name",
    "is_placeholder",
    "is_template_expression",
    "keyword_score",
    "looks_like_hash",
    "normalize_for_matching",
]

#: Words that indicate a line is about a credential. Matched on word boundaries,
#: case-insensitively, with ``-`` and ``_`` treated as the same character.
#:
#: This is the *generic* vocabulary. A rule's own ``keywords`` are separate and
#: stricter; see :func:`keyword_score`.
#:
#: Multi-word entries exist because ``api_key`` and ``api-key`` and ``APIKey``
#: should all count once. The list is deliberately short: every entry here
#: raises the confidence of a HEURISTIC match, so a word that appears in
#: unrelated prose costs precision on every scan.
CONTEXT_VOCABULARY: Final[tuple[str, ...]] = (
    "api-key",
    "api-secret",
    "access-key",
    "access-token",
    "auth-token",
    "client-secret",
    "credential",
    "credentials",
    "encryption-key",
    "passphrase",
    "password",
    "passwd",
    "private-key",
    "refresh-token",
    "secret",
    "secrets",
    "signing-key",
    "token",
    "webhook",
)

#: Lengths, in hex characters, of the digests that appear everywhere in a
#: repository and are never credentials.
#:
#: 32 is MD5, 40 is SHA-1 and a git object id, 64 is SHA-256. A value of
#: exactly one of these lengths, containing only hex, is a checksum far more
#: often than it is a secret.
#:
#: Note:
#:     This is *not* applied to the entropy rule. Stage 1 deliberately reports
#:     inert random material rather than hiding it, because a missed secret
#:     costs more than a review item. It is opt-in per pattern rule, via
#:     ``Rule.reject_hashes``, for rules whose owner knows the shape cannot be
#:     anything else.
HASH_LENGTHS: Final[frozenset[int]] = frozenset({32, 40, 64})

_ASSIGNMENT_TAIL: Final[re.Pattern[str]] = re.compile(
    r"""
    (?:^|[\s,{\[(])            # the name starts a line or follows a delimiter
    [\"']?                     # optional opening quote: "api_key":
    (?P<name>[A-Za-z_][A-Za-z0-9_.\-]*)   # the name itself
    [\"']?                     # optional closing quote
    \]?                        # optional bracket, for environ["KEY"] =
    \s*                        # space around the operator
    (?::=|=>|[:=])             # the assignment operator
    \s*
    [\"']?                     # optional opening quote of the value itself
    \s*$
    """,
    re.VERBOSE,
)

_SEPARATOR_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")

_WORD_SPLIT: Final[re.Pattern[str]] = re.compile(r"[a-z0-9]+")

#: Folds runs of ``-`` and ``_`` to a single space, so that a multi-word
#: placeholder can be written once and match every spelling convention.
_SEPARATOR_FOLD: Final[re.Pattern[str]] = re.compile(r"[-_]+")


def _build_word_pattern(word: str) -> re.Pattern[str]:
    """Compile one vocabulary entry into a word-boundary-aware pattern.

    Every pair of adjacent letters may be separated by a single ``-`` or ``_``,
    so a single entry covers ``api-key``, ``api_key``, ``apikey`` and
    ``API_KEY``. Lookarounds on both sides reject a match that is merely
    embedded in a longer identifier, which is what stops ``tokenizer`` counting
    as ``token`` and ``secretary`` counting as ``secret``.

    Lookarounds rather than ``\\b``: the vocabulary already contains ``-``, and a
    hyphen is not a word character, so ``\\b`` would demand a boundary that does
    not exist after one.
    """

    return re.compile(
        rf"(?<![A-Za-z0-9]){'[-_]?'.join(word.replace('-', ''))}(?![A-Za-z0-9])",
        re.IGNORECASE,
    )


#: One compiled pattern per vocabulary entry, so that counting *which* concepts
#: are present is exact and cannot double-count an entry matched twice.
_VOCABULARY_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    _build_word_pattern(word) for word in CONTEXT_VOCABULARY
)

#: Placeholder markers matched as whole words only, so that a short marker
#: cannot corrupt a real credential that happens to contain those letters.
#:
#: Every entry here is a *single* word. Multi-word markers like
#: ``your-api-key-here`` live in :data:`_PLACEHOLDER_PHRASES` instead, because
#: word splitting would tear them into ``your``, ``api``, ``key`` and ``here``
#: and none of those is a placeholder on its own.
#:
#: ``test`` belongs in this set even though it is only four characters, and it
#: is the one entry with real consequences: ``sk_test_...`` and
#: ``redis://:test@host`` contain it as a whole word. Rules whose own pattern
#: already proves what the value is opt out with ``Rule.suppress_placeholders``;
#: see the Stripe catalog entries.
_PLACEHOLDER_WORDS: Final[frozenset[str]] = frozenset(
    {
        "changeme",
        "dummy",
        "example",
        "fake",
        "fixme",
        "mock",
        "notreal",
        "placeholder",
        "redacted",
        "sample",
        "test",
        "testing",
        "todo",
        "xxxxx",
    }
)

#: Multi-word placeholder markers, stored with ``-`` and ``_`` already folded to
#: a single space. :func:`is_placeholder` applies the same fold to the value
#: before testing, so one entry covers ``your-api-key``, ``your_api_key``,
#: ``your api key`` and every mixture of the three.
#:
#: These are matched as substrings of the *space-normalised* value rather than
#: as whole words. That is safe here because every entry is three or more words
#: long and no generated credential contains them.
_PLACEHOLDER_PHRASES: Final[tuple[str, ...]] = (
    "insert key here",
    "replace me",
    "your api key",
    "your api key here",
    "your key here",
    "your password here",
    "your secret here",
    "your token here",
)

#: Placeholder markers matched anywhere in the value. Every entry is at least
#: five specific characters, so random material cannot plausibly contain one.
#:
#: Both separator spellings appear for each concept (``change_me`` and
#: ``change-me``) because a reader writes whichever their ecosystem uses, and
#: missing one is a false positive in every ``.env.example`` written that way.
_PLACEHOLDER_SUBSTRINGS: Final[tuple[str, ...]] = (
    "change_me",
    "changeme",
    "change-me",
    "example",
    "insert-key-here",
    "placeholder",
    "redacted",
    "replace_me",
    "replaceme",
    "replace-me",
    "your_api_key",
    "your-api-key",
    "your_key",
    "your-key",
    "yourkey",
    "your-secret",
    "yoursecret",
    "your-token",
    "yourtoken",
    "xxxxxx",
)

#: Template syntaxes, as ``(opening, closing)``. A value that is entirely one
#: of these is filled in by a templating engine at deploy time, so it is
#: documentation of a value, not the value.
#:
#: The first group is inherited from Stage 1's tokenizer so that the Stage 2
#: engine recognises everything Stage 1 recognised. The ``%...%`` form is added
#: here: Windows batch expansion is common in deployment scripts and Docker
#: entrypoints, which is exactly where a connection string appears.
#:
#: The ``%...%`` entry is the loosest match in this list, because ``%`` is a
#: common character. It fires only when the value both starts and ends with
#: ``%`` and has at least one character between them, so the accepted cost is a
#: real password that begins *and* ends with a percent sign. That is rare enough
#: to be worth the catch, and it is asserted as a known trade-off in
#: ``test_context.py``.
_TEMPLATE_PAIRS: Final[tuple[tuple[str, str], ...]] = (
    ("${", "}"),      # shell, Terraform, JavaScript template literals
    ("{{", "}}"),     # Jinja, Handlebars, Mustache
    ("<%", "%>"),      # ERB, ASP
    ("@{", "}"),      # ASP.NET Razor
    ("$(", ")"),      # shell command substitution
    ("{%", "%}"),      # Jinja and Liquid statements
    ("%(", ")"),      # printf substitution
    ("%(", "s"),      # printf with a trailing type code, as in %(name)s
    ("%", "%"),      # Windows batch expansion, as in %DB_PASSWORD%
)

_HEX_PATTERN: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-fA-F]+\Z")


def normalize_for_matching(text: str) -> str:
    """Reduce text to lower-case alphanumerics for forgiving comparisons.

    ``AWS_SECRET_ACCESS_KEY``, ``aws-secret-access-key`` and
    ``AwsSecretAccessKey`` all collapse to ``awssecretaccesskey``. That is
    deliberate for *presence* checks: the question is whether a concept appears
    near a value, not whether the spelling is exact.

    Do not use this to compare secrets. It destroys structure and would make
    two distinct credentials collide.

    Args:
        text: Any string. Non-strings raise.

    Returns:
        Lower-case text with every run of non-alphanumeric characters removed.
    """

    if not isinstance(text, str):
        raise TypeError(f"normalize_for_matching() expects str, got {type(text).__name__}")
    return _SEPARATOR_PATTERN.sub("", text.lower())


def assignment_name(line: str, column: int) -> str | None:
    """Return the name of the variable a value was assigned to.

    This is the single most informative piece of context available, because
    people name things honestly. ``aws_secret_access_key = "..."`` tells you
    what the value is far more reliably than the value's shape does.

    Recognises assignment operators ``=``, ``:``, ``=>`` and ``:=`` across
    Python, JSON, YAML, TOML, JavaScript and shell, including the quoted-key
    and subscript forms::

        API_KEY = "..."                  -> API_KEY
        "api_key": "..."                 -> api_key
        this.password = "..."            -> password
        export TOKEN=...                 -> TOKEN
        os.environ["AWS_KEY"] = "..."    -> AWS_KEY

    Args:
        line: The full text of the line.
        column: 1-based column of the value. Text before it is searched.

    Returns:
        The name, or ``None`` when the value is not preceded by an assignment.

    Note:
        A line with no assignment -- a URI on its own, a value inside a JSON
        array -- yields ``None``, which is an honest answer rather than a
        guess.
    """

    if not isinstance(line, str):
        raise TypeError(f"assignment_name() expects str, got {type(line).__name__}")
    if isinstance(column, bool) or not isinstance(column, int):
        raise TypeError(f"column must be an int, got {type(column).__name__}")
    if column < 1:
        raise ValueError("column is 1-based and must be at least 1")

    prefix = line[: column - 1]
    match = _ASSIGNMENT_TAIL.search(prefix)
    return match.group("name") if match else None


def keyword_score(line: str) -> int:
    """Score how strongly a line reads as being about a credential.

    Counts distinct generic credential words present in ``line``. A score above
    zero raises a HEURISTIC match by one confidence step; the size of the score
    does not matter, because a line naming five credential words is not five
    times as likely to hold one.

    Matching is case-insensitive, treats ``-`` and ``_`` as interchangeable,
    and requires word boundaries, so ``my_api_key_v2`` counts as one hit while
    ``tokenizer`` and ``secretary`` count for nothing.

    Args:
        line: The full text of the line.

    Returns:
        The number of distinct vocabulary words found, ``0`` when none are.

    Raises:
        TypeError: If ``line`` is not a string.

    Note:
        This is a weak signal by construction. ``token = "x"`` in a comment or a
        docstring scores the same as the real thing, which is why it only ever
        moves confidence one step and never suppresses a match on its own.
    """

    if not isinstance(line, str):
        raise TypeError(f"keyword_score() expects str, got {type(line).__name__}")

    spans = []
    for pattern in _VOCABULARY_PATTERNS:
        found = pattern.search(line)
        if found is not None:
            spans.append(found.span())

    # Overlapping vocabulary entries would otherwise count one concept twice:
    # "access_token" matches both "access-token" and "token". Keep only matches
    # that are not contained in an earlier one, so the score counts distinct
    # concepts. Sorting by start then by decreasing end puts the widest match at
    # each position first.
    spans.sort(key=lambda span: (span[0], -span[1]))
    covered = 0
    count = 0
    for start, end in spans:
        if end > covered:
            count += 1
            covered = end
    return count


def is_placeholder(value: str) -> bool:
    """Return ``True`` when a value is documented filler rather than a secret.

    Covers the markers that appear in README files, ``.env.example`` templates
    and documentation: ``EXAMPLE``, ``changeme``, ``YOUR_KEY_HERE``,
    ``redacted``, ``xxxxxxxxxx``, ``dummy``.

    Three checks, in increasing cost and decreasing bluntness:

    1. **Substrings**, for single markers long enough that random material
       cannot plausibly contain one.
    2. **Whole words**, for short markers like ``test``. Matching these
       anywhere would corrupt every real credential that happens to contain
       the letters.
    3. **Phrases**, for multi-word markers, with ``-`` and ``_`` folded to
       spaces so one entry covers every spelling convention.

    This is a hard filter, and a hard filter that is wrong costs a real
    detection. Every list is therefore short and every entry is specific; the
    cost of each is recorded in the module-level constants.

    Args:
        value: The candidate text.

    Returns:
        ``True`` when the value carries a placeholder marker.

    Raises:
        TypeError: If ``value`` is not a string.
    """

    if not isinstance(value, str):
        raise TypeError(f"is_placeholder() expects str, got {type(value).__name__}")

    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_SUBSTRINGS):
        return True
    if set(_WORD_SPLIT.findall(lowered)) & _PLACEHOLDER_WORDS:
        return True

    spaced = _SEPARATOR_FOLD.sub(" ", lowered)
    return any(phrase in spaced for phrase in _PLACEHOLDER_PHRASES)


def is_template_expression(value: str) -> bool:
    """Return ``True`` when a value is entirely a template placeholder.

    Recognised syntaxes::

        ${VAR}      shell, Terraform, JavaScript template literals
        {{ secrets.x }}  Jinja, Handlebars, Mustache
        {{TOKEN}}
        %VAR%       Windows batch
        <%= token %> ERB, ASP
        @{VAR}      ASP.NET Razor
        $(cmd)      shell command substitution

    Only a value that is *entirely* an interpolation counts. A value that
    embeds one among literal text -- ``postgres://u:${PW}@host/db`` -- is not a
    template, and suppressing it would discard a real username, host and
    database name along with the filler.

    Args:
        value: The candidate text.

    Returns:
        ``True`` when the whole value is an interpolation.
    """

    if not isinstance(value, str):
        raise TypeError(f"is_template_expression() expects str, got {type(value).__name__}")

    trimmed = value.strip()
    for opening, closing in _TEMPLATE_PAIRS:
        if not trimmed.startswith(opening) or not trimmed.endswith(closing):
            continue
        # Require content between the delimiters: "${}" is an empty expansion,
        # not evidence that a templating engine filled anything in.
        if len(trimmed) >= len(opening) + len(closing) + 1:
            return True
    return False


def looks_like_hash(value: str) -> bool:
    """Return ``True`` when a value has the shape of a known checksum.

    MD5, SHA-1 and SHA-256 are 32, 40 and 64 hex characters. Values of exactly
    those lengths, containing only hex, are digests far more often than secrets.

    Intended for rules that opt in via ``Rule.reject_hashes``. It is
    deliberately *not* applied to the entropy rule: Stage 1 reports inert random
    material on purpose, and a 32-character hex API key is a plausible secret
    that this shape cannot distinguish from an MD5 sum. Deciding that is a
    judgement for whoever owns the rule, informed by context, not a default.

    Args:
        value: The candidate text.

    Returns:
        ``True`` when the value is hex of a recognised digest length.
    """

    if not isinstance(value, str):
        raise TypeError(f"looks_like_hash() expects str, got {type(value).__name__}")

    return len(value) in HASH_LENGTHS and bool(_HEX_PATTERN.match(value))