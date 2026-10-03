"""Conservative candidate extraction for entropy analysis.

Entropy is only meaningful when it is applied to something that *could* be a
credential. Running it over whole lines of source code produces thousands of
false positives: minified JavaScript, lock files and compressed assets are
mostly high-entropy noise.

So this module does the opposite of a general-purpose scanner. It extracts a
small number of plausible token values -- quoted literals and the right-hand
sides of assignments -- and throws away the obvious non-secrets before anything
downstream sees them. The expensive and clever filtering (context scoring,
allowlists, correlation with rule metadata) belongs to a later stage; this
stage deliberately stops at cheap, explainable structural filters.

**Why the code-shape filters exist.** Running entropy over the quoted strings
of this repository's own source produced 64 candidates, and every single one was
a name, a format string or a pattern. Entropy cannot tell a Python constant
from a credential: both are long mixed-character strings measuring above every
threshold. :func:`has_non_secret_structure` is the correction, and with it the
same scan produces nothing.

**What this tokenizer is not.** It is not a language parser. It is a
single-pass scanner that understands quoting and ``=`` well enough to avoid
reporting whole files as single tokens. It has no comment or string syntax
tables, because a wrong guess there is worse than missing a candidate: the
structural filters here are the last line of defence against noise.

Every candidate carries its own raw value because the entropy measurement needs
the real text. That value lives only inside a :class:`Token`, which is created
and consumed within a single call to :func:`candidates`. Tokens are never
stored, reported or serialized; the caller converts them into a
:class:`~secret_shield.models.Finding`, which cannot hold raw material.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

__all__ = [
    "Token",
    "candidates",
    "has_non_secret_structure",
    "has_repetitive_structure",
    "is_placeholder",
    "is_template_expression",
    "looks_like_placeholder_or_template",
]

_QUOTE_CHARACTERS: Final[frozenset[str]] = frozenset("\"'`")
_ESCAPE_CHARACTER: Final[str] = "\\"

#: Characters an unquoted assignment value may contain. This covers identifiers,
#: numbers, and the punctuation that appears inside URLs, DSNs and paths.
#: Anything outside this set terminates the token, which keeps a statement like
#: ``a=b=c`` from swallowing the rest of the line.
_UNQUOTED_CHARACTERS: Final[frozenset[str]] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-+/.:~@%"
)

_IDENTIFIER_CHARACTERS: Final[frozenset[str]] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)

#: Markers that mean "this text is an instruction to a template engine, not a
#: secret". Matched against the whole trimmed value only. A value that merely
#: *contains* an interpolation, such as ``"Bearer ${TOKEN}"``, is deliberately
#: kept: the literal part around the interpolation is exactly where a
#: credential gets pasted in.
_EXACT_TEMPLATE_VALUES: Final[frozenset[str]] = frozenset(
    {"${...}", "{{...}}", "${}", "{}", "{{}}", "%...%", "...", "<%...%>", "@{...}"}
)

_TEMPLATE_PAIRS: Final[tuple[tuple[str, str], ...]] = (
    ("${", "}"),
    ("{{", "}}"),
    ("<%", "%>"),
    ("%(", ")"),
    # Python's printf form is "%(name)s", which ends in the type code rather
    # than a closing parenthesis.
    ("%(", "s"),
    ("@{", "}"),
    ("$(", ")"),
)

#: Distinctive placeholder words. These are matched as substrings because a
#: placeholder is usually embedded in punctuation or other filler, as in
#: ``"changeme-1234-5678-90ab"``. Every entry is at least four specific
#: characters, so the chance of a random token containing one is negligible.
_PLACEHOLDER_SUBSTRINGS: Final[tuple[str, ...]] = (
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "change-me",
    "redacted",
    "notreal",
    "not_real",
    "replaceme",
    "replace_me",
    "yourkey",
    "your_key",
    "your-key",
    "yoursecret",
    "yourtoken",
    "dummytoken",
    "xxxx",
    "abcdef",
    "123456",
    "dummy",
    "sample",
    "fake",
    "mock",
    "insert",
    "todo",
    "fixme",
)

#: Placeholder words matched as whole words only, to keep the false-rejection
#: rate low for short markers that could occur by chance inside real material.
_PLACEHOLDER_WORDS: Final[frozenset[str]] = frozenset(
    {
        "your",
        "yours",
        "here",
        "none",
        "null",
        "nil",
        "undefined",
        "unset",
        "empty",
        "void",
        "test",
        "testing",
        "todo",
        "fixme",
        "invalid",
        "unsetvalue",
    }
)

#: A Python, JavaScript or configuration identifier: starts with a letter or
#: underscore, then letters, digits and underscores. Used to recognise code
#: rather than data.
_IDENTIFIER_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: A kebab-case name: hyphen-separated segments, each starting with a letter.
#:
#: The leading-letter requirement is load-bearing. A lowercase UUID is also a
#: sequence of hyphen-separated alphanumeric segments, and relaxing this to
#: ``[a-z0-9]`` would silently stop the scanner reporting UUIDs. See
#: :func:`_is_named_constant`.
_KEBAB_IDENTIFIER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z][A-Za-z0-9]*)+$"
)

#: A call shape: an opening parenthesis immediately followed by an identifier
#: character or by the closing parenthesis, as in ``render(error)`` or ``noop()``.
#:
#: Parenthesis syntax appears in every programming language and in none of the
#: credential alphabets -- base64, base64url, hex and base32 all exclude it.
_CALL_SHAPE_PATTERN: Final[re.Pattern[str]] = re.compile(r"\(\s*[A-Za-z_)]")

#: Sphinx and reStructuredText cross-reference roles, as they appear in
#: docstrings: ``:class:`~secret_shield.models.Finding```.
#:
#: Two shapes must be caught. The role marker itself, and the ``~`` that Sphinx
#: uses to ask for a shortened display name -- that tilde is what a tokenizer
#: extracting the backtick-quoted content actually sees.
_DOCUMENTATION_ROLE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^~?:[a-z]+:")
_SHORTHAND_MARKER: Final[str] = "~"

#: Constructs that appear in a regular expression and in nothing else. Base64,
#: base64url, hex and base32 alphabets contain none of them.
#:
#: These are deliberately the *unambiguous* ones. An earlier draft also rejected
#: a bare ``^`` or ``$``, which wrongly suppressed strong human-chosen passwords
#: such as ``Zt5#pQ2v!Lm8@Rx4$Kw9%Nb3^Hj7&Cd1*``. A lone caret or dollar sign
#: proves nothing; a non-capturing group or a backslash escape does.
_PATTERN_GROUP: Final[str] = "(?:"
_PATTERN_ESCAPE: Final[str] = "\\"

_WORD_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z0-9]+")

#: Longest token the tokenizer will produce from a single quoted literal. A
#: "quoted string" longer than this is prose, a data URI or an embedded asset,
#: not a credential. Base64 payloads up to this length stay eligible.
MAX_TOKEN_LENGTH: Final[int] = 4096

#: Origins, recorded so a finding can say where its candidate came from.
ORIGIN_QUOTED: Final[str] = "quoted"
ORIGIN_UNQUOTED: Final[str] = "unquoted-assignment"


@dataclass(frozen=True, slots=True)
class Token:
    """One plausible secret candidate found in a text file.

    The raw value is present here because entropy cannot be measured on a
    redacted string. It is deliberately confined to this object: a ``Token`` is
    created and discarded inside one call to :func:`candidates` and is never
    written to a report, a log, or a
    :class:`~secret_shield.models.Finding`.

    **``length`` is not the span.** :meth:`candidates` collapses escape
    sequences, so the characters a token carries can be fewer than the
    characters it covers: ``"a\\nb"`` yields the value ``anb`` and a
    :attr:`length` of three over a span of five. Overlap testing needs the span,
    because that is what a pattern rule's offsets are measured in, so both ends
    are recorded rather than derived.

    Attributes:
        value: The raw candidate text. Never persisted.
        line: 1-based line number.
        column: 1-based column of the first character of the value.
        offset: 0-based character offset of the value within the file text.
        end_offset: 0-based character offset just past the value's own text in
            the file, so the token covers ``[offset, end_offset)``.
        delimiter: The quote character used, or ``""`` for an unquoted value.
        origin: ``"quoted"`` or ``"unquoted-assignment"``.
    """

    value: str
    line: int
    column: int
    offset: int
    end_offset: int
    delimiter: str
    origin: str

    @property
    def length(self) -> int:
        """Length of the raw value in characters."""

        return len(self.value)

    @property
    def span(self) -> tuple[int, int]:
        """``(offset, end_offset)``, the exact source range this token covers.

        Measured in the coordinates a pattern rule reports in, which is what
        Stage 4's fusion layer compares. See the note on :attr:`length`.
        """

        return (self.offset, self.end_offset)

    def __repr__(self) -> str:
        # Never include the raw value, even when tracebacks or debuggers print
        # a token. Callers reach the value explicitly instead.
        return (
            f"Token(line={self.line}, column={self.column}, length={self.length}, "
            f"origin={self.origin!r})"
        )


def candidates(text: str) -> list[Token]:
    """Extract plausible secret candidates from ``text``.

    Two sources are recognised:

    1. **Quoted literals** -- the contents of ``"..."``, ``'...'`` and
       ``\\`...\\``` literals. This is the workhorse: it covers Python, JSON,
       YAML, TOML, JavaScript, shell and most configuration formats without
       needing to know which one it is looking at.
    2. **Assignment right-hand sides** -- an unquoted run of value characters
       following ``NAME=`` or ``NAME =``, which covers environment files and
       shell exports.

    Candidates that are obviously not secrets are discarded: template
    expressions, placeholders, values made of repeated or sequential
    characters, and literals so long that they must be prose or an embedded
    asset.

    Args:
        text: The full text of one file. Line endings are normalised first, so
            offsets are measured in ``\\n`` terms regardless of how the file was
            saved.

    Returns:
        Tokens in file order. Overlapping candidates are merged, so a value is
        never returned twice.

    Note:
        This function performs no entropy analysis and applies no length
        threshold. It answers "what text could plausibly be a credential?",
        not "is this text a credential?".
    """

    if not isinstance(text, str):
        raise TypeError(f"candidates() expects str, got {type(text).__name__}")

    normalized = _normalize_newlines(text)
    found: list[Token] = []
    length = len(normalized)
    index = 0
    line = 1
    column = 1

    while index < length:
        character = normalized[index]

        if character == "\n":
            index += 1
            line += 1
            column = 1
            continue

        if character == "#":
            index = _skip_to_newline(normalized, index)
            continue

        if character in _QUOTE_CHARACTERS:
            scanned = _scan_quoted(normalized, index, line, column)
            if scanned is None:
                # An unterminated quote: the rest of the line is not a value.
                index += 1
                continue
            value, next_index, end_line, end_column = scanned
            found.append(
                Token(
                    value=value,
                    line=line,
                    column=column + 1,
                    offset=index + 1,
                    # ``next_index`` is just past the closing quote, so the value's
                    # own text ends one character before it.
                    end_offset=next_index - 1,
                    delimiter=character,
                    origin=ORIGIN_QUOTED,
                )
            )
            index = next_index
            line, column = end_line, end_column
            continue

        if character in _IDENTIFIER_CHARACTERS:
            identifier_end = _scan_identifier(normalized, index)
            probe = identifier_end
            while probe < length and normalized[probe] in " \t":
                probe += 1
            is_assignment = (
                probe < length
                and normalized[probe] == "="
                and normalized[probe : probe + 2] != "=="
            )
            if is_assignment:
                value_start = probe + 1
                while value_start < length and normalized[value_start] in " \t":
                    value_start += 1
                if (
                    value_start < length
                    and normalized[value_start] not in _QUOTE_CHARACTERS
                ):
                    run_end = _scan_unquoted(normalized, value_start)
                    if run_end > value_start:
                        found.append(
                            Token(
                                value=normalized[value_start:run_end],
                                line=line,
                                column=column + (value_start - index),
                                offset=value_start,
                                end_offset=run_end,
                                delimiter="",
                                origin=ORIGIN_UNQUOTED,
                            )
                        )
                        column += run_end - index
                        index = run_end
                        continue
            column += identifier_end - index
            index = identifier_end
            continue

        index += 1
        column += 1

    return _keep_plausible(found)


def _keep_plausible(tokens: list[Token]) -> list[Token]:
    """Drop structurally implausible candidates and merge duplicates.

    Merging matters because an unquoted assignment inside a quoted line, or an
    overlapping construct, can otherwise produce the same text twice and lead
    to duplicate findings.
    """

    kept: list[Token] = []
    seen: set[tuple[int, int]] = set()
    for token in tokens:
        if not token.value or len(token.value) > MAX_TOKEN_LENGTH:
            continue
        if looks_like_placeholder_or_template(token.value):
            continue
        if has_repetitive_structure(token.value):
            continue
        if has_non_secret_structure(token.value):
            continue
        key = token.span
        if key in seen:
            continue
        seen.add(key)
        kept.append(token)
    return kept


def is_placeholder(value: str) -> bool:
    """Return ``True`` when the value is a documented placeholder.

    Covers the filler that appears in documentation and in templates:
    ``"EXAMPLE"``, ``"REDACTED"``, ``"CHANGE_ME"``, ``"YOUR_KEY_HERE"``,
    ``"xxxxxxxx"``, ``"abcdef123456"``.

    This is a hard filter. Dropping a genuine credential that happens to
    contain one of these markers costs a real detection, so the marker list is
    deliberately short and only contains strings long enough that random
    material cannot plausibly contain them.
    """

    if not isinstance(value, str):
        raise TypeError(f"is_placeholder() expects str, got {type(value).__name__}")

    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_SUBSTRINGS):
        return True
    words = set(_WORD_PATTERN.findall(lowered))
    return bool(words & _PLACEHOLDER_WORDS)


def is_template_expression(value: str) -> bool:
    """Return ``True`` when the value is purely a template placeholder.

    Only a value that is *entirely* an interpolation counts, such as
    ``"${TOKEN}"`` or ``"{{ secret }}"``. A value that embeds an interpolation
    among literal text is kept on purpose: the literal text is the part worth
    scanning.
    """

    if not isinstance(value, str):
        raise TypeError(
            f"is_template_expression() expects str, got {type(value).__name__}"
        )

    trimmed = value.strip()
    if trimmed in _EXACT_TEMPLATE_VALUES:
        return True
    return any(
        trimmed.startswith(opening) and trimmed.endswith(closing)
        for opening, closing in _TEMPLATE_PAIRS
    )


def looks_like_placeholder_or_template(value: str) -> bool:
    """Return ``True`` for anything the structural filters should discard."""

    return is_template_expression(value) or is_placeholder(value)


def has_non_secret_structure(value: str) -> bool:
    """Return ``True`` when a value is shaped like code rather than like data.

    Entropy cannot tell a Python constant from a credential: both are long
    strings of mixed characters, and both measure above every threshold. On this
    repository's own source, entropy alone reported 64 candidates, and every
    one of them was a name, a format string or a pattern. This function is the
    correction, and each check below states what it rejects and what it costs.

    The six syntax shapes come from measuring that 64-finding sample, plus one
    geometric rule that needs no sample at all: key material is single-line.
    A bare-URL rule was added later, when the Stage 2 catalog put a long
    endpoint in a remediation string and a webhook path in a regex literal: both
    were locators, and both were false positives.

    Note:
        Every check here can in principle suppress a real secret that happens to
        be written in an unusual way -- a password chosen by a human rather than
        generated by a machine. That is the correct direction to be wrong in: a
        false negative is a missed secret, a false positive is a review item.
        Where a rule's cost is now covered by an exact vendor match, that rule
        says so in its own docstring.

    Known gap: long CamelCase identifiers
    -------------------------------------

    A bare compound identifier -- ``FilesystemScanConfig``, twenty characters,
    mixed case, no separator -- is caught by none of the checks here.
    ``_is_named_constant`` needs an underscore to recognise a name, and
    ``_KEBAB_IDENTIFIER_PATTERN`` needs a hyphen, so such a value reaches the
    entropy rule and is reported whenever it is at least ``min_length`` long
    and measures at or above ``min_raw_entropy``.

    This is a real false-positive class, not a curiosity. Compound identifiers
    of that shape are ordinary in compiled languages and in generated code, and
    a scanner that reports them gets muted by its users within a week.

    It is deliberately **not** fixed here. The obvious filter -- "has an
    interior capital following a lowercase" -- also rejects generated bodies
    such as ``aB3dE5fG7hJ9kL``, which is exactly the shape a machine-made
    secret has. That fix would trade a false positive for a false negative, and
    choosing the trade properly needs the Stage 4 fusion rules in place, where
    an entropy candidate that a vendor rule already matched costs nothing to
    suppress.

    Found by the Stage 3 self-scan, which is what it is for. The offending
    identifier was renamed rather than the rule weakened; the class is now
    called :class:`~secret_shield.sources.PathScanConfig`.
    """

    return (
        _spans_lines(value)
        or _has_interpolation_syntax(value)
        or _is_qualified_code_reference(value)
        or _is_named_constant(value)
        or _is_documentation_role(value)
        or _has_pattern_punctuation(value)
        or _is_call_expression(value)
        or _is_bare_url(value)
    )


def _spans_lines(value: str) -> bool:
    """Return ``True`` for a value containing a line break.

    Key material is single-line by construction: no credential is issued with a
    newline in it. A value that spans lines is a block of prose, a docstring or
    a wrapped Markdown span, and all three are the kind of text that measures
    high purely because it uses lots of different letters.

    This is the only check here that is not about code syntax, and it is also
    the cheapest and the least arguable, which is why it is tested first.
    """

    return "\n" in value or "\r" in value


def _has_interpolation_syntax(value: str) -> bool:
    """Return ``True`` for a value containing braces.

    Braces mean an interpolation or a format template: an f-string, a
    ``str.format`` template, a shell brace expansion or a JSON object. This is
    the single largest source of noise in source code, because half of modern
    string literals are f-strings.

    No generated credential contains a brace, so this check costs nothing.
    """

    return "{" in value or "}" in value


def _is_qualified_code_reference(value: str) -> bool:
    """Return ``True`` for a dotted reference such as ``package.module.Name``.

    Every dot-separated segment must be a valid identifier. That requirement is
    what keeps real values intact: a database URL has dots, but its segments
    contain ``://``, ``@`` and ``/``, so it is not mistaken for a reference. A
    hostname like ``cache.internal.example`` *is* rejected, which is correct,
    since a hostname is not a credential.

    The cost is a JWT whose three segments happen to avoid ``-`` and ``_``. A
    JWT is an issued token rather than a credential, and one whose segments are
    plain alphanumeric is a legitimate thing to miss here.
    """

    if "." not in value:
        return False
    segments = value.split(".")
    return all(_IDENTIFIER_PATTERN.match(segment) for segment in segments)


def _is_named_constant(value: str) -> bool:
    """Return ``True`` for an identifier that is a *name*, not a value.

    Two naming conventions join words with punctuation, and both produce long
    mixed-character strings that measure high:

    * snake_case, where the joiner is ``_``: ``DEFAULT_MIN_RAW_ENTROPY``.
    * kebab-case, where the joiner is ``-``: ``github-pat-fine-grained``.

    Generated secrets use punctuation only as a vendor prefix, and only at the
    start: ``ghp_...`` is a GitHub token, ``AWS_SECRET_ACCESS_KEY`` is a name.

    **Why every kebab segment must begin with a letter.** Without that
    requirement a hyphen filter would swallow every UUID, because a lowercase
    UUID is exactly ``hex-hex-hex-hex-hex`` and each segment is ``[a-z0-9]+``.
    Names are built from words; identifiers-as-values are built from digits and
    the occasional letter. That one requirement is what keeps
    ``550e8400-e29b-41d4-a716-446655440000`` detectable while
    ``aws-secret-access-key`` is not.

    The cost of this check, in both arms, is a real secret that is written as
    separated lowercase words. That trade is now *paid* rather than *owed*:
    Stage 2 vendor rules match those prefixes exactly, and
    ``aws-secret-access-key`` is reported by a context-gated rule that requires
    a nearby identifier. Secrets generated as one unbroken string of letters
    and digits are unaffected.
    """

    if _IDENTIFIER_PATTERN.match(value) and "_" in value:
        return True
    return bool(_KEBAB_IDENTIFIER_PATTERN.match(value))


def _is_documentation_role(value: str) -> bool:
    """Return ``True`` for a Sphinx cross-reference.

    Documentation roles dominate the docstrings of any project that publishes
    API documentation, and ``~secret_shield.models.Finding`` measures 3.9 bits
    per character. Neither a role marker nor the ``~`` shorthand prefix is ever
    part of a credential: no generated secret contains a tilde, and the only
    everyday text that starts with one is a home-directory path, which is a
    path rather than a secret.
    """

    if value.startswith(_SHORTHAND_MARKER):
        return True
    return bool(_DOCUMENTATION_ROLE_PATTERN.match(value))


def _has_pattern_punctuation(value: str) -> bool:
    """Return ``True`` when a value carries regular-expression syntax.

    Only constructs that cannot occur in a credential are treated as proof: a
    non-capturing group, a backslash escape, or a value anchored at both ends.
    A single ``^`` or ``$`` is not proof of anything -- strong human-chosen
    passwords contain them -- so they only count when paired as a full-match
    pattern, which is what ``^...$`` means.
    """

    if _PATTERN_GROUP in value or _PATTERN_ESCAPE in value:
        return True
    return value.startswith("^") and value.endswith("$")


def _is_bare_url(value: str) -> bool:
    """Return ``True`` for a URL that identifies a location and nothing else.

    A URL is a locator. On its own it is not a credential, and a long one --
    an IAM console path, a webhook endpoint written into a regex literal --
    measures high purely because it uses many different characters.

    **Two exclusions keep this from eating real credentials**, and both matter
    more than the rule itself:

    * **A URL with userinfo is not suppressed.** ``@`` means
      ``scheme://user:password@host``, and that password is a secret. The
      entropy rule must keep reporting connection strings, which are its most
      valuable finds.
    * **A URL with a query string is not suppressed.** A pre-signed S3 or
      CloudFront URL carries its authentication in ``?X-Amz-Signature=...``,
      which is a credential in the path-plus-query of the URL. Suppressing
      query-bearing URLs would hide every one of them.

    What remains -- ``scheme://host/path`` with neither ``@`` nor ``?`` -- is a
    bare locator.

    The cost: a URL that keeps its secret in the path, such as a Slack incoming
    webhook, is suppressed here. That cost is paid rather than owed, because
    ``slack-incoming-webhook`` in the Stage 2 catalog matches that exact shape
    with far stronger evidence than entropy provides.
    """

    if "://" not in value:
        return False
    return "@" not in value and "?" not in value


def _is_call_expression(value: str) -> bool:
    """Return ``True`` for a value carrying function-call syntax.

    ``render_text(result)`` and ``Finding.from_match()`` both measure high
    enough to be reported, and both are code. Parentheses are universal in
    programming languages and absent from every credential alphabet, so the
    shape is proof of one and only one thing.

    The cost is a human-chosen password containing a bracket, such as
    ``Pass(word)123``, which this suppresses. That is a narrower loss than it
    looks: machine-generated keys never contain one, and a password strong
    enough to be worth scanning is usually punctuation-heavy without
    juxtaposition of a letter and a bracket.
    """

    return bool(_CALL_SHAPE_PATTERN.search(value))


def has_repetitive_structure(value: str) -> bool:
    """Return ``True`` when the value has no real information content.

    Detects a single character repeated (``"aaaaaaaa..."``), a value that is
    two copies of the same block (``"abcdabcdabcd..."``), and strictly
    ascending or descending runs (``"abcdef..."``, ``"987654..."``).

    These all score near-zero entropy anyway, so this is a cheap pre-filter
    that keeps obviously synthetic material out of the pipeline entirely.
    """

    if not isinstance(value, str):
        raise TypeError(
            f"has_repetitive_structure() expects str, got {type(value).__name__}"
        )

    length = len(value)
    if length < 4:
        return False
    if len(set(value)) == 1:
        return True
    if length % 2 == 0 and value[: length // 2] * 2 == value:
        return True
    deltas = {ord(second) - ord(first) for first, second in zip(value, value[1:])}
    return deltas in ({1}, {-1})


def _normalize_newlines(text: str) -> str:
    """Normalise line endings so offsets and line numbers agree everywhere."""

    if "\r" not in text:
        return text
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _skip_to_newline(text: str, index: int) -> int:
    """Return the index of the next newline at or after ``index``."""

    newline = text.find("\n", index)
    return len(text) if newline == -1 else newline


def _scan_identifier(text: str, index: int) -> int:
    """Return the index just past an identifier starting at ``index``."""

    end = index
    while end < len(text) and text[end] in _IDENTIFIER_CHARACTERS:
        end += 1
    return end


def _scan_unquoted(text: str, index: int) -> int:
    """Return the index just past an unquoted value run starting at ``index``."""

    end = index
    while end < len(text) and text[end] in _UNQUOTED_CHARACTERS:
        end += 1
    return end


def _scan_quoted(
    text: str, index: int, line: int, column: int
) -> tuple[str, int, int, int] | None:
    """Scan a quoted literal starting at ``index``.

    Returns ``(value, next_index, end_line, end_column)``, or ``None`` when the
    literal is unterminated. Escape sequences are collapsed so that
    ``"a\\"b"`` is one value rather than two.

    Single and double quotes must close on the same line: in the languages that
    use them, a newline before the closing quote means the quote is not actually
    a string, and treating the rest of the file as a token is the fastest way to
    flood the scanner with nonsense. Backticks may span lines, because
    multi-line template literals are common and their contents are still worth
    examining.
    """

    quote = text[index]
    end = index + 1
    characters: list[str] = []
    end_line = line
    end_column = column + 1
    length = len(text)

    while end < length:
        character = text[end]
        if character == _ESCAPE_CHARACTER and end + 1 < length:
            following = text[end + 1]
            if following == "\n":
                end_line += 1
                end_column = 1
            else:
                characters.append(following)
                end_column += 1
            end += 2
            continue
        if character == quote:
            return "".join(characters), end + 1, end_line, end_column + 1
        if character == "\n":
            if quote != "`":
                return None
            end_line += 1
            end_column = 1
            characters.append(character)
            end += 1
            continue
        characters.append(character)
        end_column += 1
        end += 1

    return None
