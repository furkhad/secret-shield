"""The Stage 1 detector: high-entropy string screening.

This rule is deliberately blunt, and it is the only one that does not need to
know what a value belongs to.

What it claims: *this text has enough character variety to be worth a human
look.* What it does not claim: *this text is a credential.* A hex API key, a
SHA-1 commit hash, a UUID, a base64-encoded image, a git blob ID and a leaked
credential are indistinguishable to an entropy measurement, and no threshold
change will separate them. The vendor rules do that job, and
:mod:`secret_shield.pipeline` decides what to do when both kinds of evidence
land on the same bytes.

Three entry points, one decision
--------------------------------

:func:`evaluate` is the decision: given a value and the thresholds, return the
entropy that qualified it or ``None``. :func:`entropy_candidates` applies that
decision to a stream of tokens and returns the qualifying ones **with their
source spans**, as :class:`EntropyCandidate` objects. :func:`detect` is
:func:`entropy_candidates` followed by redaction.

The split exists because the decision and the conversion are now used by two
different callers. ``detect`` wants findings; fusion wants to compare spans
against another detector's, which a redacted finding can no longer supply.
Deciding once and converting once means the thresholds are applied in exactly
one place and cannot drift between the two callers.

Three consequences are baked into the code rather than left to the reporter:

* **Severity is capped at MEDIUM.** Entropy carries no information about impact.
  Impact is a property of what the value unlocks, and only a rule that knows
  the vendor can assess that.
* **Confidence is PROBABLE, never higher.** The evidence is a statistic over
  characters. Even an unusually high score is an invitation to review.
* **There is an upper bound on usefulness.** :data:`MAX_ENTROPY` acts as a
  ceiling too: a string with more than 8 bits per character needs over 256
  distinct characters, which is natural language, not key material.

Two gates must both be passed to produce a finding: a raw entropy floor that
rules out low-variety text, and an evenness ratio that is alphabet-independent.
See :data:`DEFAULT_MIN_RAW_ENTROPY` for why the raw floor is 3.5 rather than
the intuitive 4.0.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from ..entropy import MAX_ENTROPY, normalized_entropy, shannon_entropy
from ..masking import FULLY_REDACTED
from ..models import (
    Confidence,
    DetectorKind,
    Finding,
    Location,
    SecretCategory,
    Severity,
    SourceKind,
)
from ..tokenizer import Token

__all__ = [
    "RULE_ID",
    "RULE_NAME",
    "REMEDIATION",
    "FALSE_POSITIVE_NOTES",
    "DEFAULT_MIN_LENGTH",
    "DEFAULT_MIN_RAW_ENTROPY",
    "DEFAULT_MIN_NORMALIZED_ENTROPY",
    "EntropyCandidate",
    "EntropyRuleConfig",
    "default_entropy_config",
    "detect",
    "entropy_candidates",
    "evaluate",
]

RULE_ID: Final[str] = "high-entropy-string"
RULE_NAME: Final[str] = "High-entropy string"

REMEDIATION: Final[str] = (
    "Entropy alone does not identify a credential. Confirm whether this value "
    "is live before acting on it. If it is a secret, rotate it at the issuing "
    "service and move it out of source control into a secret manager or "
    "environment variable, then remove it from the history of this repository."
)

FALSE_POSITIVE_NOTES: Final[str] = (
    "Expect hits on Git commit and blob hashes, UUIDs and other identifiers, "
    "checksums, minified and bundled assets, embedded images encoded as data "
    "URIs, compiled binary blobs, and hex-encoded API keys that belong to a "
    "vendor rule which did not match. Any value that is random-looking has the "
    "same shape as a credential, and entropy alone cannot tell them apart: a "
    "SHA-1 hash and a leaked token score identically. Suppress these by "
    "disabling this rule for a path in configuration, or by lowering "
    "entropy.min_length or entropy.min_normalized_entropy, rather than by "
    "trusting a single hit."
)

DEFAULT_MIN_LENGTH: Final[int] = 20
"""Shortest candidate considered. Below this, entropy is dominated by noise."""

DEFAULT_MIN_RAW_ENTROPY: Final[float] = 3.5
"""Minimum entropy in bits per character: a floor, not the real test.

The obvious threshold to reach for is 4.0 bits per character, and it is wrong.
A 16-symbol alphabet -- hex -- has a *mathematical ceiling* of exactly
``log2(16) = 4.0``, so a gate at 4.0 is only ever satisfied by a perfect
uniform distribution that does not occur. Real hex tokens measure 3.93 to 3.98
and would be silently discarded. The floor therefore sits at 3.5, which admits
hex, and :data:`DEFAULT_MIN_NORMALIZED_ENTROPY` does the discriminating.
"""

DEFAULT_MIN_NORMALIZED_ENTROPY: Final[float] = 0.8
"""Minimum distribution-evenness ratio, on a 0..1 scale.

This is the primary gate, and it is alphabet-independent: it asks how evenly
the characters are spread over the alphabet the value actually uses. Uniform
random material scores above 0.98 whether it is hex, base32 or base64, while
text, paths and identifiers sit around 0.91 to 0.96.

Evenness alone cannot separate two random hex strings, and it is not meant to.
A SHA-1 commit hash, a UUID and a hex API key have the same shape and the same
score. Distinguishing them needs the vendor rules and allowlists of a later
stage; here they are reported at MEDIUM severity for a human to dismiss.
"""

#: A value with at least this many space-separated words is prose, not a
#: credential.
#:
#: This is the *only* defense against text, and it has to carry that weight on
#: its own. Entropy cannot make the distinction: an English sentence measures
#: 4.39 bits per character and an evenness of 0.92, which clears both gates.
#: What it cannot do is survive a word count -- real key material contains no
#: spaces at all. Counting words removes a whole class of false positives for
#: the cost of two lines of code.
#:
#: The threshold of 2 means "two words are tolerated". ``"Bearer <token>"`` is
#: worth scanning; a sentence is not.
MAX_PROSE_WORDS: Final[int] = 2


@dataclass(frozen=True, slots=True)
class EntropyRuleConfig:
    """Tunable thresholds for the entropy screen.

    Attributes:
        min_length: Shortest candidate considered, in characters.
        min_raw_entropy: Minimum Shannon entropy in bits per character.
        min_normalized_entropy: Minimum evenness ratio in ``[0.0, 1.0]``.
        max_raw_entropy: Candidates above this are ignored as non-credential
            text. Keeps natural language out, and keeps the reported entropy
            inside the range :class:`~secret_shield.models.Finding` accepts.
        max_prose_words: Ignore candidates with at least this many
            space-separated words of two or more characters.
        max_severity: Ceiling for this rule's findings. May only reduce
            severity below MEDIUM, never raise it: entropy cannot rank impact.
    """

    min_length: int = DEFAULT_MIN_LENGTH
    min_raw_entropy: float = DEFAULT_MIN_RAW_ENTROPY
    min_normalized_entropy: float = DEFAULT_MIN_NORMALIZED_ENTROPY
    max_raw_entropy: float = MAX_ENTROPY
    max_prose_words: int = MAX_PROSE_WORDS
    max_severity: Severity = Severity.MEDIUM

    def __post_init__(self) -> None:
        if self.min_length < 1:
            raise ValueError("min_length must be at least 1")
        if self.min_raw_entropy < 0.0:
            raise ValueError("min_raw_entropy must not be negative")
        if not 0.0 <= self.min_normalized_entropy <= 1.0:
            raise ValueError("min_normalized_entropy must be between 0.0 and 1.0")
        if self.max_raw_entropy < self.min_raw_entropy:
            raise ValueError("max_raw_entropy must be at least min_raw_entropy")
        if self.max_prose_words < 0:
            raise ValueError("max_prose_words must not be negative")
        if not isinstance(self.max_severity, Severity):
            raise TypeError("max_severity must be a Severity")
        if self.max_severity > Severity.MEDIUM:
            raise ValueError(
                "entropy-only findings cannot exceed MEDIUM severity; "
                "entropy carries no information about impact"
            )

    @property
    def severity_ceiling(self) -> Severity:
        """The severity this rule may use, never above MEDIUM."""

        return min(self.max_severity, Severity.MEDIUM)


DEFAULT_ENTROPY_CONFIG: Final[EntropyRuleConfig] = EntropyRuleConfig()
"""The shipped defaults: length 20, entropy 4.0 bits per character, ratio 0.8."""


def default_entropy_config() -> EntropyRuleConfig:
    """Return a fresh copy of the default entropy configuration."""

    return EntropyRuleConfig()


@dataclass(frozen=True, slots=True)
class EntropyCandidate:
    """One candidate that passed every entropy gate, with the span it covers.

    **This object holds the credential in the clear**, and it observes the same
    discipline as :class:`~secret_shield.detectors.base.RawMatch`: it exists
    only between the tokenizer and the fusion layer, its ``repr`` is redacted,
    and it is never stored in a
    :class:`~secret_shield.models.Finding`.

    It exists because :func:`detect` is not the only consumer of this rule any
    more. Stage 4 has to compare an entropy hit against a pattern hit to decide
    whether they describe one secret or two, and that comparison needs a source
    range -- not just a redacted finding, whose offsets are gone by the time it
    is built. Producing the evidence first and the finding second keeps the
    redaction boundary exactly where it was.

    Attributes:
        value: The candidate text. Never persisted.
        start_offset: 0-based offset of the value within the file text.
        end_offset: 0-based offset just past the value in the file text.
        line: 1-based line of the first character.
        column: 1-based column of the first character.
        entropy: Shannon entropy in bits per character, the value that passed.
    """

    value: str
    start_offset: int
    end_offset: int
    line: int
    column: int
    entropy: float

    @property
    def span(self) -> tuple[int, int]:
        """``(start_offset, end_offset)``, in pattern-rule coordinates.

        Taken from the tokenizer's own record of the source text rather than
        from ``offset + len(value)``, so it stays correct for a literal
        containing escape sequences.
        """

        return (self.start_offset, self.end_offset)

    @property
    def length(self) -> int:
        """Length of the candidate in characters."""

        return len(self.value)

    def __repr__(self) -> str:
        return (
            f"EntropyCandidate(line={self.line}, column={self.column}, "
            f"length={self.length}, entropy={self.entropy:.2f})"
        )

    def to_finding(
        self,
        path: str,
        *,
        severity: Severity = Severity.MEDIUM,
        source_kind: SourceKind = SourceKind.FILE,
        commit: str | None = None,
        commit_time: int | None = None,
        fingerprint_key: bytes | None = None,
    ) -> Finding:
        """Convert to a redacted :class:`~secret_shield.models.Finding`.

        The one place an entropy candidate becomes a finding on its own. The
        fusion layer builds composites through a
        :class:`~secret_shield.detectors.base.RawMatch` instead, because only a
        pattern match knows the rule, the category and the remediation.

        Args:
            path: File path recorded on the finding.
            severity: Severity to use. Callers pass
                :attr:`EntropyRuleConfig.severity_ceiling`, which is never above
                MEDIUM.
            source_kind: Whether the text came from a file or from Git history.
            commit: Commit hash, when scanning history.
            commit_time: Commit timestamp, when scanning history.
            fingerprint_key: Optional HMAC key for the correlation digest. See
                :func:`~secret_shield.masking.fingerprint`. ``None`` keeps the
                unkeyed SHA-256 default.

        Note:
            The value is masked and fingerprinted inside ``from_match`` and then
            dropped. Nothing about it outlives the call.
        """

        return Finding.from_match(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            category=SecretCategory.UNKNOWN,
            severity=severity,
            confidence=Confidence.PROBABLE,
            detector=DetectorKind.ENTROPY,
            location=Location(
                source_kind=source_kind,
                path=path,
                line=self.line,
                column=self.column,
                commit=commit,
                commit_time=commit_time,
            ),
            raw_value=self.value,
            policy=FULLY_REDACTED,
            fingerprint_key=fingerprint_key,
            entropy=self.entropy,
            matched_keywords=(),
            remediation=REMEDIATION,
        )

    def __str__(self) -> str:
        return self.__repr__()


def entropy_candidates(
    tokens: Iterable[Token],
    config: EntropyRuleConfig | None = None,
) -> tuple[EntropyCandidate, ...]:
    """Return the tokens that pass every entropy gate, with their spans.

    This is the rule's decision, separated from :func:`detect` so that the
    decision can be taken on its own and compared against other detectors. The
    gates are exactly :func:`evaluate`'s; nothing is added or relaxed here.

    Args:
        tokens: Candidates from :func:`secret_shield.tokenizer.candidates`.
        config: Thresholds to apply. Defaults to
            :data:`DEFAULT_ENTROPY_CONFIG`.

    Returns:
        Candidates in token order. The returned objects hold raw values; see
        the class docstring.
    """

    settings = config if config is not None else DEFAULT_ENTROPY_CONFIG
    found: list[EntropyCandidate] = []

    for token in tokens:
        entropy = evaluate(token.value, settings)
        if entropy is None:
            continue
        found.append(
            EntropyCandidate(
                value=token.value,
                start_offset=token.offset,
                end_offset=token.end_offset,
                line=token.line,
                column=token.column,
                entropy=entropy,
            )
        )

    return tuple(found)


def evaluate(value: str, config: EntropyRuleConfig | None = None) -> float | None:
    """Return the entropy of ``value`` if it qualifies as a candidate.

    This is the whole rule, exposed separately from :func:`detect` so that the
    decision can be tested and reasoned about on its own.

    Args:
        value: The raw candidate text.
        config: Thresholds to apply. Defaults to
            :data:`DEFAULT_ENTROPY_CONFIG`.

    Returns:
        The value's entropy in bits per character when it passes every gate, or
        ``None`` when it does not.

    Note:
        A returned number means "worth reviewing", never "is a secret".
    """

    settings = config if config is not None else DEFAULT_ENTROPY_CONFIG

    if len(value) < settings.min_length:
        return None
    if _looks_like_prose(value, settings):
        return None

    raw = shannon_entropy(value)
    if raw < settings.min_raw_entropy:
        return None
    if raw > settings.max_raw_entropy:
        return None
    if normalized_entropy(value) < settings.min_normalized_entropy:
        return None
    return raw


def detect(
    tokens: Iterable[Token],
    path: str,
    config: EntropyRuleConfig | None = None,
    *,
    source_kind: SourceKind = SourceKind.FILE,
    commit: str | None = None,
    commit_time: int | None = None,
    fingerprint_key: bytes | None = None,
) -> tuple[Finding, ...]:
    """Turn qualifying candidates into findings.

    This is :func:`entropy_candidates` followed by redaction: the entropy rule's
    decision happens in one place, and this function only converts the result.
    It reports every qualifying candidate separately, which is the right answer
    when the entropy rule is running on its own. When a pattern rule also
    matched the same bytes, :func:`secret_shield.pipeline.fuse` decides the two
    are one secret before anything is built here.

    The raw value is passed to :meth:`~secret_shield.models.Finding.from_match`
    and never stored: it is masked and fingerprinted there, then dropped. No
    other attribute of a finding carries any part of it.

    Args:
        tokens: Candidates from :func:`secret_shield.tokenizer.candidates`.
        path: File path recorded on every finding.
        config: Thresholds to apply.
        source_kind: Whether the text came from a file or from Git history.
        commit: Commit hash, when scanning history.
        commit_time: Commit timestamp, when scanning history.
        fingerprint_key: Optional HMAC key for the correlation digest. ``None``
            keeps the unkeyed SHA-256 default.

    Returns:
        Findings in candidate order. Each one is at most MEDIUM severity and
        PROBABLE confidence, and its category is UNKNOWN because entropy gives
        no hint about what kind of credential it might be.
    """

    settings = config if config is not None else DEFAULT_ENTROPY_CONFIG

    return tuple(
        candidate.to_finding(
            path,
            severity=settings.severity_ceiling,
            source_kind=source_kind,
            commit=commit,
            commit_time=commit_time,
            fingerprint_key=fingerprint_key,
        )
        for candidate in entropy_candidates(tokens, settings)
    )


def _looks_like_prose(value: str, settings: EntropyRuleConfig) -> bool:
    """Return ``True`` when the value is separated into too many words.

    Requires each word to be at least two characters so that ``"a b c"`` is not
    mistaken for prose while ``"key ab cd"`` still is.
    """

    words = [word for word in value.split() if len(word) >= 2]
    return len(words) > settings.max_prose_words
