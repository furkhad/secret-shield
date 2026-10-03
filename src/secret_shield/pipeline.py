"""Stage 4: two detectors, one honest answer.

Stage 1 asked whether a value *looks* random. Stage 2 asked *which vendor
issued it*. Both are right, and running both over the same file means a single
real secret is reported twice: an ``aws_secret_access_key`` line produces an
``aws-secret-access-key`` finding from the vendor rule and a
``high-entropy-string`` finding from the entropy rule, because from the
entropy rule's point of view that line is simply some random material.

Two findings for one secret is not a cosmetic problem. It doubles the finding
count, it puts a CRITICAL vendor finding next to a MEDIUM anonymous one that a
reviewer has to triage separately, and it teaches users that SecretShield's
output is padded -- which is the fastest way to get a security tool muted.

This module is the layer that makes the two answers one.

The order of operations
-----------------------

::

    source            sources/filesystem.py  -- which bytes to look at
    filtering         filters/              -- whether to look at them at all
    pattern detection detectors/base.py     -- RawMatch
    entropy detection entropy_rule.py       -- EntropyCandidate
    overlap fusion    this module           -- MergedMatch
    deduplication     this module           -- Finding
    materialization   this module           -- redacted, safe to keep
    ordering          this module           -- canonical, stable
    aggregation       sources/filesystem.py -- one ScanResult

Context adjustment and placeholder suppression are *inside* the two detectors
rather than separate passes over their output. That is deliberate: both already
apply :func:`~secret_shield.detectors.context.is_placeholder`,
:func:`~secret_shield.detectors.context.is_template_expression` and their own
entropy and context gates at the moment they produce evidence, and re-running
those decisions on a fused span could only reach a different answer on some
inputs and an arbitrary one on others. Fusion therefore cannot resurrect a
match a detector suppressed, and cannot undo a confidence promotion one of them
granted.

Why the vendor rule wins identity
---------------------------------

When two detectors describe the same bytes, one of them knows what the value
*is*. ``aws-secret-access-key`` carries a category, a severity, a remediation
string and a documented length; ``high-entropy-string`` carries none of those
and says, honestly, only that the characters are varied. Reporting the entropy
finding as its own result would tell a reviewer to go and look at a 40-character
base64 string without telling them it is an AWS credential, and would file a
CRITICAL finding as MEDIUM.

So the vendor rule supplies the identity, the entropy hit is demoted to
supporting evidence, and the result is a single
:class:`~secret_shield.models.DetectorKind.COMPOSITE` finding. The entropy
candidate's own text is then discarded rather than masked: there is no need to
reveal a second, wider version of the same secret, and the narrower one is the
one the rule's remediation text is about.

Why entropy cannot produce a verified finding
---------------------------------------------

:attr:`~secret_shield.models.Confidence.VERIFIED` means "confirmed against the
issuing service, out of band". Entropy is a statistic over the characters of a
value, and so is the pattern that matched it -- two statistics computed on the
same bytes, not two independent observations of the world. Agreement between
them raises confidence by exactly one step and stops at
:attr:`~secret_shield.models.Confidence.HIGH_CONFIDENCE`, because
``HIGH_CONFIDENCE`` is already the vocabulary's word for "this is as sure as a
scanner that never touches the network can be". Nothing in SecretShield
contacts an issuing service, and a rule may not even declare ``VERIFIED`` as
its base confidence, so no arithmetic here can reach it.

Severity is a separate question and entropy has no part in it
--------------------------------------------------------------

Severity answers "if this is real, how bad is it", which is a property of the
credential rather than of the evidence. A composite finding reports its vendor
rule's severity verbatim; an entropy-only finding reports the entropy
configuration's ceiling, which
:class:`~secret_shield.detectors.entropy_rule.EntropyRuleConfig` already
refuses to let rise above MEDIUM. Entropy never lowers a vendor severity either:
a HEURISTIC rule that matched a 40-character base64 string next to a line
reading ``aws_secret_access_key`` is genuinely CRITICAL, and an anonymous
opinion about character variety is not entitled to argue otherwise.

Why deduplication does not use the masked value
-----------------------------------------------

Two different credentials can produce the same mask. With the default
fully-redacted policy every value of every length becomes the same twelve
asterisks, so keying on ``masked_value`` would silently delete real findings --
and it would delete them precisely in the report that matters most, the one full
of secrets. Correlation therefore uses the value's *fingerprint*, a truncated
digest that distinguishes values without revealing them, and always combines it
with the rule and the location so that two occurrences of one secret in two
files stay two findings.

The same fingerprint, keyed without the location, is what
:meth:`~secret_shield.models.Finding.secret_key` already provides for reporting
"this one key appears in twelve commits". That is a *correlation* key and is
deliberately not used for deduplication; the two must not be confused.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from .detectors.base import (
    DetectorRegistry,
    RawMatch,
    Specificity,
    find_matches,
)
from .detectors.entropy_rule import (
    RULE_ID as ENTROPY_RULE_ID,
)
from .detectors.entropy_rule import (
    EntropyCandidate,
    EntropyRuleConfig,
    default_entropy_config,
    entropy_candidates,
)
from .models import (
    Confidence,
    DetectorKind,
    Finding,
    Location,
    Severity,
    SourceKind,
)
from .tokenizer import candidates

__all__ = [
    "ENTROPY_CONFIDENCE",
    "MAX_CONFIDENCE",
    "MergedMatch",
    "analyze_text",
    "dedupe",
    "describes_same_value",
    "fuse",
    "pattern_order",
]


MAX_CONFIDENCE: Final[Confidence] = Confidence.HIGH_CONFIDENCE
"""The highest confidence SecretShield will ever assign.

Named here because the fusion arithmetic has to clamp against it, and a clamp
whose bound is written as a bare literal is a clamp that will be forgotten when
the next stage adds a level.
"""

ENTROPY_CONFIDENCE: Final[Confidence] = Confidence.PROBABLE
"""Confidence of an entropy-only finding: evidence, and only evidence.

A statistic over characters is a good reason to look at something. It is never
a reason to say it is a credential.
"""

#: Tie-break order for "which pattern rule gets to name this finding".
#:
#: Specificity first, because it measures how much identity the rule brings:
#: an EXACT rule pinned a documented prefix to a documented length, a HEURISTIC
#: rule matched a shape that several vendors could have issued. Only when two
#: rules are equally specific does ``priority`` decide, and ``id`` breaks the
#: remaining tie so the order is total and never depends on registration order.
_SPECIFICITY_RANK: Final[dict[Specificity, int]] = {
    Specificity.EXACT: 0,
    Specificity.HEURISTIC: 1,
}


@dataclass(frozen=True, slots=True)
class MergedMatch:
    """One finding's worth of evidence, before anything is redacted.

    The output of :func:`fuse` and the input to redaction. It holds raw values
    for exactly as long as :class:`~secret_shield.detectors.base.RawMatch` and
    :class:`~secret_shield.detectors.entropy_rule.EntropyCandidate` do, and its
    ``repr`` is redacted to match.

    Attributes:
        pattern: The rule match that names this finding, or ``None`` when no
            pattern rule matched and the finding is entropy-only.
        entropy: Entropy candidates that corroborate this finding. Empty for a
            PATTERN finding with no corroboration; one or more for a COMPOSITE
            one.
        detector: Which kind of finding this is.
        confidence: Final confidence, after corroboration.
        severity: Final severity, taken from :attr:`pattern` when there is one.
        span: The source range the finding covers.
    """

    pattern: RawMatch | None
    entropy: tuple[EntropyCandidate, ...]
    detector: DetectorKind
    confidence: Confidence
    severity: Severity
    span: tuple[int, int]

    @property
    def id(self) -> str:
        """The rule id this finding will carry."""

        if self.pattern is not None:
            return self.pattern.rule.id
        return ENTROPY_RULE_ID

    @property
    def raw_value(self) -> str:
        """The single value this finding is about.

        **A pattern match owns the value whenever there is one.** The entropy
        candidate that corroborates it usually covers a wider range -- the whole
        quoted literal, the whole connection string -- and reporting that wider
        range would report a host name, a database name or a query string as
        though each were part of the secret. The vendor rule already decided
        which characters are the credential, and that decision is not revisited
        here.

        The wider text is not masked, fingerprinted or stored anywhere. It is
        simply not used.
        """

        if self.pattern is not None:
            return self.pattern.value
        if not self.entropy:
            raise ValueError("a MergedMatch must carry a pattern match or entropy evidence")
        return self.entropy[0].value

    @property
    def location(self) -> tuple[int, int]:
        """1-based ``(line, column)`` the finding points at."""

        if self.pattern is not None:
            return (self.pattern.line, self.pattern.column)
        first = self.entropy[0]
        return (first.line, first.column)

    def to_finding(
        self,
        path: str,
        *,
        source_kind: SourceKind = SourceKind.FILE,
        commit: str | None = None,
        commit_time: int | None = None,
    ) -> Finding:
        """Materialise the redacted :class:`~secret_shield.models.Finding`.

        The raw value is a local: :meth:`Finding.from_match` masks and
        fingerprints it and drops it, and no attribute of the result can hold
        it. Nothing is logged on the way, and no exception anywhere in this call
        interpolates a value.
        """

        line, column = self.location

        if self.pattern is None:
            return self.entropy[0].to_finding(
                path,
                severity=self.severity,
                source_kind=source_kind,
                commit=commit,
                commit_time=commit_time,
            )

        rule = self.pattern.rule
        return Finding.from_match(
            rule_id=rule.id,
            rule_name=rule.name,
            category=rule.category,
            severity=self.severity,
            confidence=self.confidence,
            detector=self.detector,
            location=Location(
                source_kind=source_kind,
                path=path,
                line=line,
                column=column,
                commit=commit,
                commit_time=commit_time,
            ),
            raw_value=self.raw_value,
            policy=rule.mask_policy,
            entropy=self.pattern.entropy,
            matched_keywords=self.pattern.matched_keywords,
            remediation=rule.remediation,
        )

    def __repr__(self) -> str:
        return (
            f"MergedMatch(rule_id={self.id!r}, detector={self.detector.value}, "
            f"severity={self.severity.label}, confidence={self.confidence.label}, "
            f"span={self.span}, entropy_evidence={len(self.entropy)})"
        )


def pattern_order(match: RawMatch) -> tuple[int, int, int, int]:
    """Return the deterministic identity ordering key for a pattern match.

    Specificity, then priority, then id, then position. Every component is a
    property of the rule or of the text, never of the order rules were
    registered in, so two registries built from differently ordered inputs fuse
    identically. The offset comes last so that the ordering is stable for the
    common case of one rule matching several places in a file.
    """

    rule = match.rule
    return (
        _SPECIFICITY_RANK[rule.specificity],
        rule.priority,
        rule.id,
        match.start_offset,
    )


def fuse(
    patterns: Sequence[RawMatch],
    entropy: Sequence[EntropyCandidate],
    *,
    entropy_severity: Severity = Severity.MEDIUM,
) -> tuple[MergedMatch, ...]:
    """Collapse two detectors' overlapping evidence into one match each.

    The algorithm, in full:

    1. **Drop duplicate pattern matches.** Two matches with the same span *and*
       the same value are the same bytes seen twice and become one. Two matches
       with the same span but different values are reporting different groups
       out of one regex match and both survive.
    2. **Attach corroboration.** Every entropy candidate is tested against every
       surviving pattern match (:func:`describes_same_value`).
    3. **One entropy candidate corroborates at most one pattern.** It is
       attached to the single best pattern it describes. When it describes two
       or more -- a quoted literal holding two vendor keys, say -- it is
       discarded: it is evidence about a *region*, not about either secret, and
       crediting it to one of them would be a coin toss dressed up as analysis.
       Both patterns keep their own findings, which is the answer a reviewer
       wants.
    4. **Emit.** One :class:`MergedMatch` per surviving pattern match, plus one
       per entropy candidate that matched nothing.

    Results are ordered by :meth:`MergedMatch.span`, then by the pattern identity
    key, so the output does not depend on how either detector happened to
    iterate.

    Args:
        patterns: Every surviving :class:`~secret_shield.detectors.base.RawMatch`
            for one content unit.
        entropy: Every surviving
            :class:`~secret_shield.detectors.entropy_rule.EntropyCandidate` for
            the same unit, measured in the same text.
        entropy_severity: Severity for an entropy-only finding. Callers pass
            :attr:`~secret_shield.detectors.entropy_rule.EntropyRuleConfig.severity_ceiling`.

    Returns:
        Merged matches, each of which will become exactly one finding.
    """

    survivors = _drop_duplicate_patterns(patterns)
    corroboration, consumed = _corroborating_entropy(survivors, entropy)

    merged: list[MergedMatch] = []

    for index, match in enumerate(survivors):
        # Sorted by span, not by arrival: the corroborating evidence is part of
        # the result, so leaving it in whatever order the detector produced would
        # make two callers with the same evidence disagree.
        support = tuple(
            sorted((entropy[position] for position in corroboration.get(index, ())), key=lambda c: c.span)
        )
        composite = bool(support)
        merged.append(
            MergedMatch(
                pattern=match,
                entropy=support,
                detector=DetectorKind.COMPOSITE if composite else DetectorKind.PATTERN,
                confidence=_combined_confidence(match.confidence(), composite),
                severity=match.rule.severity,
                span=match.span,
            )
        )

    for index, candidate in enumerate(entropy):
        # ``consumed`` covers a candidate that described several patterns as well
        # as one that described exactly one. A candidate that overlapped *any*
        # vendor match has been spoken for; only a candidate that overlapped
        # none is left to report on its own.
        if index in consumed:
            continue
        merged.append(
            MergedMatch(
                pattern=None,
                entropy=(candidate,),
                detector=DetectorKind.ENTROPY,
                confidence=ENTROPY_CONFIDENCE,
                severity=min(entropy_severity, Severity.MEDIUM),
                span=candidate.span,
            )
        )

    return tuple(sorted(merged, key=lambda item: (*item.span, item.id)))


def describes_same_value(pattern: RawMatch, candidate: EntropyCandidate) -> bool:
    """Return whether a pattern match and an entropy candidate are one secret.

    This is the whole of the overlap decision, and it is deliberately narrow.

    **Containment merges.** One detector's span covering the other's is the
    normal case and needs no further evidence: a vendor rule matched inside a
    quoted literal, or inside a connection string, or inside a whole
    configuration value. The larger span says only "there is material here",
    which the smaller span has already identified.

    **Proper partial overlap merges only when the values agree.** Interleaved
    spans -- ``[10, 40)`` against ``[20, 60)`` -- are the one geometry where
    neither detector is looking at a superset of the other, and guessing here
    would be guessing about which of two values a human should go and look at.
    So the test is textual: does one detector's value contain the other's? An
    unquoted ``ghp_<36>`` inside a longer value run, where the run continues
    past the token, merges, because the vendor match found the same characters
    inside the same run.

    **Touching is not overlapping.** Two spans that merely abut describe two
    different values, and merging them would hide the second one.
    """

    pattern_span, candidate_span = pattern.span, candidate.span
    if not _overlaps(pattern_span, candidate_span):
        return False
    if _contains(pattern_span, candidate_span) or _contains(candidate_span, pattern_span):
        return True
    return pattern.value in candidate.value or candidate.value in pattern.value


def dedupe(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """Drop repeated occurrences of one match, deterministically.

    The key is ``(rule, location, fingerprint)``.

    * **Rule**, because two rules matching one place are two different claims
      and both are worth making.
    * **Location**, including the commit, because the same secret in two files
      or two commits is two occurrences and each one is somewhere a reviewer
      has to go.
    * **Fingerprint**, so that two findings that claim the same place with the
      same rule but different values are both kept. It is a truncated digest,
      so it separates values without revealing one.

    What the key deliberately does *not* contain is ``masked_value``. Under the
    default policy every value masks to the same twelve asterisks, so a mask
    would merge genuinely different secrets and delete real findings from the
    report that most needs them. Nor is the key
    :meth:`~secret_shield.models.Finding.secret_key`: that one answers "is this
    the same secret as that other finding?", which is a reporting question, and
    using it here would turn a correlation feature into a deletion.

    Order is preserved: the first finding for a key wins.
    """

    seen: set[tuple[str, str, int | None, int | None, str, str | None]] = set()
    kept: list[Finding] = []

    for finding in findings:
        location = finding.location
        key = (
            finding.rule_id,
            location.path,
            location.line,
            location.column,
            location.commit,
            finding.value_fingerprint,
        )
        if key in seen:
            continue
        seen.add(key)
        kept.append(finding)

    return tuple(kept)


def analyze_text(
    text: str,
    path: str,
    *,
    registry: DetectorRegistry | None = None,
    entropy: EntropyRuleConfig | None = None,
    source_kind: SourceKind = SourceKind.FILE,
    commit: str | None = None,
    commit_time: int | None = None,
) -> tuple[Finding, ...]:
    """Run both detectors over one text and return fused, redacted findings.

    This is the whole analysis pipeline for a single content unit, in the order
    it has to happen: both detectors speak first, fusion decides what is one
    finding, and only then is anything materialised. A finding is built after
    the last moment at which a duplicate could still be removed, because
    building one earlier would mean two masked copies of the same value to
    reconcile.

    Args:
        text: The full text of one file, with line endings already normalised.
            Both detectors must measure offsets in *this* string: fusion compares
            them, and a caller that hands two detectors differently truncated
            copies of a file is asking for wrong answers rather than fewer ones.
        path: File path recorded on every finding.
        registry: Pattern rules to apply. ``None`` uses the shipped catalog.
        entropy: Entropy thresholds. ``None`` uses the shipped defaults.
        source_kind: Whether the text came from a file or from Git history.
        commit: Commit hash, when scanning history.
        commit_time: Commit timestamp, when scanning history.

    Returns:
        Findings in the canonical order -- by path, then position, then rule --
        with duplicates removed. Empty when nothing matched.

    Raises:
        TypeError: If ``text`` is not a string or ``path`` is not one.
    """

    if not isinstance(text, str):
        raise TypeError(f"analyze_text() expects str, got {type(text).__name__}")
    if not isinstance(path, str):
        raise TypeError(f"analyze_text() expects str path, got {type(path).__name__}")

    settings = entropy if entropy is not None else default_entropy_config()

    patterns = find_matches(text, registry)
    candidates_found = entropy_candidates(candidates(text), settings)

    merged = fuse(
        patterns,
        candidates_found,
        entropy_severity=settings.severity_ceiling,
    )
    findings = tuple(
        match.to_finding(
            path,
            source_kind=source_kind,
            commit=commit,
            commit_time=commit_time,
        )
        for match in merged
    )

    return tuple(sorted(dedupe(findings), key=lambda finding: finding.sort_key))


# ---------------------------------------------------------------------------
# Fusion internals
# ---------------------------------------------------------------------------


def _overlaps(first: tuple[int, int], second: tuple[int, int]) -> bool:
    """Return whether two half-open ranges share at least one character.

    Half-open, so ``(0, 5)`` and ``(5, 9)`` do **not** overlap: they abut, and
    abutting spans are two values, not one.
    """

    return first[0] < second[1] and second[0] < first[1]


def _contains(outer: tuple[int, int], inner: tuple[int, int]) -> bool:
    """Return whether ``inner`` lies entirely within ``outer``."""

    return outer[0] <= inner[0] and inner[1] <= outer[1]


def _combined_confidence(base: Confidence, corroborated: bool) -> Confidence:
    """Return the confidence of a pattern match after fusion.

    Uncorroborated, the pattern match keeps whatever its rule and its context
    earned it, which is what :meth:`RawMatch.confidence` already decided.
    Corroborated, it gains exactly one step, floored at
    :data:`ENTROPY_CONFIDENCE` and clamped at :data:`MAX_CONFIDENCE`.

    Three consequences, all of them the point:

    * **One step, not one per corroborating candidate.** A literal containing
      three high-entropy tokens would otherwise escalate a weak heuristic to the
      ceiling on its own. Confidence has four levels; evidence should not be
      able to spend them faster than it can earn them.
    * **Floored at PROBABLE.** The entropy rule never reports below that, so a
      CANDIDATE pattern match corroborated by entropy lands on PROBABLE, not on
      a step *below* the evidence that supports it.
    * **Clamped at HIGH_CONFIDENCE.** An EXACT rule is already there, and
      ``VERIFIED`` is not reachable from any input. That is the point: see the
      module docstring on why agreement between two patterns over the same bytes
      is not verification.
    """

    if not corroborated:
        return base
    return Confidence(min(max(base, ENTROPY_CONFIDENCE) + 1, MAX_CONFIDENCE))


def _drop_duplicate_patterns(patterns: Sequence[RawMatch]) -> tuple[RawMatch, ...]:
    """Remove pattern matches that repeat another's span and value exactly.

    Both conditions are required. The same span with a *different* value means
    one regex match yielded two different groups -- ``database-uri-with-password``
    reporting the whole URI and its password would be the shape -- and those are
    two claims about two different things, so both stay.

    Which of two identical matches survives is decided by
    :func:`pattern_order`, so the survivor is always the more specific rule. The
    cost, stated plainly: if the catalog ever contained two rules matching
    identical bytes with identical values, the weaker rule's id would be lost.
    No such pair exists -- the catalog's patterns are disjoint by construction --
    and adding one is the moment :class:`~secret_shield.models.Finding` would
    need somewhere to record second-hand evidence.
    """

    seen: set[tuple[int, int, str]] = set()
    unique: list[RawMatch] = []

    for match in sorted(patterns, key=pattern_order):
        key = (*match.span, match.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(match)

    return tuple(unique)


def _corroborating_entropy(
    patterns: Sequence[RawMatch],
    entropy: Sequence[EntropyCandidate],
) -> tuple[dict[int, tuple[int, ...]], frozenset[int]]:
    """Decide which entropy candidates back which patterns, and which are spent.

    Returns ``(supporting, consumed)``:

    * ``supporting`` maps a pattern index to the entropy candidates that back it.
    * ``consumed`` is every entropy candidate that overlapped at least one
      pattern match, whether it backed exactly one or several.

    Step 3 of :func:`fuse` lives here: a candidate that describes more than one
    pattern backs none of them. It is still consumed, because it is not a
    finding about a secret -- it is the entropy rule noticing that a quoted
    literal is dense with random material, which is a fact about the literal and
    not about either of the keys inside it. Reporting it would put a third
    finding on a line that holds two secrets, describing a value that is neither.

    Both loops are over ordered sequences and neither builds an
    order-dependent result, so the mapping is a function of the evidence alone.
    """

    supporting: dict[int, list[int]] = {}
    consumed: set[int] = set()

    for candidate_index, candidate in enumerate(entropy):
        described = [
            index
            for index, match in enumerate(patterns)
            if describes_same_value(match, candidate)
        ]
        if not described:
            continue
        consumed.add(candidate_index)
        if len(described) == 1:
            supporting.setdefault(described[0], []).append(candidate_index)

    return (
        {index: tuple(indices) for index, indices in supporting.items()},
        frozenset(consumed),
    )