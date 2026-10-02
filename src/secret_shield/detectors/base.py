"""The rule abstraction, the match record, and the registry.

Stage 1 detected secrets by asking one question about every plausible string:
does it look random? That question has no room for what a secret *is*. Stage 2
adds the second question -- which vendor, which shape, which length -- and this
module is the machinery for asking it.

The design goal is that **adding a provider is a data change, not a code
change**. A rule is a frozen dataclass holding a pattern and its metadata; the
registry is an ordered collection; the engine in this module walks rules
generically. Nothing here mentions AWS, Stripe or GitHub. Those names appear
only in :mod:`secret_shield.detectors.catalog`, so a new provider is one entry
in a tuple.

Three types make up the public surface:

* :class:`Rule` -- a pattern plus everything needed to judge, report and redact
  a match. Immutable and self-validating.
* :class:`RawMatch` -- one rule hitting one span. Transient, and the *only*
  place in the system where a raw credential is allowed to exist.
* :class:`DetectorRegistry` -- an ordered, duplicate-proof collection of rules.

**The raw-value lifetime.** :class:`RawMatch` holds the matched text because
placeholder suppression, entropy measurement and context scoring all need the
real characters. It is created by :func:`find_matches`, consumed by
:func:`findings_from`, and dropped. It is never stored in a
:class:`~secret_shield.models.Finding`, never written to a report, and its
``repr`` is redacted so that a debugger or traceback cannot print it. This is
the same discipline
:class:`~secret_shield.models.Finding.from_match` applies to ``raw_value``.

**Nothing here proves a credential is live.** A pattern match says a value has
the shape a vendor issues. It says nothing about whether the value is active,
whether it belongs to the repository's owner, or whether it has already been
rotated. SecretShield never contacts an issuing service, so no rule in this
module can ever justify ``Confidence.VERIFIED``.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Final

from ..entropy import shannon_entropy
from ..masking import FULLY_REDACTED, MaskPolicy
from ..models import (
    Confidence,
    DetectorKind,
    Finding,
    Location,
    SecretCategory,
    Severity,
    SourceKind,
)
from ..tokenizer import has_repetitive_structure
from .context import (
    assignment_name,
    is_placeholder,
    is_template_expression,
    looks_like_hash,
    normalize_for_matching,
)

__all__ = [
    "DetectorKind",
    "RawMatch",
    "Rule",
    "DetectorRegistry",
    "Specificity",
    "MAX_MATCH_LENGTH",
    "VALUE_GROUP_NAMES",
    "find_matches",
    "findings_from",
]


class Specificity(Enum):
    """How much a rule's pattern alone tells us about a match.

    The tiers are a statement about *evidence*, not about *impact*. A rule that
    pins a vendor prefix to a documented length is EXACT: the shape is
    meaningful even on an otherwise empty line. A rule that matches "some
    high-entropy value assigned to something called ``token``" is HEURISTIC:
    both halves of the evidence are individually weak.
    """

    EXACT = "exact"
    """A fixed vendor prefix, a constrained alphabet, or a strong identity."""

    HEURISTIC = "heuristic"
    """A generic password/api_key/token assignment, a generic URI, or an
    otherwise ambiguous candidate."""


#: Named groups a rule pattern may use to designate the credential itself,
#: rather than the whole match.
#:
#: A rule whose pattern also matches surrounding syntax -- an assignment's
#: right-hand side, say -- needs to say which part is the secret. A group named
#: ``secret`` or ``value`` is the credential; without one, the whole match is.
#: Checking two names rather than one costs nothing and lets a catalog author
#: use whichever reads better at the call site.
VALUE_GROUP_NAMES: Final[tuple[str, ...]] = ("secret", "value")

_RULE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$")

#: Longest match a single rule may produce. A rule that can match "the rest of
#: the file" is a bug, and this bound turns that bug into a truncated finding
#: rather than a multi-megabyte report line.
MAX_MATCH_LENGTH: Final[int] = 32_768


@dataclass(frozen=True, slots=True)
class Rule:
    """One detection rule: a pattern and the metadata needed to act on it.

    Rules are data. Adding a provider means adding a :class:`Rule` to the
    catalog; it never means editing this class or the engine.

    Patterns are compiled once, at construction, so a malformed rule is
    rejected where it is written rather than at scan time. A catalog that
    imports cleanly is a catalog whose regexes all compile.

    Attributes:
        id: Stable kebab-case identifier. Unique across a registry.
        name: Human-readable name for reports.
        category: What kind of credential this rule looks for.
        severity: Impact *if the match is real*. Independent of confidence.
        pattern: Regular expression source. Matched against whole-file text,
            never against a pre-split token, so that a rule may span lines.
        specificity: Evidence tier. Drives the default confidence.
        base_confidence: Confidence before any contextual evidence is counted.
            ``None`` derives it from :attr:`specificity`. May not be
            ``Confidence.VERIFIED``: verification is out of band.
        keywords: Context words that support this rule. With
            :attr:`requires_context`, at least one must be present or the match
            is discarded.
        placeholders: Extra placeholder markers for this rule, beyond the global
            list. Use for vendor-specific filler such as a published example.
        min_entropy: Minimum Shannon entropy in bits per character. ``None``
            disables the check, which is correct for rules whose pattern already
            constrains the value.
        max_length: Longest value this rule accepts. ``None`` means no bound
            beyond :data:`MAX_MATCH_LENGTH`.
        requires_context: When ``True``, a match with no supporting keyword on
            its line is discarded rather than merely downgraded.
        suppress_placeholders: When ``True`` (the default), placeholder markers
            discard the match. Set ``False`` only when the rule's own pattern
            already establishes what the value is, and a marker inside it is
            therefore structural rather than filler -- ``sk_test_...`` is the
            worked example, since ``test`` is a placeholder word and also part
            of a Stripe key prefix.
        reject_hashes: When ``True``, values shaped like a known checksum are
            discarded. Off by default, because a 32-character hex string is a
            plausible secret and only this rule's owner knows it is not.
        mask_policy: How to redact a match from this rule.
        false_positive_notes: What this rule is known to misfire on. Carried in
            the metadata so the cost of each rule is written down next to it.
        remediation: What to do about a match. Shown once per rule in reports.
        priority: Lower numbers are evaluated first and reported first. Ties
            break on :attr:`id`, so ordering never depends on registration
            order.
        dotall: Compile the pattern with ``re.DOTALL``, for rules that must
            span lines.
        compiled: The compiled pattern. Set in ``__post_init__``; excluded from
            equality and ``repr``.
    """

    id: str
    name: str
    category: SecretCategory
    severity: Severity
    pattern: str
    specificity: Specificity = Specificity.EXACT
    base_confidence: Confidence | None = None
    keywords: tuple[str, ...] = ()
    placeholders: tuple[str, ...] = ()
    min_entropy: float | None = None
    max_length: int | None = None
    requires_context: bool = False
    suppress_placeholders: bool = True
    reject_hashes: bool = False
    mask_policy: MaskPolicy = FULLY_REDACTED
    false_positive_notes: str = ""
    remediation: str = ""
    priority: int = 100
    dotall: bool = False

    compiled: re.Pattern[str] = field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        _require_text(self.id, "id")
        if not _RULE_ID_PATTERN.match(self.id):
            raise ValueError(
                f"rule id must be lowercase alphanumeric segments joined by '-' or '_', "
                f"got {self.id!r}"
            )
        _require_text(self.name, "name")

        if not isinstance(self.category, SecretCategory):
            raise TypeError(f"category must be a SecretCategory, got {type(self.category).__name__}")
        if not isinstance(self.severity, Severity):
            raise TypeError(f"severity must be a Severity, got {type(self.severity).__name__}")
        if not isinstance(self.specificity, Specificity):
            raise TypeError(
                f"specificity must be a Specificity, got {type(self.specificity).__name__}"
            )
        if self.base_confidence is not None and not isinstance(self.base_confidence, Confidence):
            raise TypeError(
                f"base_confidence must be a Confidence or None, got {type(self.base_confidence).__name__}"
            )
        if self.base_confidence is Confidence.VERIFIED:
            # A pattern match is evidence about shape, never about liveness.
            # Allowing VERIFIED here would let a future catalog entry claim
            # out-of-band verification that never happened.
            raise ValueError(
                f"rule {self.id!r} may not declare VERIFIED confidence; "
                "verification requires contacting the issuing service, "
                "which SecretShield never does"
            )

        self._require_string_tuple(self.keywords, "keywords")
        self._require_string_tuple(self.placeholders, "placeholders")
        _require_text(self.false_positive_notes, "false_positive_notes", allow_empty=True)
        _require_text(self.remediation, "remediation", allow_empty=True)
        _require_text(self.pattern, "pattern")

        if not isinstance(self.mask_policy, MaskPolicy):
            raise TypeError("mask_policy must be a MaskPolicy")
        if self.min_entropy is not None:
            if isinstance(self.min_entropy, bool) or not isinstance(self.min_entropy, (int, float)):
                raise TypeError("min_entropy must be a number or None")
            if not 0.0 <= float(self.min_entropy) <= 8.0:
                raise ValueError("min_entropy must be between 0.0 and 8.0 bits per character")
        if self.max_length is not None:
            if isinstance(self.max_length, bool) or not isinstance(self.max_length, int):
                raise TypeError("max_length must be an int or None")
            if self.max_length < 1:
                raise ValueError("max_length must be at least 1")
        if not isinstance(self.priority, int) or isinstance(self.priority, bool):
            raise TypeError("priority must be an int")
        if not isinstance(self.dotall, bool):
            raise TypeError("dotall must be a bool")
        if not isinstance(self.suppress_placeholders, bool):
            raise TypeError("suppress_placeholders must be a bool")
        if not isinstance(self.reject_hashes, bool):
            raise TypeError("reject_hashes must be a bool")
        if self.requires_context and not self.keywords:
            raise ValueError(
                f"rule {self.id!r} requires context but declares no keywords, "
                "so it could never match"
            )

        flags = re.MULTILINE | (re.DOTALL if self.dotall else 0)
        try:
            compiled = re.compile(self.pattern, flags)
        except re.error as exc:
            # The pattern is rule metadata, never scanned content, so quoting it
            # here leaks nothing.
            raise ValueError(f"rule {self.id!r} has an invalid pattern: {exc}") from exc

        object.__setattr__(self, "compiled", compiled)

    @staticmethod
    def _require_string_tuple(values: object, name: str) -> None:
        if isinstance(values, str) or not isinstance(values, Iterable):
            raise TypeError(f"{name} must be a tuple of strings, got {type(values).__name__}")
        for value in values:
            _require_text(value, f"{name} entry")

    @property
    def confidence_floor(self) -> Confidence:
        """Confidence before any contextual evidence is counted."""

        if self.base_confidence is not None:
            return self.base_confidence
        if self.specificity is Specificity.EXACT:
            return Confidence.HIGH_CONFIDENCE
        return Confidence.CANDIDATE

    @property
    def value_group(self) -> str | None:
        """Name of the group holding the credential, or ``None`` for group 0."""

        for name in VALUE_GROUP_NAMES:
            if name in self.compiled.groupindex:
                return name
        return None

    def all_placeholders(self) -> tuple[str, ...]:
        """Rule-specific placeholder markers, normalised to lower case."""

        return tuple(marker.lower() for marker in self.placeholders)

    def search(self, text: str) -> Iterator[re.Match[str]]:
        """Yield every match of this rule's pattern in ``text``."""

        return self.compiled.finditer(text)


@dataclass(frozen=True, slots=True)
class RawMatch:
    """One rule matching one span of text.

    **This object holds the credential in the clear.** It is the only type in
    SecretShield permitted to do so, it is created and destroyed inside a
    single scan, and its :meth:`__repr__` is redacted so that an accidental
    print, log or debugger inspection reveals nothing.

    A :class:`~secret_shield.models.Finding` must never be built from this
    object's ``value`` field by anything other than
    :meth:`~secret_shield.models.Finding.from_match`, which redacts
    immediately.

    Attributes:
        rule: The rule that matched.
        value: The matched credential text. Never persisted.
        line: 1-based line of the first character.
        column: 1-based column of the first character.
        end_line: 1-based line of the last character.
        end_column: 1-based column just past the last character.
        start_offset: 0-based offset of the first character in the file text.
        end_offset: 0-based offset just past the match.
        entropy: Shannon entropy of the value in bits per character.
        matched_keywords: Context words that supported this match.
        assignment_name: Variable name the value was assigned to, if any.
    """

    rule: Rule
    value: str
    line: int
    column: int
    end_line: int
    end_column: int
    start_offset: int
    end_offset: int
    entropy: float
    matched_keywords: tuple[str, ...] = ()
    assignment_name: str | None = None

    @property
    def id(self) -> str:
        """The matching rule's identifier."""

        return self.rule.id

    @property
    def length(self) -> int:
        """Length of the raw value in characters."""

        return len(self.value)

    @property
    def span(self) -> tuple[int, int]:
        """``(start_offset, end_offset)``, for overlap tests.

        Stage 4 needs this to merge a pattern match with an entropy match that
        covers the same bytes, so that one span produces one
        ``DetectorKind.COMPOSITE`` finding rather than two competing ones.
        """

        return (self.start_offset, self.end_offset)

    @property
    def overlaps(self) -> bool:
        """Whether this match covers more than one line."""

        return self.end_line > self.line

    def confidence(self) -> Confidence:
        """Confidence after contextual evidence.

        Supporting context raises a HEURISTIC rule by exactly one step. An EXACT
        rule is already at the ceiling, so context cannot raise it further --
        there is nowhere above ``HIGH_CONFIDENCE`` to go except
        ``VERIFIED``, and this tool never claims that.
        """

        floor = self.rule.confidence_floor
        if floor >= Confidence.HIGH_CONFIDENCE:
            return floor
        if self.matched_keywords or self.assignment_name:
            return min(Confidence.HIGH_CONFIDENCE, Confidence(floor + 1))
        return floor

    def to_finding(
        self,
        path: str,
        *,
        source_kind: SourceKind = SourceKind.FILE,
        commit: str | None = None,
        commit_time: int | None = None,
    ) -> Finding:
        """Convert to a redacted :class:`~secret_shield.models.Finding`.

        The raw value is passed to ``from_match``, which masks and fingerprints
        it and then drops it. Nothing about this object outlives the call.
        """

        return Finding.from_match(
            rule_id=self.rule.id,
            rule_name=self.rule.name,
            category=self.rule.category,
            severity=self.rule.severity,
            confidence=self.confidence(),
            detector=DetectorKind.PATTERN,
            location=Location(
                source_kind=source_kind,
                path=path,
                line=self.line,
                column=self.column,
                commit=commit,
                commit_time=commit_time,
            ),
            raw_value=self.value,
            policy=self.rule.mask_policy,
            entropy=self.entropy,
            matched_keywords=self.matched_keywords,
            remediation=self.rule.remediation,
        )

    def __repr__(self) -> str:
        # Redacted by construction: length and position only. Never the value.
        return (
            f"RawMatch(rule_id={self.rule.id!r}, length={self.length}, "
            f"line={self.line}, column={self.column}, "
            f"confidence={self.confidence().label!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class DetectorRegistry:
    """An ordered, duplicate-proof collection of rules.

    Ordering is by ``(priority, id)`` and not by insertion, so two registries
    built from differently ordered inputs scan in the same order and produce
    the same report. That matters for diffing.

    Args:
        rules: Rules to register. Order does not affect behaviour.

    Raises:
        ValueError: If two rules share an id, or a rule fails validation.
    """

    __slots__ = ("_rules",)

    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self._rules: dict[str, Rule] = {}
        for rule in rules:
            self.register(rule)

    def register(self, rule: Rule) -> Rule:
        """Add a rule and return it, for use in an assignment.

        Raises:
            TypeError: If ``rule`` is not a :class:`Rule`.
            ValueError: If its id is already registered. Failing loudly is
                deliberate: two rules sharing an id would silently double-report
                or shadow each other depending on iteration order.
        """

        if not isinstance(rule, Rule):
            raise TypeError(f"register() expects a Rule, got {type(rule).__name__}")
        if rule.id in self._rules:
            raise ValueError(f"duplicate rule id {rule.id!r} in registry")
        self._rules[rule.id] = rule
        return rule

    def get(self, rule_id: str) -> Rule:
        """Return the rule with this id.

        Raises:
            KeyError: If no such rule is registered.
        """

        try:
            return self._rules[rule_id]
        except KeyError:
            raise KeyError(f"no rule registered with id {rule_id!r}") from None

    def find(self, rule_id: str) -> Rule | None:
        """Return the rule with this id, or ``None``."""

        return self._rules.get(rule_id)

    def rules(self) -> tuple[Rule, ...]:
        """Every rule in deterministic evaluation order."""

        return tuple(sorted(self._rules.values(), key=lambda rule: (rule.priority, rule.id)))

    def ids(self) -> tuple[str, ...]:
        """Every registered id in evaluation order."""

        return tuple(rule.id for rule in self.rules())

    def for_category(self, category: SecretCategory) -> tuple[Rule, ...]:
        """Every rule targeting one category, in evaluation order."""

        return tuple(rule for rule in self.rules() if rule.category is category)

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules

    def __iter__(self) -> Iterator[Rule]:
        return iter(self.rules())

    def __len__(self) -> int:
        return len(self._rules)


class _LineIndex:
    """Map a character offset to a 1-based line and column.

    Built once per scan. A bisect per lookup keeps line-accurate reporting
    affordable even when dozens of rules match in a large file.
    """

    __slots__ = ("_starts",)

    def __init__(self, text: str) -> None:
        starts = [0]
        index = text.find("\n")
        while index != -1:
            starts.append(index + 1)
            index = text.find("\n", index + 1)
        self._starts = starts

    def position(self, offset: int) -> tuple[int, int]:
        """Return the 1-based ``(line, column)`` of a character offset."""

        line_index = bisect.bisect_right(self._starts, offset) - 1
        return (line_index + 1, offset - self._starts[line_index] + 1)


def _require_text(value: object, name: str, *, allow_empty: bool = False) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if not value.strip() and not allow_empty:
        raise ValueError(f"{name} must be a non-empty string")


def _extract_value(match: re.Match[str], rule: Rule) -> str | None:
    """Return the credential text a match designates.

    Uses the ``secret``/``value`` group when the rule declares one, and the
    whole match otherwise. Returns ``None`` when the designated group is absent
    or did not participate, which happens with alternations such as
    ``(?P<secret>foo)|(?P<value>bar)``.
    """

    group = rule.value_group
    value = match.group(0) if group is None else match.group(group)
    return value or None


def _line_text(text: str, offset: int) -> str:
    """Return the line containing ``offset``, without its terminator."""

    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return text[start:] if end == -1 else text[start:end]


def _present_keywords(rule: Rule, line: str) -> tuple[str, ...]:
    """Return the rule's keywords that appear in ``line``.

    Matching is on :func:`normalize_for_matching` output, so spelling and
    separator conventions do not matter: ``AWS_SECRET_ACCESS_KEY``,
    ``aws-secret-access-key`` and ``AwsSecretAccessKey`` all match
    ``aws_secret_access_key``.

    The keyword itself is returned, never the line, so nothing scanned leaks
    into a finding.
    """

    if not rule.keywords:
        return ()
    haystack = normalize_for_matching(line)
    return tuple(
        stripped
        for keyword in rule.keywords
        if (stripped := keyword.strip()) and normalize_for_matching(stripped) in haystack
    )


def _is_rule_placeholder(rule: Rule, value: str) -> bool:
    """Return ``True`` when a rule's own placeholder markers appear in a value."""

    lowered = value.lower()
    return any(marker in lowered for marker in rule.all_placeholders())


def find_matches(
    text: str,
    registry: DetectorRegistry | None = None,
    *,
    config: object = None,
) -> list[RawMatch]:
    """Run every registered rule over ``text`` and return surviving matches.

    Each match passes through the same gate, in this order, so that the reason
    for a rejection is always the same reason regardless of which rule fired:

    1. **Empty or oversized.** A match that could match "the rest of the file"
       is a rule-authoring bug, and is bounded rather than reported.
    2. **Placeholder and template.** Documented examples and unfilled
       interpolations are not credentials.
    3. **Repetitive structure.** ``aaaaaaaa`` and ``abcdef`` carry no
       information; this is Stage 1's filter, reused rather than duplicated.
    4. **Hash shape**, only for rules that opt in.
    5. **Entropy floor**, only for rules that set one.
    6. **Mandatory context**, for rules that require it. This *discards* the
       match rather than downgrading it, because a 40-character base64 string
       that no vendor claims is not an AWS secret key.

    Args:
        text: Full text of one file. Line endings are expected to be normalised
            already, as :func:`secret_shield.scanner.scan_file` does.
        registry: Rules to apply. Defaults to
            :func:`default_registry` from :mod:`secret_shield.detectors.catalog`.
        config: Reserved for per-scan tuning. Accepted and ignored so that
            callers can pass it before it is needed.

    Returns:
        Matches in ``(rule priority, rule id, offset)`` order, which is
        deterministic and independent of dict iteration or thread scheduling.

    Note:
        The returned objects hold raw credential text. Convert them with
        :func:`findings_from` immediately and let them go out of scope.

    Note:
        Overlapping matches from different rules are *not* merged here. Deciding
        that a pattern match and an entropy match covering the same bytes should
        become one ``COMPOSITE`` finding is a later stage's job, and doing it
        half-way here would be worse than not doing it.
    """

    if not isinstance(text, str):
        raise TypeError(f"find_matches() expects str, got {type(text).__name__}")

    active = registry if registry is not None else _catalog_registry()
    index = _LineIndex(text)
    matches: list[RawMatch] = []

    for rule in active.rules():
        for found in rule.compiled.finditer(text):
            candidate = _extract_value(found, rule)
            if candidate is None:
                continue
            if len(candidate) > MAX_MATCH_LENGTH:
                continue
            if rule.max_length is not None and len(candidate) > rule.max_length:
                continue
            if rule.suppress_placeholders and (
                is_placeholder(candidate) or _is_rule_placeholder(rule, candidate)
            ):
                continue
            if is_template_expression(candidate):
                continue
            if has_repetitive_structure(candidate):
                continue
            if rule.reject_hashes and looks_like_hash(candidate):
                continue

            entropy = shannon_entropy(candidate)
            if rule.min_entropy is not None and entropy < rule.min_entropy:
                continue

            line, column = index.position(found.start())
            end_line, end_column = index.position(max(found.start(), found.end() - 1))
            line_text = _line_text(text, found.start())
            keywords = _present_keywords(rule, line_text)
            if rule.requires_context and not keywords:
                continue

            matches.append(
                RawMatch(
                    rule=rule,
                    value=candidate,
                    line=line,
                    column=column,
                    end_line=end_line,
                    end_column=end_column,
                    start_offset=found.start(),
                    end_offset=found.end(),
                    entropy=entropy,
                    matched_keywords=keywords,
                    assignment_name=assignment_name(line_text, column),
                )
            )

    return matches


def findings_from(
    matches: Iterable[RawMatch],
    path: str,
    *,
    source_kind: SourceKind = SourceKind.FILE,
    commit: str | None = None,
    commit_time: int | None = None,
) -> tuple[Finding, ...]:
    """Convert raw matches to redacted findings, dropping exact duplicates.

    This is the only function that turns a :class:`RawMatch` into a
    :class:`~secret_shield.models.Finding`, and it does so through
    ``from_match``, which redacts before returning. Duplicates are collapsed on
    ``(rule, span)``, which can only arise from a rule whose pattern matches the
    same bytes twice.

    Args:
        matches: Output of :func:`find_matches`.
        path: File path recorded on every finding.
        source_kind: Whether the text came from a file or from Git history.
        commit: Commit hash, when scanning history.
        commit_time: Commit timestamp, when scanning history.

    Returns:
        Findings in deterministic order.
    """

    findings: list[Finding] = []
    seen: set[tuple[str, int, int]] = set()

    for match in matches:
        key = (match.rule.id, *match.span)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            match.to_finding(
                path,
                source_kind=source_kind,
                commit=commit,
                commit_time=commit_time,
            )
        )

    return tuple(findings)


def _catalog_registry() -> DetectorRegistry:
    """Return the shipped catalog, built once and cached.

    Imported lazily so that :mod:`catalog` can import this module for
    :class:`Rule` without a circular import at module load.
    """

    global _CATALOG_REGISTRY
    if _CATALOG_REGISTRY is None:
        from .catalog import default_registry

        _CATALOG_REGISTRY = default_registry()
    return _CATALOG_REGISTRY


_CATALOG_REGISTRY: DetectorRegistry | None = None