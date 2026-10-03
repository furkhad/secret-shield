"""Core data model for SecretShield.

Two ideas shape everything in this module.

**Severity and confidence are different questions.** Severity answers "if
this is real, how bad is it?" and comes from the rule, so it is fixed.
Confidence answers "how sure are we that this is real?" and comes from the
evidence for this particular match. A generic ``password = "..."`` line is
CRITICAL severity but only MEDIUM confidence; a bare AWS key ID is HIGH
confidence but MEDIUM severity, because the ID alone does not compromise
anything.

**A finding is evidence, not proof.** Nothing in this module is ever allowed to
claim that a match is a confirmed secret unless an out-of-band verification
step produced it. :attr:`Confidence.VERIFIED` exists so the vocabulary has
somewhere to go; the initial release never produces it.

The security invariant that makes the rest of the design work:
:class:`Finding` has **no field that can hold a raw secret**. A value is
masked and fingerprinted inside :meth:`Finding.from_match` and then dropped.
This is stronger than masking on output, because it means a stray ``print()``,
``repr()``, debugger session or traceback cannot leak anything -- the secret
is not there to leak.
"""

from __future__ import annotations

import enum
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from .entropy import MAX_ENTROPY
from .masking import (
    FINGERPRINT_LENGTH,
    REDACTION,
    MaskPolicy,
    contains_control_characters,
    is_fingerprint,
    strip_control_characters,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "SCHEMA_VERSION",
    "Severity",
    "Confidence",
    "SecretCategory",
    "SourceKind",
    "DetectorKind",
    "Location",
    "ScanError",
    "Finding",
    "ScanResult",
]

TOOL_NAME: Final[str] = "secret-shield"
"""Canonical tool name used in report envelopes."""

TOOL_VERSION: Final[str] = "0.1.0"
"""Current version, recorded in report envelopes.

Defined here rather than in ``__init__`` so that library modules can report the
version without importing the package they live in.
"""

SCHEMA_VERSION: Final[str] = "1.0"
"""Version of the report schema. Consumers should break loudly on a change."""

_RULE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$")
_COMMIT_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")


class _LabelledEnum(enum.Enum):
    """Shared label handling for the report-facing enums.

    Reports must always use :attr:`label`, never :func:`str`. ``Severity`` is
    an ``IntEnum``, so ``str(Severity.HIGH)`` renders as ``3`` on Python 3.11+
    and would silently corrupt output.
    """

    @property
    def label(self) -> str:
        """Lowercase, human-readable name used in all serialized output."""

        return self.name.lower()

    @classmethod
    def from_label(cls, value: str) -> _LabelledEnum:
        """Parse a label back into an enum member.

        Parsing is case-insensitive and treats ``-`` and ``_`` as equivalent,
        so ``"high-confidence"`` and ``"HIGH_CONFIDENCE"`` both work.

        Raises:
            TypeError: If ``value`` is not a string.
            ValueError: If ``value`` is not a valid label. The message lists
                the valid options, because a typo in a config file is the
                most likely cause.
        """

        if not isinstance(value, str):
            raise TypeError(
                f"{cls.__name__}.from_label() expects str, got {type(value).__name__}"
            )
        normalized = value.strip().lower().replace("-", "_")
        try:
            return cls[normalized.upper()]  # type: ignore[index]
        except KeyError:
            valid = ", ".join(member.label for member in cls)  # type: ignore[attr-defined]
            raise ValueError(
                f"unknown {cls.__name__} label {value!r}; valid labels: {valid}"
            ) from None


class Severity(_LabelledEnum, enum.IntEnum):
    """How damaging a finding would be *if the match is real*.

    Values are integers so that comparison against a ``--fail-on`` threshold
    is a plain ``>=`` and sorting findings is deterministic.
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Confidence(_LabelledEnum, enum.IntEnum):
    """How much evidence supports that a match is a genuine secret.

    Confidence is assigned per match, never per rule, and never rises just
    because a rule has a high severity. Entropy analysis may corroborate a
    pattern match but must never push a value to ``VERIFIED``.
    """

    CANDIDATE = 1
    """A weak signal. Usually context-driven or low-entropy only."""

    PROBABLE = 2
    """A heuristic rule with supporting context, or strong entropy."""

    HIGH_CONFIDENCE = 3
    """A vendor-specific pattern matched: a known prefix and a known length."""

    VERIFIED = 4
    """Confirmed against the issuing service out of band.

    The initial release never produces this value. It exists so that reports
    and thresholds have a stable destination for a future, opt-in
    verification step.
    """


class SecretCategory(_LabelledEnum, enum.StrEnum):
    """The kind of credential a finding refers to.

    The ``UNKNOWN`` member is deliberate: it lets a rule ship before its
    category is agreed, and keeps reports honest about what is known.
    """

    UNKNOWN = "unknown"
    API_KEY = "api_key"
    AWS = "aws"
    DATABASE = "database"
    GITHUB = "github"
    OPENAI = "openai"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    SLACK = "slack"
    STRIPE = "stripe"
    GENERIC_TOKEN = "generic_token"


class SourceKind(_LabelledEnum, enum.StrEnum):
    """Where the scanned bytes came from."""

    FILE = "file"
    GIT = "git"


class DetectorKind(_LabelledEnum, enum.StrEnum):
    """Which detector produced a finding, before any fusion.

    ``COMPOSITE`` means pattern and entropy evidence agreed on the same span.
    """

    PATTERN = "pattern"
    ENTROPY = "entropy"
    COMPOSITE = "composite"


@dataclass(frozen=True, slots=True)
class Location:
    """Where a match was observed.

    Line and column are 1-based, matching every editor and every error message
    a user will see. Both are optional because some scans have no line
    structure.
    """

    source_kind: SourceKind
    path: str
    line: int | None = None
    column: int | None = None
    commit: str | None = None
    commit_time: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path.strip():
            raise ValueError("path must be a non-empty string")
        # Normalised here, not at print time, so the stored value is already
        # safe. A directory scan builds this path from filenames found on disk,
        # and a filename may contain an ANSI escape or a newline: `evil\e[31mFAKE`
        # is a legal Linux filename and the cheapest way there is to forge a line
        # in someone's CI log. Stripping at construction means every consumer is
        # protected, including ones written later.
        #
        # The cost is that the reported path may not match the name on disk
        # exactly. That is the right way round: the path is a label for a human,
        # and a label that can repaint someone's terminal is not worth the
        # fidelity. A path that becomes empty is rejected below rather than
        # reported as an anonymous finding.
        object.__setattr__(self, "path", strip_control_characters(self.path))
        if not self.path.strip():
            raise ValueError("path must not consist only of control characters")
        self._validate_optional_int(self.line, "line")
        self._validate_optional_int(self.column, "column")
        if self.commit is not None:
            if not isinstance(self.commit, str):
                raise TypeError(f"commit must be str or None, got {type(self.commit).__name__}")
            if not _COMMIT_PATTERN.match(self.commit):
                raise ValueError("commit must be a full 40-character lowercase SHA-1")
        self._validate_optional_int(self.commit_time, "commit_time")
        if self.commit_time is not None and self.commit_time < 0:
            raise ValueError("commit_time must be a non-negative Unix timestamp")

    @staticmethod
    def _validate_optional_int(value: object, name: str) -> None:
        if value is None:
            return
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an int or None, got {type(value).__name__}")
        if value < 1:
            raise ValueError(f"{name} is 1-based and must be >= 1")

    def to_display(self) -> str:
        """Render the location the way an editor addresses it.

        Returns ``path:line:column`` for a file, or ``path@commit`` for Git
        history, dropping whichever parts are unknown.
        """

        text = self.path
        if self.line is not None:
            text += f":{self.line}"
            if self.column is not None:
                text += f":{self.column}"
        if self.commit is not None:
            text += f"@{self.commit[:12]}"
        return text

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping with a stable key order."""

        return {
            "source_kind": str(self.source_kind),
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "commit": self.commit,
            "commit_time": self.commit_time,
        }

    def __repr__(self) -> str:
        return (
            f"Location(source_kind={self.source_kind.label}, "
            f"path={self.path!r}, line={self.line}, column={self.column}, "
            f"commit={self.commit!r})"
        )


@dataclass(frozen=True, slots=True)
class ScanError:
    """A recoverable failure that happened while scanning.

    Errors are collected rather than raised so that one unreadable file does
    not abort a scan of ten thousand. The scan then finishes with exit code
    :data:`~secret_shield.exit_codes.EXIT_SCAN_ERROR`.

    The ``reason`` is written by us and displayed by us, so it must describe
    *what* failed without quoting the contents that failed. Never build a
    reason by interpolating scanned bytes.
    """

    reason: str
    path: str | None = None
    code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("reason must be a non-empty string")
        # Normalising here rather than at print time means the stored value is
        # already safe: a hostile path cannot inject escapes into a report.
        object.__setattr__(self, "reason", strip_control_characters(self.reason))
        if self.path is not None:
            if not isinstance(self.path, str):
                raise TypeError(f"path must be str or None, got {type(self.path).__name__}")
            object.__setattr__(self, "path", strip_control_characters(self.path))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping with a stable key order."""

        return {"code": self.code, "path": self.path, "reason": self.reason}

    def __repr__(self) -> str:
        return f"ScanError(path={self.path!r}, reason={self.reason!r}, code={self.code!r})"


@dataclass(frozen=True, slots=True)
class Finding:
    """One potential secret exposure, already redacted.

    A ``Finding`` records evidence that something secret-shaped exists at a
    location. It does not assert that the material is real or still valid;
    that judgement belongs to :attr:`confidence`.

    **Security invariant:** there is no attribute here that can hold raw
    secret material. Build instances through :meth:`from_match`, which masks
    and fingerprints the value and then discards it, or with values that are
    already redacted.

    Attributes:
        rule_id: Stable kebab-case identifier of the rule that matched.
        rule_name: Human-readable rule name for reports.
        category: What kind of credential this looks like.
        severity: How damaging it would be if real.
        confidence: How much evidence supports that it is real.
        detector: Which detector fired, before fusion.
        location: Where the match was observed.
        masked_value: Redacted value. Never contains the original.
        value_length: Length of the original value, a deliberate triage field.
            The masked value itself never encodes length.
        value_fingerprint: Truncated digest of the original value, used to
            correlate occurrences without storing the secret.
        entropy: Shannon entropy in bits per character, when entropy analysis
            contributed to this finding.
        matched_keywords: Non-secret evidence such as
            ``("aws_secret_access_key", "production")``. Never the value.
        remediation: Short advice on what to do about it.
    """

    rule_id: str
    rule_name: str
    category: SecretCategory
    severity: Severity
    confidence: Confidence
    detector: DetectorKind
    location: Location
    masked_value: str
    value_length: int
    value_fingerprint: str
    entropy: float | None = None
    matched_keywords: tuple[str, ...] = ()
    remediation: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not _RULE_ID_PATTERN.match(self.rule_id):
            raise ValueError(
                "rule_id must be a lowercase kebab-case identifier, "
                f"for example 'aws-access-key-id'; got {self.rule_id!r}"
            )
        if not isinstance(self.rule_name, str) or not self.rule_name.strip():
            raise ValueError("rule_name must be a non-empty string")
        if not isinstance(self.masked_value, str) or not self.masked_value:
            raise ValueError("masked_value must be a non-empty string")
        if contains_control_characters(self.masked_value):
            # Multi-line output would let a repository reshape a report, and a
            # masked value has no legitimate reason to contain one.
            raise ValueError("masked_value must not contain control characters")
        if isinstance(self.value_length, bool) or not isinstance(self.value_length, int):
            raise TypeError("value_length must be an int")
        if self.value_length < 0:
            raise ValueError("value_length must be non-negative")
        if not is_fingerprint(self.value_fingerprint):
            raise ValueError(
                "value_fingerprint must be "
                f"{FINGERPRINT_LENGTH} lowercase hexadecimal characters"
            )
        if self.entropy is not None:
            if isinstance(self.entropy, bool) or not isinstance(self.entropy, (int, float)):
                raise TypeError("entropy must be a float or None")
            if self.entropy != self.entropy:  # NaN
                raise ValueError("entropy must not be NaN")
            if not 0.0 <= float(self.entropy) <= MAX_ENTROPY:
                raise ValueError(f"entropy must be between 0.0 and {MAX_ENTROPY}")
        object.__setattr__(self, "matched_keywords", self._clean_keywords())
        object.__setattr__(self, "remediation", strip_control_characters(self.remediation))

    def _clean_keywords(self) -> tuple[str, ...]:
        """Validate keywords and freeze them into a tuple.

        Accepts any iterable at construction time so callers can pass a list or
        a set, but stores a tuple so the instance stays hashable and immutable.
        """

        keywords = self.matched_keywords
        if isinstance(keywords, str):
            raise TypeError("matched_keywords must be an iterable of strings, not a string")
        cleaned: list[str] = []
        for keyword in keywords:
            if not isinstance(keyword, str) or not keyword.strip():
                raise ValueError("each matched keyword must be a non-empty string")
            cleaned.append(strip_control_characters(keyword))
        return tuple(cleaned)

    @classmethod
    def from_match(
        cls,
        *,
        rule_id: str,
        rule_name: str,
        category: SecretCategory,
        severity: Severity,
        confidence: Confidence,
        detector: DetectorKind,
        location: Location,
        raw_value: str,
        policy: MaskPolicy | None = None,
        fingerprint_key: bytes | None = None,
        entropy: float | None = None,
        matched_keywords: Iterable[str] = (),
        remediation: str = "",
    ) -> Finding:
        """Build a finding from a raw match, redacting the value immediately.

        This is the only supported way to create a :class:`Finding` from
        detected material, and it exists so that the raw value has the
        shortest possible lifetime in the program.

        ``raw_value`` is a local: it is masked and fingerprinted on the two
        lines below and never assigned to ``self``, so it becomes unreachable
        as soon as this call returns. It is never logged, never embedded in an
        exception message, and never stored.

        Args:
            raw_value: The matched secret. Held only for the duration of this
                call.
            policy: Masking policy for this rule. Defaults to
                :data:`~secret_shield.masking.FULLY_REDACTED`.
            fingerprint_key: Optional HMAC key for :func:`fingerprint`. Use one
                for low-entropy values, whose unkeyed digests are
                brute-forceable.

        Returns:
            A finding that holds no raw secret material.

        Multi-line values -- a private key block, for instance -- are always
        fully redacted. Revealing a prefix of such a value would expose the
        surrounding block, and a redaction marker containing a newline would
        let scanned content break the layout of a report.
        """

        if not isinstance(raw_value, str):
            raise TypeError(f"raw_value must be str, got {type(raw_value).__name__}")

        effective_policy = policy if policy is not None else MaskPolicy()
        candidate = raw_value.strip()
        if contains_control_characters(candidate):
            masked_value = REDACTION
        else:
            masked_value = effective_policy.apply(candidate)

        # Raw material stops here. Nothing below reads it again.
        value_length = len(raw_value)
        value_fingerprint = effective_policy.fingerprint(raw_value, key=fingerprint_key)

        return cls(
            rule_id=rule_id,
            rule_name=rule_name,
            category=category,
            severity=severity,
            confidence=confidence,
            detector=detector,
            location=location,
            masked_value=masked_value,
            value_length=value_length,
            value_fingerprint=value_fingerprint,
            entropy=entropy,
            matched_keywords=matched_keywords,
            remediation=remediation,
        )

    def occurrence_key(self) -> tuple[str, str, int | None, int | None]:
        """Identify this one occurrence: rule plus place, ignoring commit.

        Used to collapse duplicates produced by overlapping rules or by a file
        reachable through several paths.
        """

        return (self.rule_id, self.location.path, self.location.line, self.location.column)

    def secret_key(self) -> tuple[str, str]:
        """Identify the underlying secret across occurrences.

        Two findings sharing a ``secret_key`` are the same material in
        different places. This is how "one key, twelve commits" is reported
        without storing the key.
        """

        return (self.rule_id, self.value_fingerprint)

    @property
    def sort_key(self) -> tuple[str, int, int, str, str]:
        """Deterministic ordering key: path, then position, then rule.

        Missing line or column sort as ``0`` so that single-line sources such
        as a filename-only result come first rather than failing to compare.
        """

        return (
            self.location.path,
            self.location.line or 0,
            self.location.column or 0,
            self.rule_id,
            self.value_fingerprint,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping with a stable key order."""

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category.value,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "detector": self.detector.value,
            "location": self.location.to_dict(),
            "masked_value": self.masked_value,
            "value_length": self.value_length,
            "value_fingerprint": self.value_fingerprint,
            "entropy": self.entropy,
            "matched_keywords": list(self.matched_keywords),
            "remediation": self.remediation,
        }

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize to JSON deterministically.

        ``to_dict`` fixes the key order, so the same finding always produces
        byte-identical JSON. That makes report diffs meaningful.
        """

        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    def __repr__(self) -> str:
        # Only redacted material and non-secret metadata appear here. An
        # accidental print, log or debugger inspection is therefore safe.
        return (
            f"Finding(rule_id={self.rule_id!r}, "
            f"severity={self.severity.label}, confidence={self.confidence.label}, "
            f"location={self.location.to_display()!r}, "
            f"masked_value={self.masked_value!r}, "
            f"value_fingerprint={self.value_fingerprint!r})"
        )


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one scan produced: findings, statistics and errors.

    Immutable and JSON-ready. Reporters take a ``ScanResult`` and return a
    string; writing the string to a file is the CLI's job, which keeps the
    reporters trivially testable.

    Lists passed in are converted to tuples so a caller cannot mutate a result
    after the fact.
    """

    findings: tuple[Finding, ...] = ()
    errors: tuple[ScanError, ...] = ()
    files_scanned: int = 0
    bytes_scanned: int = 0
    duration_seconds: float = 0.0
    tool_version: str = ""
    started_at: str | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", _freeze(self.findings, Finding, "findings"))
        object.__setattr__(self, "errors", _freeze(self.errors, ScanError, "errors"))
        for name in ("files_scanned", "bytes_scanned"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an int, got {type(value).__name__}")
            if value < 0:
                raise ValueError(f"{name} must be non-negative")
        if isinstance(self.duration_seconds, bool) or not isinstance(
            self.duration_seconds, (int, float)
        ):
            raise TypeError("duration_seconds must be a number")
        if self.duration_seconds != self.duration_seconds:  # NaN
            raise ValueError("duration_seconds must not be NaN")
        if self.duration_seconds < 0:
            raise ValueError("duration_seconds must be non-negative")

    def sorted_findings(self) -> tuple[Finding, ...]:
        """Return findings in the canonical, deterministic order.

        Sorting is by path, position and rule. The sort is stable, so findings
        that compare equal keep the order in which they were produced.
        """

        return tuple(sorted(self.findings, key=lambda finding: finding.sort_key))

    def counts_by_severity(self) -> Mapping[str, int]:
        """Count findings per severity label, most severe first.

        Every label is present, even at zero, so a report table has no holes.
        """

        counts = {severity.label: 0 for severity in sorted(Severity, reverse=True)}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def counts_by_confidence(self) -> Mapping[str, int]:
        """Count findings per confidence label, most confident first."""

        counts = {confidence.label: 0 for confidence in sorted(Confidence, reverse=True)}
        for finding in self.findings:
            counts[finding.confidence.label] += 1
        return counts

    def counts_by_category(self) -> Mapping[str, int]:
        """Count findings per category, ordered alphabetically for stable output."""

        counts: dict[str, int] = {}
        for finding in self.findings:
            key = finding.category.value
            counts[key] = counts.get(key, 0) + 1
        return {key: counts[key] for key in sorted(counts)}

    def highest_severity(self) -> Severity | None:
        """Return the most severe severity present, or ``None`` if no findings."""

        if not self.findings:
            return None
        return max(finding.severity for finding in self.findings)

    def distinct_secret_count(self) -> int:
        """Count unique secrets across all findings.

        Two findings of the same rule with the same fingerprint are one
        secret reported twice.
        """

        return len({finding.secret_key() for finding in self.findings})

    def summary(self) -> dict[str, Any]:
        """Return the report's summary block with a stable key order."""

        highest = self.highest_severity()
        return {
            "total_findings": len(self.findings),
            "distinct_secrets": self.distinct_secret_count(),
            "by_severity": dict(self.counts_by_severity()),
            "by_confidence": dict(self.counts_by_confidence()),
            "by_category": dict(self.counts_by_category()),
            "highest_severity": highest.label if highest is not None else None,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "error_count": len(self.errors),
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable report envelope with a stable key order."""

        return {
            "schema_version": self.schema_version,
            "tool": {"name": TOOL_NAME, "version": self.tool_version},
            "summary": self.summary(),
            "findings": [finding.to_dict() for finding in self.sorted_findings()],
            "errors": [error.to_dict() for error in self.errors],
        }

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize the whole report to deterministic JSON."""

        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    def __repr__(self) -> str:
        return (
            f"ScanResult(findings={len(self.findings)}, errors={len(self.errors)}, "
            f"files_scanned={self.files_scanned}, bytes_scanned={self.bytes_scanned})"
        )


def _freeze(values: Iterable[Any], expected_type: type, name: str) -> tuple[Any, ...]:
    """Convert an iterable of models into a tuple, validating element types."""

    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be an iterable of {expected_type.__name__}, not a string")
    try:
        items = tuple(values)
    except TypeError:
        raise TypeError(f"{name} must be an iterable of {expected_type.__name__}") from None
    for item in items:
        if not isinstance(item, expected_type):
            raise TypeError(
                f"{name} must contain only {expected_type.__name__} instances, "
                f"got {type(item).__name__}"
            )
    return items