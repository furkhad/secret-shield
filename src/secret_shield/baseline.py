"""Baseline management for SecretShield.

A baseline is a persistent record of known findings that should not cause a
scan to fail. It enables incremental adoption: a team can baseline existing
findings, then fail only on new ones.

Security invariants:
- A baseline entry never contains raw secret material.
- The finding identity is stable and does not depend on the report fingerprint mode.
- Baseline matching does not silently suppress changed findings.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .models import Finding, ScanResult
from .masking import is_fingerprint, strip_control_characters

__all__ = [
    "BASELINE_SCHEMA_VERSION",
    "BASELINE_TOOL_NAME",
    "Baseline",
    "BaselineEntry",
    "BaselineComparison",
    "FindingIdentity",
    "load_baseline",
    "save_baseline",
    "compare_with_baseline",
    "FindingClassification",
]

BASELINE_SCHEMA_VERSION: Final[str] = "1.0"
"""Version of the baseline schema. Consumers should break loudly on a change."""

BASELINE_TOOL_NAME: Final[str] = "secret-shield"
"""Tool name recorded in baseline files."""


@dataclass(frozen=True, slots=True)
class FindingIdentity:
    """Stable identity for a finding, independent of report fingerprint mode.

    This identity is used for baseline matching. It includes the value_fingerprint
    which is computed during Finding creation using the configured fingerprint key.
    Two findings with the same identity represent the same secret at the same location.
    """

    rule_id: str
    path: str
    line: int | None
    column: int | None
    value_fingerprint: str
    commit: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id.strip():
            raise ValueError("rule_id must be a non-empty string")
        if not isinstance(self.path, str) or not self.path.strip():
            raise ValueError("path must be a non-empty string")
        if self.line is not None and (not isinstance(self.line, int) or self.line < 1):
            raise ValueError("line must be a positive integer or None")
        if self.column is not None and (not isinstance(self.column, int) or self.column < 1):
            raise ValueError("column must be a positive integer or None")
        if not is_fingerprint(self.value_fingerprint):
            raise ValueError(
                f"value_fingerprint must be a valid fingerprint: {self.value_fingerprint!r}"
            )
        if self.commit is not None:
            if not isinstance(self.commit, str) or len(self.commit) != 40:
                raise ValueError("commit must be a 40-character SHA-1 or None")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping with stable key order."""
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "value_fingerprint": self.value_fingerprint,
            "commit": self.commit,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FindingIdentity:
        """Create a FindingIdentity from a dictionary."""
        return cls(
            rule_id=data["rule_id"],
            path=data["path"],
            line=data.get("line"),
            column=data.get("column"),
            value_fingerprint=data["value_fingerprint"],
            commit=data.get("commit"),
        )

    @classmethod
    def from_finding(cls, finding: Finding) -> FindingIdentity:
        """Create a FindingIdentity from a Finding."""
        location = finding.location
        return cls(
            rule_id=finding.rule_id,
            path=location.path,
            line=location.line,
            column=location.column,
            value_fingerprint=finding.value_fingerprint,
            commit=location.commit,
        )

    def sort_key(self) -> tuple[str, str, int | None, int | None, str, str | None]:
        """Deterministic ordering key for baseline entries."""
        return (
            self.rule_id,
            self.path,
            self.line or 0,
            self.column or 0,
            self.value_fingerprint,
            self.commit or "",
        )


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """A single entry in a baseline file.

    Contains only the finding identity and non-secret metadata. No raw secrets,
    no masked values, no source lines.
    """

    identity: FindingIdentity
    category: str
    severity: str
    confidence: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping with stable key order."""
        return {
            "identity": self.identity.to_dict(),
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineEntry:
        """Create a BaselineEntry from a dictionary."""
        return cls(
            identity=FindingIdentity.from_dict(data["identity"]),
            category=data["category"],
            severity=data["severity"],
            confidence=data["confidence"],
        )

    @classmethod
    def from_finding(cls, finding: Finding) -> BaselineEntry:
        """Create a BaselineEntry from a Finding."""
        return cls(
            identity=FindingIdentity.from_finding(finding),
            category=finding.category.value
            if hasattr(finding.category, "value")
            else str(finding.category),
            severity=finding.severity.label if hasattr(finding.severity, "label") else str(finding.severity),
            confidence=finding.confidence.label if hasattr(finding.confidence, "label") else str(finding.confidence),
        )

    def sort_key(self) -> tuple[str, str, int | None, int | None, str, str | None]:
        """Deterministic ordering key."""
        return self.identity.sort_key()


@dataclass(frozen=True, slots=True)
class Baseline:
    """A collection of baselined findings.

    The baseline is immutable once created. Use `with_entries` to create a
    modified copy.
    """

    schema_version: str
    tool_name: str
    tool_version: str
    entries: tuple[BaselineEntry, ...]

    def __post_init__(self) -> None:
        if self.schema_version != BASELINE_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported baseline schema version: {self.schema_version!r} "
                f"(expected {BASELINE_SCHEMA_VERSION!r})"
            )
        if self.tool_name != BASELINE_TOOL_NAME:
            raise ValueError(
                f"baseline tool name mismatch: {self.tool_name!r} "
                f"(expected {BASELINE_TOOL_NAME!r})"
            )
        # Validate entries are sorted
        for i in range(len(self.entries) - 1):
            if self.entries[i].sort_key() > self.entries[i + 1].sort_key():
                raise ValueError("baseline entries must be sorted by identity")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping with stable key order."""
        return {
            "schema_version": self.schema_version,
            "tool": {"name": self.tool_name, "version": self.tool_version},
            "entries": [entry.to_dict() for entry in self.entries],
        }

    def to_json(self) -> str:
        """Serialize to deterministic JSON."""
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=False,
            separators=(",", ":"),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Baseline:
        """Create a Baseline from a dictionary."""
        tool = data.get("tool", {})
        return cls(
            schema_version=data["schema_version"],
            tool_name=tool.get("name", BASELINE_TOOL_NAME),
            tool_version=tool.get("version", "unknown"),
            entries=tuple(
                sorted(
                    (BaselineEntry.from_dict(e) for e in data.get("entries", [])),
                    key=lambda e: e.sort_key(),
                )
            ),
        )

    def with_entries(self, entries: tuple[BaselineEntry, ...]) -> Baseline:
        """Return a new Baseline with the given entries."""
        return Baseline(
            schema_version=self.schema_version,
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            entries=tuple(sorted(entries, key=lambda e: e.sort_key())),
        )

    def identities(self) -> set[FindingIdentity]:
        """Return the set of finding identities in this baseline."""
        return {entry.identity for entry in self.entries}


def _compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file for integrity checking."""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_baseline(path: Path) -> Baseline:
    """Load and validate a baseline file.

    Args:
        path: Path to the baseline JSON file.

    Returns:
        A validated Baseline object.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not valid JSON, has wrong schema version,
            or fails validation.
        OSError: If the file cannot be read.
    """
    if not path.exists():
        raise FileNotFoundError(f"baseline file not found: {path}")
    if not path.is_file():
        raise ValueError(f"baseline path is not a file: {path}")

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"baseline file is not valid UTF-8: {exc}") from None

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline file is not valid JSON: {exc}") from None

    return Baseline.from_dict(data)


def save_baseline(baseline: Baseline, path: Path) -> None:
    """Save a baseline to a file atomically with owner-only permissions.

    Args:
        baseline: The Baseline to save.
        path: Destination path.

    Raises:
        OSError: If the file cannot be written.
    """
    # Atomic write with 0600 permissions
    parent = path.parent if str(path.parent) else Path(".")
    if not parent.is_dir():
        raise OSError(f"output directory {parent} does not exist")
    if path.is_dir():
        raise OSError(f"output path {path} is a directory")

    import tempfile
    import os

    try:
        handle, temporary = tempfile.mkstemp(
            dir=str(parent), prefix=".secretshield-",
            suffix=".baseline.tmp"
        )
    except OSError as exc:
        raise OSError(f"cannot create temporary file in {parent}: {exc}") from None

    temporary_path = Path(temporary)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(baseline.to_json())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except OSError as exc:
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise OSError(f"cannot write baseline to {path}: {exc}") from None


class FindingClassification:
    """Classification of a finding relative to a baseline."""

    NEW = "new"
    """Finding not present in baseline."""
    BASELINED = "baselined"
    """Finding matches a baseline entry."""
    STALE = "stale"
    """Baseline entry with no matching finding in current results."""


@dataclass(frozen=True, slots=True)
class BaselineComparison:
    """Result of comparing a ScanResult against a Baseline."""

    new_findings: tuple[Finding, ...]
    """Findings not present in the baseline."""
    baselined_findings: tuple[Finding, ...]
    """Findings that match a baseline entry."""
    stale_entries: tuple[BaselineEntry, ...]
    """Baseline entries with no matching finding in current results."""

    @property
    def has_new_findings(self) -> bool:
        """Return True if there are any new (non-baselined) findings."""
        return len(self.new_findings) > 0

    @property
    def has_stale_entries(self) -> bool:
        """Return True if there are stale baseline entries."""
        return len(self.stale_entries) > 0

    def summary(self) -> dict[str, int]:
        """Return a summary of the comparison."""
        return {
            "new": len(self.new_findings),
            "baselined": len(self.baselined_findings),
            "stale": len(self.stale_entries),
        }


def compare_with_baseline(
    result: ScanResult, baseline: Baseline
) -> BaselineComparison:
    """Compare scan results against a baseline.

    Args:
        result: The scan result to compare.
        baseline: The baseline to compare against.

    Returns:
        A BaselineComparison with classified findings and stale entries.

    The comparison uses FindingIdentity which includes the value_fingerprint.
    This means a finding is only considered "baselined" if it matches the same
    rule, at the same location, with the same secret value (via fingerprint).
    A finding with a different value at the same location is classified as NEW,
    not baselined - this prevents silent suppression of changed secrets.
    """
    baseline_identities = baseline.identities()
    current_identities = {FindingIdentity.from_finding(f) for f in result.findings}

    new_findings = []
    baselined_findings = []

    for finding in result.findings:
        identity = FindingIdentity.from_finding(finding)
        if identity in baseline_identities:
            baselined_findings.append(finding)
        else:
            new_findings.append(finding)

    # Stale entries: in baseline but not in current results
    stale_identities = baseline_identities - current_identities
    stale_entries = tuple(
        entry for entry in baseline.entries if entry.identity in stale_identities
    )

    return BaselineComparison(
        new_findings=tuple(sorted(new_findings, key=lambda f: f.sort_key)),
        baselined_findings=tuple(sorted(baselined_findings, key=lambda f: f.sort_key)),
        stale_entries=tuple(sorted(stale_entries, key=lambda e: e.sort_key)),
    )


def create_baseline_from_result(result: ScanResult, tool_version: str) -> Baseline:
    """Create a new baseline from a scan result.

    All findings in the result become baselined entries.

    Args:
        result: The scan result to baseline.
        tool_version: Version of the tool creating the baseline.

    Returns:
        A new Baseline containing all findings from the result.
    """
    entries = tuple(
        sorted(
            (BaselineEntry.from_finding(f) for f in result.findings),
            key=lambda e: e.sort_key(),
        )
    )
    return Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        tool_name=BASELINE_TOOL_NAME,
        tool_version=tool_version,
        entries=entries,
    )


def update_baseline(baseline: Baseline, result: ScanResult, tool_version: str) -> Baseline:
    """Update a baseline with new findings from a scan result.

    New findings are added to the baseline. Stale entries (baseline entries
    with no matching current finding) are preserved but can be reviewed.

    Args:
        baseline: The existing baseline.
        result: The scan result with current findings.
        tool_version: Version of the tool updating the baseline.

    Returns:
        An updated Baseline with all current findings baselined.
    """
    comparison = compare_with_baseline(result, baseline)
    # New baseline contains all current findings (new + baselined)
    all_current = comparison.new_findings + comparison.baselined_findings
    entries = tuple(
        sorted(
            (BaselineEntry.from_finding(f) for f in all_current),
            key=lambda e: e.sort_key(),
        )
    )
    return Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        tool_name=BASELINE_TOOL_NAME,
        tool_version=tool_version,
        entries=entries,
    )