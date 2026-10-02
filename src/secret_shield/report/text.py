"""Human-readable text report.

The report is the last place a secret could escape, so it is built to be
boring:

* Only redacted values are rendered. The reporter never has access to raw
  material, because :class:`~secret_shield.models.Finding` does not hold any.
* Source lines are never quoted. The surrounding line almost always contains the
  secret next to the match, so showing it would undo the masking.
* Every piece of scanned-derived text -- paths included -- is stripped of
  control characters before printing. A repository can contain a file named
  ``\\x1b[31mevil\\x1b[0m``; without this it could repaint the terminal of
  whoever reads the report.
* No colours and no timestamps. Output is plain ASCII-safe text that is
  byte-stable between runs, so two scans of the same tree can be diffed.
* Every rendered line fits in :data:`LINE_WIDTH`, so a hostile filename cannot
  push a finding's fields out of alignment.

Wall-clock duration is deliberately **not** rendered. It varies between runs,
and including it would make every report differ for no useful reason. The
value stays available on the result for callers that want it. For the same
reason, remediation advice is printed once per distinct rule in its own
section rather than repeated under every finding.
"""

from __future__ import annotations

import textwrap
from typing import Final

from ..masking import strip_control_characters
from ..models import Finding, ScanError, ScanResult

__all__ = ["render_text", "LINE_WIDTH"]

LINE_WIDTH: Final[int] = 78
"""Target width for wrapped text."""

_INDENT: Final[str] = "  "
_FIELD_INDENT: Final[str] = "     "


def render_text(result: ScanResult) -> str:
    """Render a scan result as human-readable text.

    Args:
        result: The scan to describe.

    Returns:
        A deterministic report string. The same result always renders to the
        same text, and the raw value of any detected secret appears nowhere in
        it.
    """

    if not isinstance(result, ScanResult):
        raise TypeError(f"render_text() expects a ScanResult, got {type(result).__name__}")

    sections: list[str] = [
        _render_header(result),
        _render_findings(result),
        _render_advice(result),
        _render_errors(result),
        _render_summary(result),
        _render_footer(),
    ]
    return "\n".join(section for section in sections if section) + "\n"


def _render_header(result: ScanResult) -> str:
    version = result.tool_version or "unknown"
    lines = [f"SecretShield {version} - scan report", ""]
    if result.errors:
        lines.append("NOTE: the scan could not read every requested input.")
        lines.append("")
    return "\n".join(lines)


def _render_findings(result: ScanResult) -> str:
    findings = result.sorted_findings()
    if not findings:
        return ""

    lines = [
        f"FINDINGS ({len(findings)})",
        "",
    ]
    for index, finding in enumerate(findings, start=1):
        lines.append(_render_finding(index, finding))
        lines.append("")
    return "\n".join(lines)


def _render_finding(index: int, finding: Finding) -> str:
    severity = finding.severity.label.upper()
    location = finding.location
    headline = (
        f"{_INDENT}{index}. [{severity}] {finding.rule_id} "
        f"({finding.category.value})"
    )
    entropy = (
        f"{finding.entropy:.2f} bits/char"
        if finding.entropy is not None
        else "not measured"
    )

    return "\n".join(
        [
            headline,
            _wrap(location.to_display(), prefix=f"{_FIELD_INDENT}at         : "),
            f"{_FIELD_INDENT}masked     : {finding.masked_value}",
            f"{_FIELD_INDENT}length     : {finding.value_length} characters",
            f"{_FIELD_INDENT}fingerprint: {finding.value_fingerprint}",
            f"{_FIELD_INDENT}entropy    : {entropy}",
            f"{_FIELD_INDENT}confidence : {finding.confidence.label} "
            f"(detected by {finding.detector.value})",
            _wrap(_ASSESSMENT, prefix=f"{_FIELD_INDENT}assessment : "),
        ]
    )


def _render_advice(result: ScanResult) -> str:
    """Render the remediation text once per distinct rule.

    Five findings from one rule share one piece of advice. Repeating it five
    times makes a report of a clean repository unreadable, so the advice moves
    to its own section keyed by rule id, in first-appearance order.
    """

    advice: list[tuple[str, str]] = []
    counts: dict[str, int] = {}
    for finding in result.sorted_findings():
        if not finding.remediation.strip():
            continue
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        if all(finding.rule_id != rule for rule, _ in advice):
            advice.append((finding.rule_id, finding.remediation))

    if not advice:
        return ""

    lines = ["HOW TO RESPOND", ""]
    for rule_id, remediation in advice:
        count = counts[rule_id]
        label = f"{rule_id} ({count} finding{'s' if count != 1 else ''})"
        lines.append(_wrap(label, prefix=f"{_INDENT}- "))
        lines.append(_wrap(remediation, prefix=f"{_INDENT}  "))
        lines.append("")
    return "\n".join(lines)


def _render_errors(result: ScanResult) -> str:
    if not result.errors:
        return ""
    lines = ["ERRORS", ""]
    for error in result.errors:
        lines.append(f"{_INDENT}- {_render_error(error)}")
    lines.append("")
    return "\n".join(lines)


def _render_error(error: ScanError) -> str:
    location = _safe(error.path) if error.path else "<unknown path>"
    code = f"[{error.code}] " if error.code else ""
    return f"{code}{_safe(error.reason)} ({location})"


def _render_summary(result: ScanResult) -> str:
    summary = result.summary()
    lines = [
        "SUMMARY",
        "",
        f"{_INDENT}total findings   : {summary['total_findings']}",
        f"{_INDENT}distinct secrets : {summary['distinct_secrets']}",
        f"{_INDENT}by severity      : {_format_counts(summary['by_severity'])}",
        f"{_INDENT}by confidence    : {_format_counts(summary['by_confidence'])}",
        f"{_INDENT}files scanned    : {result.files_scanned}",
        f"{_INDENT}bytes scanned    : {result.bytes_scanned}",
        f"{_INDENT}errors           : {summary['error_count']}",
    ]
    return "\n".join(lines)


def _render_footer() -> str:
    return (
        f"\nFindings are candidates, not confirmed secrets. Values are masked;\n"
        f"nothing above can be used to reach a live system without your own copy\n"
        f"of the original value."
    )


def _format_counts(counts: dict[str, int]) -> str:
    """Format a count mapping, dropping zero-valued entries."""

    present = [f"{name} {count}" for name, count in counts.items() if count]
    return ", ".join(present) if present else "none"


def _safe(text: str) -> str:
    """Make untrusted text safe to print.

    Control characters are removed, then newlines are folded to single spaces so
    that one finding can never occupy several lines of the report.
    """

    return " ".join(strip_control_characters(text).split())


def _wrap(text: str, *, prefix: str) -> str:
    """Return sanitized text wrapped to :data:`LINE_WIDTH`, or ``""`` if empty.

    ``textwrap`` is deterministic, so wrapping cannot make the report vary
    between runs. Hyphenated words are kept whole so that a rule id or a
    path segment is never split mid-token; a value with no spaces at all, such
    as a very long path, is broken at the width limit instead.

    Every field in a finding goes through here, so no line of a report can
    exceed :data:`LINE_WIDTH` regardless of what an attacker put in a filename.
    """

    cleaned = _safe(text)
    if not cleaned:
        return ""
    return textwrap.fill(
        cleaned,
        width=LINE_WIDTH,
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
        break_on_hyphens=False,
    )


_ASSESSMENT: Final[str] = (
    "high character variety, not a confirmed credential; review before acting"
)