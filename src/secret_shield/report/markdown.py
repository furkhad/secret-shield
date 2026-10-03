"""Markdown report renderer.

Produces deterministic Markdown output with strict security constraints -
no raw secrets, no raw source lines, only safe escaped content.
"""

from __future__ import annotations

from ..models import Finding, ScanError, ScanResult
from .security import markdown_escape, sanitize_text

SCHEMA_VERSION = "1.0"


def _escape_table_cell(text: str) -> str:
    """Escape text for safe inclusion in a Markdown table cell."""
    return markdown_escape(text)


def _get_unique_remediations(findings: tuple[Finding, ...]) -> list[str]:
    """Get unique remediation messages, preserving order of first appearance."""
    seen: set[str] = set()
    result: list[str] = []
    for f in findings:
        if f.remediation:
            rem = sanitize_text(f.remediation)
            if rem not in seen:
                seen.add(rem)
                result.append(rem)
    return result


def render_markdown(result: ScanResult, *, include_fingerprint: bool = True) -> str:
    """Render a ScanResult as deterministic Markdown.

    Args:
        result: The scan result to render
        include_fingerprint: Whether each finding shows its correlation digest.
            Omit it for a report bound for a public URL: an unkeyed digest of a
            low-entropy value is brute-forceable.

    Returns:
        Markdown string
    """
    findings = tuple(sorted(result.findings, key=lambda f: f.sort_key))
    errors = tuple(
        sorted(
            result.errors,
            key=lambda e: (e.path or "", e.code or "", sanitize_text(e.reason)),
        )
    )

    lines: list[str] = []
    lines.append("# Secret Shield Report")
    lines.append("")
    lines.append("## Metadata")
    lines.append("")
    lines.append(f"- Schema Version: {SCHEMA_VERSION}")
    lines.append(f"- Tool: secret-shield {result.tool_version}")
    lines.append(f"- Files Scanned: {result.files_scanned}")
    lines.append(f"- Bytes Scanned: {result.bytes_scanned}")
    lines.append(f"- Findings: {len(findings)}")
    lines.append(f"- Errors: {len(errors)}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    if len(findings) == 0:
        lines.append("No findings detected.")
    else:
        # Count by severity
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.label
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for sev in sorted(severity_counts):
            lines.append(f"- {sev}: {severity_counts[sev]}")
    lines.append("")

    if findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Rule | Severity | Location | Masked Value | Details |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            rule = _escape_table_cell(f"{f.rule_name} ({f.rule_id})")
            sev = _escape_table_cell(f.severity.label)
            # ``to_display`` rather than a hand-built path:line:column, so a
            # history finding carries its commit and a finding with no line
            # number does not print "path:None:None".
            loc = _escape_table_cell(f.location.to_display())
            masked = _escape_table_cell(f.masked_value)
            detail_parts = [
                f"len={f.value_length}",
                f"conf={f.confidence}",
                f"det={f.detector}",
            ]
            if include_fingerprint:
                detail_parts.append(f"fp={f.value_fingerprint[:8]}")
            details = _escape_table_cell(", ".join(detail_parts))
            lines.append(f"| {rule} | {sev} | {loc} | `{masked}` | {details} |")
        lines.append("")

        remediations = _get_unique_remediations(findings)
        if remediations:
            lines.append("## Remediation")
            lines.append("")
            for rem in remediations:
                lines.append(f"- {_escape_table_cell(rem)}")
            lines.append("")

    if errors:
        lines.append("## Errors")
        lines.append("")
        for e in errors:
            path_part = f" ({e.path})" if e.path else ""
            code_part = f" [{e.code}]" if e.code else ""
            lines.append(f"- {markdown_escape(sanitize_text(e.reason))}{path_part}{code_part}")
        lines.append("")

    return "\n".join(lines)
