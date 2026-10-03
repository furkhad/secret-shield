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


def render_markdown(result: ScanResult) -> str:
    """Render a ScanResult as deterministic Markdown.

    Args:
        result: The scan result to render

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
            loc = _escape_table_cell(f"{f.location.path}:{f.location.line}:{f.location.column}")
            masked = _escape_table_cell(f.masked_value)
            details = _escape_table_cell(
                f"len={f.value_length}, conf={f.confidence}, det={f.detector}, fp={f.value_fingerprint[:8]}"
            )
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
