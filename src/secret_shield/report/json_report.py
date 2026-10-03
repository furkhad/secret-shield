"""JSON report renderer.

Produces deterministic JSON output from ScanResult with strict security
constraints - no raw secrets, no raw source lines, only masked values.
"""

from __future__ import annotations

import json
from typing import Any, Final

from ..models import Finding, ScanError, ScanResult
from .security import safe_json_serialize, sanitize_text

SCHEMA_VERSION: Final[str] = "1.0"


def _finding_to_dict(finding: Finding, *, include_fingerprint: bool) -> dict[str, Any]:
    """Convert a Finding to a dict for JSON serialization."""
    data: dict[str, Any] = {
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "category": finding.category.value if hasattr(finding.category, "value") else str(finding.category),
        "severity": finding.severity.label,
        "confidence": finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
        "detector": finding.detector.label if hasattr(finding.detector, "label") else (finding.detector.value if hasattr(finding.detector, "value") else str(finding.detector)),
        "location": {
            "path": finding.location.path,
            "line": finding.location.line,
            "column": finding.location.column,
        },
        "masked_value": finding.masked_value,
        "value_length": finding.value_length,
        "entropy": finding.entropy,
    }

    if include_fingerprint:
        data["fingerprint"] = finding.value_fingerprint

    if finding.matched_keywords:
        data["matched_keywords"] = tuple(sorted(finding.matched_keywords))

    if getattr(finding, "evidence", None):
        data["evidence"] = finding.evidence

    if finding.remediation:
        data["remediation"] = sanitize_text(finding.remediation)

    return data


def _error_to_dict(error: ScanError) -> dict[str, Any]:
    """Convert a ScanError to a dict for JSON serialization."""
    data: dict[str, Any] = {
        "reason": sanitize_text(error.reason),
    }
    if error.path:
        data["path"] = error.path
    if error.code:
        data["code"] = error.code
    return data


def render_json(result: ScanResult, *, include_fingerprint: bool = True) -> str:
    """Render a ScanResult as deterministic JSON.

    Args:
        result: The scan result to render
        include_fingerprint: Whether each finding carries its ``fingerprint``
            correlation digest. Omit it for a report bound for a public URL: an
            unkeyed digest of a low-entropy value is brute-forceable.

    Returns:
        JSON string with deterministic key ordering
    """
    # Build output with deterministic ordering
    findings = tuple(sorted(result.findings, key=lambda f: f.sort_key))
    errors = tuple(
        sorted(
            result.errors,
            key=lambda e: (e.path or "", e.code or "", sanitize_text(e.reason)),
        )
    )

    output: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": "secret-shield",
            "version": result.tool_version,
        },
        "summary": {
            "files_scanned": result.files_scanned,
            "bytes_scanned": result.bytes_scanned,
            "findings_count": len(findings),
            "errors_count": len(errors),
        },
        "findings": [_finding_to_dict(f, include_fingerprint=include_fingerprint) for f in findings],
        "errors": [_error_to_dict(e) for e in errors],
    }

    # Use ensure_ascii to prevent control chars; sort_keys for determinism
    return json.dumps(
        safe_json_serialize(output),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
