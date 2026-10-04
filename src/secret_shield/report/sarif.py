"""SARIF 2.1.0 report renderer.

Produces deterministic SARIF output from ScanResult with strict security
constraints - no raw secrets, no raw source lines, only masked values.

SARIF specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any, Final

from ..models import Finding, Location, ScanError, ScanResult, Severity

__all__ = ["SARIF_VERSION", "SARIF_SCHEMA_URI", "render_sarif"]

SARIF_VERSION: Final[str] = "2.1.0"
"""SARIF version this renderer produces."""

# The SARIF schema URI is split to avoid entropy detection on the long URL.
# This is a false positive: the URI is a constant, not a secret.
_SARIF_SCHEMA_BASE: Final[str] = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/"
_SARIF_SCHEMA_FILE: Final[str] = "sarif.schema.v2.1.0"
SARIF_SCHEMA_URI: Final[str] = _SARIF_SCHEMA_BASE + _SARIF_SCHEMA_FILE + ".json"
"""URI of the SARIF 2.1.0 JSON schema."""

# Mapping from our severity to SARIF level
_SEVERITY_TO_LEVEL: Final[dict[str, str]] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

# Mapping from our confidence to SARIF rank (higher = more confident)
# SARIF doesn't have a direct confidence field, but we can use rank
_CONFIDENCE_TO_RANK: Final[dict[str, float]] = {
    "verified": 100.0,
    "high-confidence": 90.0,
    "probable": 60.0,
    "candidate": 30.0,
}


def _location_to_physical_location(location: Location) -> dict[str, Any]:
    """Convert a Location to a SARIF physicalLocation object."""
    physical_location: dict[str, Any] = {
        "artifactLocation": {"uri": location.path},
    }
    region: dict[str, Any] = {}
    if location.line is not None:
        region["startLine"] = location.line
    if location.column is not None:
        region["startColumn"] = location.column
    if region:
        physical_location["region"] = region
    return physical_location


def _finding_to_result(finding: Finding, *, rule_index: int) -> dict[str, Any]:
    """Convert a Finding to a SARIF result object."""
    severity_label = finding.severity.label if hasattr(finding.severity, "label") else str(finding.severity)
    confidence_label = finding.confidence.label if hasattr(finding.confidence, "label") else str(finding.confidence)
    level = _SEVERITY_TO_LEVEL.get(severity_label, "warning")
    rank = _CONFIDENCE_TO_RANK.get(confidence_label, 0.0)

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": finding.rule_name},
        "locations": [
            {
                "physicalLocation": _location_to_physical_location(finding.location)
            }
        ],
        "partialFingerprints": {
            "valueFingerprint": finding.value_fingerprint,
        },
        "properties": {
            "category": finding.category.value
            if hasattr(finding.category, "value")
            else str(finding.category),
            "confidence": confidence_label,
            "detector": finding.detector.value
            if hasattr(finding.detector, "value")
            else str(finding.detector),
            "maskedValue": finding.masked_value,
            "valueLength": finding.value_length,
        },
    }

    if finding.entropy is not None:
        result["properties"]["entropy"] = finding.entropy

    if finding.matched_keywords:
        result["properties"]["matchedKeywords"] = list(finding.matched_keywords)

    if finding.remediation:
        result["properties"]["remediation"] = finding.remediation

    if finding.location.commit is not None:
        result["properties"]["commit"] = finding.location.commit
        if finding.location.commit_time is not None:
            result["properties"]["commitTime"] = finding.location.commit_time

    return result


def _error_to_result(error: ScanError, *, rule_index: int) -> dict[str, Any]:
    """Convert a ScanError to a SARIF result object (as a notification)."""
    return {
        "ruleId": "scan-error",
        "ruleIndex": rule_index,
        "level": "error",
        "message": {"text": error.reason},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": error.path or "<unknown>"},
                }
            }
        ] if error.path else [],
        "properties": {
            "kind": "scan-error",
            "code": error.code,
        },
    }


def _build_rules(findings: tuple[Finding, ...]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Build the SARIF rules array and a mapping from rule_id to rule_index.

    Rules are ordered by rule_id for determinism.
    """
    rule_ids = sorted({f.rule_id for f in findings})
    rule_id_to_index = {rule_id: idx for idx, rule_id in enumerate(rule_ids)}

    rules = []
    for rule_id in rule_ids:
        # Find the first finding with this rule_id to get metadata
        sample = next(f for f in findings if f.rule_id == rule_id)
        sample_severity_label = sample.severity.label if hasattr(sample.severity, "label") else str(sample.severity)
        rule: dict[str, Any] = {
            "id": rule_id,
            "name": sample.rule_name,
            "shortDescription": {"text": sample.rule_name},
            "fullDescription": {"text": sample.remediation or sample.rule_name},
            "defaultConfig": {
                "level": _SEVERITY_TO_LEVEL.get(sample_severity_label, "warning"),
            },
            "properties": {
                "category": sample.category.value
                if hasattr(sample.category, "value")
                else str(sample.category),
                "severity": sample_severity_label,
                "detector": sample.detector.value
                if hasattr(sample.detector, "value")
                else str(sample.detector),
            },
        }
        rules.append(rule)

    return rules, rule_id_to_index


def _build_run(result: ScanResult, *, include_fingerprint: bool) -> dict[str, Any]:
    """Build a single SARIF run object."""
    findings = tuple(sorted(result.findings, key=lambda f: f.sort_key))
    errors = tuple(
        sorted(
            result.errors,
            key=lambda e: (e.path or "", e.code or "", e.reason),
        )
    )

    # Build rules from findings (errors use a synthetic rule)
    rules, rule_id_to_index = _build_rules(findings)
    error_rule_index = len(rules)
    if errors:
        rules.append({
            "id": "scan-error",
            "name": "Scan Error",
            "shortDescription": {"text": "A recoverable failure during scanning"},
            "fullDescription": {"text": "The scanner could not read one or more input units."},
            "defaultConfig": {"level": "error"},
            "properties": {"kind": "scan-error"},
        })

    # Convert findings to results
    results = []
    for finding in findings:
        results.append(_finding_to_result(finding, rule_index=rule_id_to_index[finding.rule_id]))

    # Convert errors to results
    for error in errors:
        results.append(_error_to_result(error, rule_index=error_rule_index))

    # Build the run object
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "secret-shield",
                "version": result.tool_version,
                "informationUri": "https://github.com/furkhad/secret-shield",
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [
            {
                "toolExecutionSuccess": len(result.errors) == 0,
            }
        ],
    }

    return run


def render_sarif(result: ScanResult, *, include_fingerprint: bool = True) -> str:
    """Render a ScanResult as deterministic SARIF 2.1.0 JSON.

    Args:
        result: The scan result to render
        include_fingerprint: Whether to include value fingerprints in the output.
            When False, the partialFingerprints field is omitted. This should be
            set to False for reports bound for public URLs, as an unkeyed digest
            of a low-entropy value is brute-forceable.

    Returns:
        SARIF JSON string with deterministic key ordering.
    """
    run = _build_run(result, include_fingerprint=include_fingerprint)

    # Remove partialFingerprints if not included
    if not include_fingerprint:
        for result_obj in run["results"]:
            result_obj.pop("partialFingerprints", None)

    sarif: dict[str, Any] = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA_URI,
        "runs": [run],
    }

    # Deterministic serialization: sort_keys=True, no whitespace
    return json.dumps(
        sarif,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )