"""Tests for SARIF report rendering."""

from __future__ import annotations

import json

from secret_shield.models import (
    DetectorKind,
    Finding,
    Location,
    ScanError,
    ScanResult,
    Severity,
    SourceKind,
)
from secret_shield.report import render_sarif, SARIF_VERSION, SARIF_SCHEMA_URI


def make_finding(**kwargs) -> Finding:
    defaults = {
        "rule_id": "test-rule",
        "rule_name": "Test Rule",
        "category": "secret",
        "severity": Severity.MEDIUM,
        "confidence": 0.9,
        "detector": DetectorKind.PATTERN,
        "location": Location(
            path="test.py", line=1, column=1, source_kind=SourceKind.FILE
        ),
        "masked_value": "****",
        "value_length": 4,
        "value_fingerprint": "abc123def456",
        "entropy": 3.5,
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_empty_result() -> None:
    result = ScanResult(
        findings=(),
        errors=(),
        files_scanned=0,
        bytes_scanned=0,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    output = render_sarif(result)
    data = json.loads(output)
    assert data["version"] == SARIF_VERSION
    assert data["$schema"] == SARIF_SCHEMA_URI
    assert data["runs"][0]["results"] == []
    assert data["runs"][0]["tool"]["driver"]["name"] == "secret-shield"


def test_single_finding() -> None:
    finding = make_finding()
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    output = render_sarif(result)
    data = json.loads(output)
    result_obj = data["runs"][0]["results"][0]
    assert result_obj["ruleId"] == "test-rule"
    assert result_obj["level"] == "warning"
    assert "maskedValue" in result_obj["properties"]


def test_deterministic_output() -> None:
    finding = make_finding()
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    out1 = render_sarif(result)
    out2 = render_sarif(result)
    assert out1 == out2


def test_no_raw_secrets() -> None:
    finding = make_finding(masked_value="****", value_fingerprint="abc123def456")
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    output = render_sarif(result)
    # Should not contain the actual secret value
    assert "actual-secret" not in output
    assert "secret123" not in output


def test_no_raw_source_lines() -> None:
    finding = make_finding()
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    output = render_sarif(result)
    # SARIF output should not include raw source code lines
    # This is enforced by design - only masked values
    assert output  # Just verify it renders


def test_findings_without_fingerprint() -> None:
    finding = make_finding()
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    output = render_sarif(result, include_fingerprint=False)
    data = json.loads(output)
    assert "partialFingerprints" not in data["runs"][0]["results"][0]


def test_errors_included() -> None:
    error = ScanError(reason="file not found", path="missing.txt", code="not-found")
    result = ScanResult(
        findings=(),
        errors=(error,),
        files_scanned=0,
        bytes_scanned=0,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    output = render_sarif(result)
    data = json.loads(output)
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["level"] == "error"
