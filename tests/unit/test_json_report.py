"""Tests for JSON report rendering."""

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
from secret_shield.report import render_json


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
    output = render_json(result)
    data = json.loads(output)
    assert data["schema_version"] == "1.0"
    assert data["summary"]["findings_count"] == 0
    assert data["summary"]["errors_count"] == 0
    assert data["findings"] == []
    assert data["errors"] == []


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
    output = render_json(result)
    data = json.loads(output)
    assert data["findings"][0]["rule_id"] == "test-rule"
    assert data["findings"][0]["severity"] == "medium"
    assert "masked_value" in data["findings"][0]


def test_deterministic_key_order() -> None:
    finding = make_finding()
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    out1 = render_json(result)
    out2 = render_json(result)
    assert out1 == out2
    data = json.loads(out1)
    assert list(data.keys()) == sorted(data.keys())


def test_multiple_findings_ordered() -> None:
    f1 = make_finding(
        rule_id="b",
        location=Location(path="b.py", line=2, column=1, source_kind=SourceKind.FILE),
    )
    f2 = make_finding(
        rule_id="a",
        location=Location(path="a.py", line=1, column=1, source_kind=SourceKind.FILE),
    )
    result = ScanResult(
        findings=(f1, f2),
        errors=(),
        files_scanned=2,
        bytes_scanned=20,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    out = render_json(result)
    data = json.loads(out)
    assert data["findings"][0]["rule_id"] == "a"
    assert data["findings"][1]["rule_id"] == "b"


def test_errors_serialized() -> None:
    error = ScanError(reason="file not found", path="missing.txt", code="not-found")
    result = ScanResult(
        findings=(),
        errors=(error,),
        files_scanned=0,
        bytes_scanned=0,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    out = render_json(result)
    data = json.loads(out)
    assert data["errors"][0]["reason"] == "file not found"
    assert data["errors"][0]["path"] == "missing.txt"


def test_no_raw_secrets_in_output() -> None:
    finding = make_finding(masked_value="****", rule_id="aws")
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=100,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    out = render_json(result)
    assert "****" in out
