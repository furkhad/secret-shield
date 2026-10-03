"""Tests for Markdown report rendering."""

from __future__ import annotations

from secret_shield.models import (
    DetectorKind,
    Finding,
    Location,
    ScanResult,
    Severity,
    SourceKind,
)
from secret_shield.report import render_markdown


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
    output = render_markdown(result)
    assert "No findings detected" in output


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
    output = render_markdown(result)
    assert "Test Rule" in output


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
    out1 = render_markdown(result)
    out2 = render_markdown(result)
    assert out1 == out2


def test_escape_pipes() -> None:
    finding = make_finding(rule_name="Rule|With|Pipe")
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    output = render_markdown(result)
    assert "|" not in output or "\\|" in output


def test_escape_backticks() -> None:
    finding = make_finding(masked_value="`secret`")
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    output = render_markdown(result)
    assert output is not None
