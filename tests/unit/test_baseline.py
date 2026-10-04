"""Tests for baseline functionality."""

from __future__ import annotations

import json
from pathlib import Path

from secret_shield.baseline import (
    BASELINE_SCHEMA_VERSION,
    BASELINE_TOOL_NAME,
    Baseline,
    BaselineEntry,
    FindingIdentity,
    compare_with_baseline,
    create_baseline_from_result,
    load_baseline,
    save_baseline,
    update_baseline,
    FindingClassification,
)
from secret_shield.models import (
    DetectorKind,
    Finding,
    Location,
    ScanResult,
    Severity,
    SourceKind,
)


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


def test_finding_identity_stable() -> None:
    finding = make_finding()
    identity1 = FindingIdentity.from_finding(finding)
    identity2 = FindingIdentity.from_finding(finding)
    assert identity1 == identity2
    assert identity1.rule_id == "test-rule"
    assert identity1.path == "test.py"
    assert identity1.line == 1


def test_finding_identity_independent_of_fingerprint_mode() -> None:
    # Identity must include value_fingerprint but be stable
    finding = make_finding(value_fingerprint="abc123def456")
    identity = FindingIdentity.from_finding(finding)
    assert identity.value_fingerprint == "abc123def456"


def test_baseline_entry_no_raw_secrets() -> None:
    finding = make_finding(masked_value="REDACTED123")
    entry = BaselineEntry.from_finding(finding)
    # Entry should not contain masked_value or raw value
    d = entry.to_dict()
    assert "masked_value" not in str(d)
    assert "REDACTED123" not in json.dumps(d)


def test_create_baseline_from_result() -> None:
    finding = make_finding()
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    baseline = create_baseline_from_result(result, "0.1.0")
    assert baseline.schema_version == BASELINE_SCHEMA_VERSION
    assert baseline.tool_name == BASELINE_TOOL_NAME
    assert len(baseline.entries) == 1


def test_compare_with_baseline_new_finding() -> None:
    finding = make_finding(value_fingerprint="abc123def456")
    baseline_result = ScanResult(
        findings=(),
        errors=(),
        files_scanned=0,
        bytes_scanned=0,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    baseline = create_baseline_from_result(baseline_result, "0.1.0")
    current = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    comparison = compare_with_baseline(current, baseline)
    assert len(comparison.new_findings) == 1
    assert len(comparison.baselined_findings) == 0
    assert comparison.has_new_findings


def test_compare_with_baseline_baselined_finding() -> None:
    finding = make_finding(value_fingerprint="abc123def456")
    baseline_result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    baseline = create_baseline_from_result(baseline_result, "0.1.0")
    comparison = compare_with_baseline(baseline_result, baseline)
    assert len(comparison.new_findings) == 0
    assert len(comparison.baselined_findings) == 1


def test_compare_with_baseline_stale_entry() -> None:
    finding1 = make_finding(value_fingerprint="abc123def456", location=Location(path="test1.py", line=1, column=1, source_kind=SourceKind.FILE))
    finding2 = make_finding(value_fingerprint="def456abc123", location=Location(path="test2.py", line=1, column=1, source_kind=SourceKind.FILE))
    baseline_result = ScanResult(
        findings=(finding1, finding2),
        errors=(),
        files_scanned=2,
        bytes_scanned=20,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    baseline = create_baseline_from_result(baseline_result, "0.1.0")
    current = ScanResult(
        findings=(finding1,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    comparison = compare_with_baseline(current, baseline)
    assert len(comparison.stale_entries) == 1


def test_baseline_matching_not_silently_suppress_changed() -> None:
    finding_orig = make_finding(value_fingerprint="abc123def456", location=Location(path="test.py", line=1, column=1, source_kind=SourceKind.FILE))
    baseline_result = ScanResult(
        findings=(finding_orig,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    baseline = create_baseline_from_result(baseline_result, "0.1.0")
    # Different value at same location
    finding_changed = make_finding(value_fingerprint="def456abc123", location=Location(path="test.py", line=1, column=1, source_kind=SourceKind.FILE))
    current = ScanResult(
        findings=(finding_changed,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    comparison = compare_with_baseline(current, baseline)
    # Changed finding is NOT baselined - it's a new finding
    assert len(comparison.new_findings) == 1
    assert len(comparison.baselined_findings) == 0
