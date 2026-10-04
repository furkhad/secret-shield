"""Integration tests for SARIF and baseline functionality."""

from __future__ import annotations

import json
from pathlib import Path

from secret_shield.models import (
    DetectorKind,
    Finding,
    Location,
    ScanResult,
    Severity,
    SourceKind,
)
from secret_shield.report import render_sarif
from secret_shield.baseline import (
    create_baseline_from_result,
    compare_with_baseline,
    load_baseline,
    save_baseline,
)
from secret_shield import baseline as baseline_mod


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


def test_sarif_deterministic_across_runs() -> None:
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
    out3 = render_sarif(result)
    assert out1 == out2
    assert out2 == out3


def test_sarif_contains_no_raw_secrets() -> None:
    finding = make_finding(masked_value="****")
    result = ScanResult(
        findings=(finding,),
        errors=(),
        files_scanned=1,
        bytes_scanned=10,
        duration_seconds=0.1,
        tool_version="0.1.0",
    )
    output = render_sarif(result)
    # Ensure no actual secret content leaks
    assert "test-secret" not in output
    assert "AKIA" not in output
    data = json.loads(output)
    # SARIF structure is valid
    assert "runs" in data
    assert data["version"] == "2.1.0"


def test_baseline_load_save_roundtrip(tmp_path: Path) -> None:
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
    out_file = tmp_path / "baseline.json"
    save_baseline(baseline, out_file)
    loaded = load_baseline(out_file)
    assert loaded.schema_version == baseline.schema_version
    assert len(loaded.entries) == len(baseline.entries)


def test_baseline_invalid_schema_version(tmp_path: Path) -> None:
    bad = {
        "schema_version": "999.0",
        "tool": {"name": baseline_mod.BASELINE_TOOL_NAME, "version": "0.1.0"},
        "entries": [],
    }
    out_file = tmp_path / "bad.json"
    out_file.write_text(json.dumps(bad))
    try:
        load_baseline(out_file)
        assert False, "should have raised"
    except ValueError:
        pass


def test_baseline_invalid_file(tmp_path: Path) -> None:
    out_file = tmp_path / "bad.json"
    out_file.write_text("{not json")
    try:
        load_baseline(out_file)
        assert False, "should have raised"
    except ValueError:
        pass
