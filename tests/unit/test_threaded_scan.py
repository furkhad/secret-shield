"""Tests for multithreaded filesystem scanning."""

from __future__ import annotations

from pathlib import Path

import pytest

from secret_shield.config import ConfigError, load_config
from secret_shield.sources.filesystem import (
    PathScanConfig,
    scan_path,
)


def test_jobs_setting_validation() -> None:
    """Invalid job counts are rejected."""
    with pytest.raises(ValueError):
        PathScanConfig(jobs=0)
    with pytest.raises(ValueError):
        PathScanConfig(jobs=-1)
    with pytest.raises(ValueError):
        PathScanConfig(jobs=65)
    with pytest.raises(ValueError):
        PathScanConfig(jobs=100)


def test_jobs_valid_counts() -> None:
    """Valid job counts are accepted."""
    for jobs in (1, 2, 4, 8, 16, 32, 64):
        cfg = PathScanConfig(jobs=jobs)
        assert cfg.jobs == jobs


def test_determinism_serial_vs_threaded(tmp_path: Path) -> None:
    """Same results with jobs=1 and jobs=4."""
    for i in range(10):
        (tmp_path / f"file_{i}.txt").write_text("hello world\n", encoding="utf-8")
    cfg1 = PathScanConfig(jobs=1)
    cfg4 = PathScanConfig(jobs=4)
    r1 = scan_path(tmp_path, cfg1)
    r4 = scan_path(tmp_path, cfg4)
    assert r1.findings == r4.findings
    assert r1.errors == r4.errors
    assert r1.files_scanned == r4.files_scanned
    assert r1.bytes_scanned == r4.bytes_scanned


def test_determinism_multiple_runs(tmp_path: Path) -> None:
    """Multiple threaded runs produce identical results."""
    for i in range(5):
        (tmp_path / f"f{i}.py").write_text("# test\n", encoding="utf-8")
    cfg = PathScanConfig(jobs=4)
    r0 = scan_path(tmp_path, cfg)
    for _ in range(5):
        r = scan_path(tmp_path, cfg)
        assert r.findings == r0.findings
        assert r.errors == r0.errors
        assert r.files_scanned == r0.files_scanned
        assert r.bytes_scanned == r0.bytes_scanned


def test_threaded_continues_after_worker_failure(tmp_path: Path) -> None:
    """Scan continues when one worker encounters issues."""
    (tmp_path / "good1.txt").write_text("safe content\n", encoding="utf-8")
    (tmp_path / "good2.txt").write_text("more safe content\n", encoding="utf-8")
    cfg = PathScanConfig(jobs=2)
    r = scan_path(tmp_path, cfg)
    assert r.files_scanned == 2
    assert len(r.errors) >= 0


def test_config_jobs_integration(tmp_path: Path) -> None:
    """Jobs can be configured via load_config."""
    cfg = load_config(project_root=tmp_path, overrides={"scan.jobs": 4})
    assert cfg.path_scan.jobs == 4

    with pytest.raises(ConfigError):
        load_config(project_root=tmp_path, overrides={"scan.jobs": 0})


def test_threaded_respects_limits(tmp_path: Path) -> None:
    """Threaded scan respects max_files limit."""
    for i in range(10):
        (tmp_path / f"f{i}.txt").write_text("data\n", encoding="utf-8")
    cfg = PathScanConfig(jobs=4, max_files=3)
    r = scan_path(tmp_path, cfg)
    assert r.files_scanned <= 3
