"""Regression tests for the independent CI credential guard.

The "Credential-Shaped Text Guard" job in ``.github/workflows/ci.yml`` failed
on run 37896104466 because its inline snippet called ``scan_path`` with its
arguments swapped, raising ``TypeError: config must be a PathScanConfig, got
PosixPath`` before scanning a single file. The guard now lives in
:file:`scripts/ci_credential_guard.py`, and this module pins its contract with
synthetic trees:

* a tree with nothing but noise exits 0;
* a ``tests/`` file holding a real vendor pattern is synthetic test data and
  does not fail the guard;
* the same value outside ``tests/`` fails the guard with exit 1 and a
  diagnostic naming the path and rule (never the value);
* the process-level exit code reaches the parent (how CI sees it).

Every value planted here is fabricated (``sk_test_`` + a repeated synthetic
block), never a real credential.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import vendor_fixtures

_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
_SRC_DIR = _SCRIPTS_DIR.parent / "src"
_GUARD_SCRIPT = _SCRIPTS_DIR / "ci_credential_guard.py"

#: A fabricated Stripe secret-test key: real vendor prefix, synthetic body.
_SYNTHETIC_STRIPE = vendor_fixtures.STRIPE_SECRET_TEST

#: A high-entropy alphanumeric blob that trips the entropy rule (PROBABLE),
#: which the guard explicitly allows.
_HIGH_ENTROPY_TOKEN = "A7KX9M2PQ5RD8V3C6N1B4W0E9YF2G6H8J3L5Z1T7"


@pytest.fixture(scope="module")
def guard() -> Any:
    """Load ``scripts/ci_credential_guard.py`` without making ``scripts/`` a package."""

    spec = importlib.util.spec_from_file_location("ci_credential_guard", _GUARD_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(root: Path, relative: str, content: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def clean_env() -> dict[str, str]:
    """Environment without any ``SECRETSHIELD_*`` variable and with ``src/`` importable."""

    base = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("SECRETSHIELD_")
    }
    base["PYTHONPATH"] = str(_SRC_DIR)
    return base


def test_clean_tree_exits_zero(
    guard: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path, "README.md", "# example\n\nplain prose, no credential shapes\n")
    assert guard.main([str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert "OK:" in captured.out


def test_probable_entropy_noise_is_allowed(
    guard: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A PROBABLE entropy finding outside tests/ is expected noise; only
    # vendor-rule matches at HIGH_CONFIDENCE+ fail the guard.
    write(tmp_path, "example.txt", f"token = {_HIGH_ENTROPY_TOKEN}\n")
    assert guard.main([str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert "OK:" in captured.out


def test_finding_under_tests_is_exempt(
    guard: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Synthetic fixtures live under tests/ and must never fail the guard.
    write(tmp_path, "tests/fixture.txt", _SYNTHETIC_STRIPE + "\n")
    assert guard.main([str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert "OK:" in captured.out


def test_real_pattern_outside_tests_fails(
    guard: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path, "config.json", f'{{"key": "{_SYNTHETIC_STRIPE}"}}\n')
    assert guard.main([str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "FAIL:" in captured.err
    assert "config.json" in captured.err
    assert "stripe-test-key" in captured.err
    # The diagnostic names the file and rule but never prints the value.
    assert _SYNTHETIC_STRIPE not in captured.out
    assert _SYNTHETIC_STRIPE not in captured.err
    assert _HIGH_ENTROPY_TOKEN not in captured.out
    assert _HIGH_ENTROPY_TOKEN not in captured.err


def test_exit_code_reaches_the_parent(tmp_path: Path) -> None:
    # CI runs `python scripts/ci_credential_guard.py .` as a subprocess; the
    # exit code is the contract, so run it exactly like the workflow does.
    write(tmp_path, "tests/fixture.txt", _SYNTHETIC_STRIPE + "\n")  # exempt
    write(tmp_path, "secrets.env", f"STRIPE_KEY={_SYNTHETIC_STRIPE}\n")  # not exempt

    failed = subprocess.run(
        [sys.executable, str(_GUARD_SCRIPT), str(tmp_path)],
        env=clean_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 1
    assert "FAIL:" in failed.stderr
    assert _SYNTHETIC_STRIPE not in failed.stdout
    assert _SYNTHETIC_STRIPE not in failed.stderr

    (tmp_path / "secrets.env").unlink()
    clean = subprocess.run(
        [sys.executable, str(_GUARD_SCRIPT), str(tmp_path)],
        env=clean_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert clean.returncode == 0
    assert "OK:" in clean.stdout
