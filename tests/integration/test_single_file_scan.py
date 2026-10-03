"""End-to-end test of the Stage 1 flow.

Scans a real file on disk with the public API and renders the result, then
checks the two properties the whole design exists to guarantee: the report is
byte-identical across runs, and the raw value never appears in it.

Every value in this file is synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import secret_shield
from secret_shield import (
    Confidence,
    DetectorKind,
    SecretCategory,
    Severity,
    render_text,
    scan_file,
)

# Synthetic, structurally realistic values. None of these is a credential and
# none can authenticate against anything.
SYNTHETIC_BASE64 = "x8Kq2mNvR4pLzW7yB1cF3dH5jS6tG9uA0"
SYNTHETIC_HEX = "a3f5c9e17b2d4806be35f1c8a07d29e4"
SYNTHETIC_OTHER = "Q7wZ2mNvR4pLzX9yB1cF3dH8jS0tG5uB2"
SYNTHETIC_DSN = "postgres://appuser:syntheticpw@db.internal:5432/production"

SAMPLE = f"""\
# Application settings -- synthetic sample for testing
DEBUG = False
DATABASE_URL = "{SYNTHETIC_DSN}"
SIGNING_TOKEN = "{SYNTHETIC_BASE64}"
CHECKSUM = "{SYNTHETIC_HEX}"
MIRROR_TOKEN = "{SYNTHETIC_OTHER}"
SESSION_SECRET = "${{SESSION_SECRET_FROM_VAULT}}"
PLACEHOLDER = "YOUR_KEY_HERE_REPLACE_ME_1234"
DESCRIPTION = "this configuration file contains several example values"
SHORT = "abc"
REPEATED = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"""


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    target = tmp_path / "settings.py"
    target.write_text(SAMPLE, encoding="utf-8")
    return target


# --------------------------------------------------------------------------
# the scan itself
# --------------------------------------------------------------------------


def test_public_api_scan_and_render(sample_file: Path) -> None:
    result = scan_file(sample_file)

    assert result.errors == ()
    assert result.files_scanned == 1
    assert result.bytes_scanned == len(SAMPLE.encode("utf-8"))
    assert len(result.findings) == 4

    text = render_text(result)
    assert "FINDINGS (4)" in text
    assert "SUMMARY" in text


def test_findings_are_where_they_should_be(sample_file: Path) -> None:
    result = scan_file(sample_file)

    # Columns are the first character of the value, i.e. just past the quote:
    #   DATABASE_URL = "  -> 12 + 1 + 1 + 1 + 1 + 1 = 17
    #   SIGNING_TOKEN = " -> 13 + 5 = 18
    #   CHECKSUM = "      ->  8 + 5 = 13
    #   MIRROR_TOKEN = " -> 12 + 5 = 17
    assert [(f.location.line, f.location.column) for f in result.findings] == [
        (3, 17),
        (4, 18),
        (5, 13),
        (6, 17),
    ]


def test_every_finding_is_hedged(sample_file: Path) -> None:
    """The claim each finding makes is bounded, in every field."""

    for finding in scan_file(sample_file).findings:
        assert finding.severity is Severity.MEDIUM
        assert finding.confidence is Confidence.PROBABLE
        assert finding.detector is DetectorKind.ENTROPY
        assert finding.category is SecretCategory.UNKNOWN
        assert finding.entropy is not None and finding.entropy >= 3.5
        assert finding.rule_id == "high-entropy-string"


def test_noise_is_suppressed(sample_file: Path) -> None:
    """The template, the placeholder, the prose, the short value and the
    repeated value are all present in the file and none of them is reported."""

    reported = {finding.location.line for finding in scan_file(sample_file).findings}

    assert 7 not in reported  # ${SESSION_SECRET_FROM_VAULT}
    assert 8 not in reported  # YOUR_KEY_HERE_REPLACE_ME_1234
    assert 9 not in reported  # English sentence
    assert 10 not in reported  # "abc"
    assert 11 not in reported  # "aaaa..."


def test_distinct_secrets_are_counted_once(sample_file: Path) -> None:
    summary = scan_file(sample_file).summary()

    assert summary["total_findings"] == 4
    assert summary["distinct_secrets"] == 4


# --------------------------------------------------------------------------
# determinism
# --------------------------------------------------------------------------


def test_two_scans_of_one_file_are_identical(sample_file: Path) -> None:
    first = scan_file(sample_file)
    second = scan_file(sample_file)

    assert first.findings == second.findings
    assert first.sorted_findings() == second.sorted_findings()
    assert first.summary() == second.summary()
    assert first.to_dict()["findings"] == second.to_dict()["findings"]


def test_two_reports_of_one_scan_are_identical(sample_file: Path) -> None:
    result = scan_file(sample_file)

    assert render_text(result) == render_text(result)


def test_reports_of_two_scans_are_byte_identical(sample_file: Path) -> None:
    assert render_text(scan_file(sample_file)) == render_text(scan_file(sample_file))


# --------------------------------------------------------------------------
# the secret must not survive
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [SYNTHETIC_BASE64, SYNTHETIC_HEX, SYNTHETIC_OTHER, SYNTHETIC_DSN],
)
def test_no_raw_secret_reaches_the_report(sample_file: Path, secret: str) -> None:
    report = render_text(scan_file(sample_file))

    assert secret not in report
    # Not even a distinctive prefix of one.
    assert secret[:8] not in report
    assert secret[-8:] not in report


def test_no_raw_secret_reaches_the_serialized_result(sample_file: Path) -> None:
    result = scan_file(sample_file)

    serialized = result.to_json()

    for secret in (SYNTHETIC_BASE64, SYNTHETIC_HEX, SYNTHETIC_OTHER, SYNTHETIC_DSN):
        assert secret not in serialized
    assert json.loads(serialized)["schema_version"] == secret_shield.SCHEMA_VERSION


def test_no_raw_secret_reaches_any_object_repr(sample_file: Path) -> None:
    result = scan_file(sample_file)
    rendered = "\n".join([repr(result), repr(result.errors), render_text(result)])

    for secret in (SYNTHETIC_BASE64, SYNTHETIC_HEX, SYNTHETIC_OTHER, SYNTHETIC_DSN):
        assert secret not in rendered


def test_no_raw_secret_survives_in_the_scanned_file(tmp_path: Path) -> None:
    """Sanity check on the fixture itself: the file is not modified by scanning."""

    target = tmp_path / "untouched.py"
    target.write_text(SAMPLE, encoding="utf-8")

    scan_file(target)

    assert target.read_text(encoding="utf-8") == SAMPLE


# --------------------------------------------------------------------------
# a clean file
# --------------------------------------------------------------------------


def test_a_clean_file_produces_an_empty_findings_section(tmp_path: Path) -> None:
    target = tmp_path / "clean.py"
    target.write_text(
        'DEBUG = True\nNAME = "secret-shield"\nLIMIT = "your_key_here"\n',
        encoding="utf-8",
    )

    result = scan_file(target)
    report = render_text(result)

    assert result.findings == ()
    assert "FINDINGS" not in report
    assert "total findings   : 0" in report
    assert "not confirmed secrets" in report


def test_a_missing_file_produces_a_report_not_an_exception(tmp_path: Path) -> None:
    result = scan_file(tmp_path / "absent.py")
    report = render_text(result)

    assert len(result.errors) == 1
    assert "ERRORS" in report
    assert "not-found" in report
    assert "could not read every requested input" in report
    assert "total findings   : 0" in report


def test_report_is_reproducible_after_the_file_changes(tmp_path: Path) -> None:
    """Editing a file changes the report only where the edit was."""

    target = tmp_path / "edited.py"
    target.write_text(f'A = "{SYNTHETIC_BASE64}"\n', encoding="utf-8")
    before = render_text(scan_file(target))

    target.write_text(f'A = "{SYNTHETIC_BASE64}"\nB = 1\n', encoding="utf-8")
    after = render_text(scan_file(target))

    assert before != after  # the edit is reflected
    # The finding itself is untouched; only the statistics move.
    assert before.split("SUMMARY")[0] == after.split("SUMMARY")[0]
    assert "total findings   : 1" in after


# --------------------------------------------------------------------------
# scanning real source code
# --------------------------------------------------------------------------


def _package_sources() -> list[Path]:
    """Every ``.py`` file that makes up the installed package."""

    root = Path(secret_shield.__file__).parent
    return sorted(root.rglob("*.py"))


def test_the_package_source_contains_no_findings() -> None:
    """This repository's own code must not read as a secret.

    Before the structural filters existed, entropy alone produced 64 findings
    across the package: Python constants, f-string fragments, qualified
    references, reStructuredText roles and a regex literal. All of them were
    code shapes, none were secrets.

    This is the load-bearing precision test of the whole stage. If a future
    change to a threshold, a filter or the tokenizer makes the scanner cry wolf
    on ordinary source code, this fails, and the failure is a list of exactly
    the values that changed the answer.
    """

    offenders: list[str] = []
    for source in _package_sources():
        for finding in scan_file(source).findings:
            offenders.append(f"{source.name}:{finding.location.line}")

    assert offenders == [], f"false positives in our own source: {offenders}"


def test_scanning_source_code_reports_no_errors() -> None:
    """The scanner reads its own source without complaint."""

    for source in _package_sources():
        result = scan_file(source)

        assert result.errors == (), f"{source.name}: {result.errors}"
        assert result.files_scanned == 1


def test_source_code_scanning_does_not_leak_the_scanned_text() -> None:
    """A docstring full of long words is not a secret, and is never printed."""

    docstring = "considerable interoperability, implementation and maintenance"
    target = Path(__file__).parent / "_scratch_docstring.py"
    target.write_text(f'"""This module {docstring}.\n"""\n', encoding="utf-8")
    try:
        report = render_text(scan_file(target))
    finally:
        target.unlink()

    assert docstring not in report
    assert "total findings   : 0" in report
