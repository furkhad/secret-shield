"""Unit tests for :mod:`secret_shield.report.text`.

Two properties matter more than the layout. First, the report must be pure: no
file I/O, and the same result always renders to the same bytes so two scans can
be diffed. Second, it must be safe on hostile input, because a report is the one
place where attacker-controlled text is deliberately shown to a human.
"""

from __future__ import annotations

import re

import pytest

from secret_shield.detectors.entropy_rule import detect as detect_entropy
from secret_shield.models import (
    TOOL_VERSION,
    Confidence,
    DetectorKind,
    Finding,
    Location,
    ScanError,
    ScanResult,
    SecretCategory,
    Severity,
    SourceKind,
)
from secret_shield.masking import FULLY_REDACTED, REDACTION
from secret_shield.report import render_text
from secret_shield.report.text import LINE_WIDTH
from secret_shield.tokenizer import candidates

SYNTHETIC_TOKEN = "x8Kq2mNvR4pLzW7yB1cF3dH5jS6tG9uA0"
SYNTHETIC_OTHER = "Q7wZ2mNvR4pLzX9yB1cF3dH8jS0tG5uB2"
SYNTHETIC_HEX = "a3f5c9e17b2d4806be35f1c8a07d29e4"

#: Anything in these classes can move the cursor, set colours, clear the screen
#: or otherwise rewrite what the reader believes they are looking at.
_TERMINAL_ESCAPES = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def result_for(text: str, path: str = "config/settings.py") -> ScanResult:
    """Scan ``text`` as if it were the file at ``path``."""

    findings = detect_entropy(candidates(text), path)
    return ScanResult(
        findings=findings,
        errors=(),
        files_scanned=1,
        bytes_scanned=len(text),
        duration_seconds=0.0,
        tool_version=TOOL_VERSION,
    )


def finding_with(**overrides: object) -> Finding:
    """Build a finding directly, so the reporter can be tested in isolation."""

    fields: dict[str, object] = {
        "rule_id": "high-entropy-string",
        "rule_name": "High-entropy string",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.PROBABLE,
        "location": Location(source_kind=SourceKind.FILE, path="a.py", line=1, column=2),
        "masked_value": REDACTION,
        "value_length": 33,
        "value_fingerprint": "0123456789ab",
        "detector": DetectorKind.ENTROPY,
        "entropy": 4.51,
        "category": SecretCategory.UNKNOWN,
        "remediation": "Review this value and rotate it if it is live.",
    }
    fields.update(overrides)
    return Finding(**fields)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# shape of the report
# --------------------------------------------------------------------------


def test_report_is_human_readable() -> None:
    text = render_text(result_for(f'A = "{SYNTHETIC_TOKEN}"\n'))

    assert text.startswith(f"SecretShield {TOOL_VERSION}")
    assert "FINDINGS (1)" in text
    assert "SUMMARY" in text
    assert text.endswith("\n")


def test_report_shows_everything_needed_to_triage() -> None:
    result = result_for(f'A = "{SYNTHETIC_TOKEN}"\n')
    finding = result.findings[0]

    text = render_text(result)

    assert "config/settings.py:1:6" in text  # path, line, column
    assert "high-entropy-string" in text  # rule
    assert "unknown" in text  # category
    assert "MEDIUM" in text  # severity
    assert "probable" in text  # confidence
    assert "5.04 bits/char" in text  # entropy
    assert REDACTION in text  # masked value
    assert "33 characters" in text  # length
    assert finding.value_fingerprint in text  # fingerprint


def test_report_shows_scan_statistics() -> None:
    result = result_for(f'A = "{SYNTHETIC_TOKEN}"\n')

    text = render_text(result)

    assert "files scanned    : 1" in text
    assert f"bytes scanned    : {result.bytes_scanned}" in text
    assert "total findings   : 1" in text


def test_report_states_that_findings_are_not_confirmed_secrets() -> None:
    text = render_text(result_for(f'A = "{SYNTHETIC_TOKEN}"\n'))

    assert "not confirmed secrets" in text
    assert "not a confirmed credential" in text


def test_report_shows_errors_alongside_findings() -> None:
    result = ScanResult(
        findings=detect_entropy(candidates(f'A = "{SYNTHETIC_TOKEN}"\n'), "a.py"),
        errors=(ScanError("file is not valid UTF-8 text", path="b.bin", code="invalid-encoding"),),
        files_scanned=1,
        bytes_scanned=40,
        duration_seconds=0.0,
        tool_version=TOOL_VERSION,
    )

    text = render_text(result)

    assert "ERRORS" in text
    assert "invalid-encoding" in text
    assert "file is not valid UTF-8 text" in text
    assert "could not read every requested input" in text


def test_report_renders_a_clean_scan_without_noise() -> None:
    result = result_for("DEBUG = True\nCOUNT = 3\n")

    text = render_text(result)

    assert "FINDINGS" not in text
    assert "ERRORS" not in text
    assert "total findings   : 0" in text
    assert "by severity      : none" in text


def test_report_handles_no_findings_and_no_errors() -> None:
    text = render_text(
        ScanResult(
            findings=(),
            errors=(),
            files_scanned=0,
            bytes_scanned=0,
            duration_seconds=0.0,
            tool_version=TOOL_VERSION,
        )
    )

    assert "total findings   : 0" in text
    assert "files scanned    : 0" in text


def test_git_locations_render_their_commit() -> None:
    commit = "a" * 40
    finding = finding_with(
        location=Location(
            source_kind=SourceKind.GIT,
            path="config/settings.py",
            line=4,
            column=9,
            commit=commit,
            commit_time=1700000000,
        )
    )

    text = render_text(ScanResult(findings=(finding,), tool_version=TOOL_VERSION))

    assert "config/settings.py:4:9" in text
    # The commit is abbreviated to the length git itself displays.
    assert commit[:12] in text
    assert commit not in text


def test_missing_entropy_renders_as_not_measured() -> None:
    text = render_text(
        ScanResult(findings=(finding_with(entropy=None),), tool_version=TOOL_VERSION)
    )

    assert "not measured" in text


# --------------------------------------------------------------------------
# advice is printed once per rule, not once per finding
# --------------------------------------------------------------------------


def test_advice_is_rendered_once_for_many_findings_from_one_rule() -> None:
    text = render_text(result_for(f'A = "{SYNTHETIC_TOKEN}"\nB = "{SYNTHETIC_OTHER}"\n'))

    assert _header_count(text, "HOW TO RESPOND") == 1
    assert text.count("Entropy alone does not identify a credential") == 1
    assert "high-entropy-string (2 findings)" in text


def test_advice_count_singular_for_a_single_finding() -> None:
    text = render_text(result_for(f'A = "{SYNTHETIC_TOKEN}"\n'))

    assert "high-entropy-string (1 finding)" in text


def test_advice_section_is_omitted_when_there_is_no_advice() -> None:
    text = render_text(
        ScanResult(findings=(finding_with(remediation=""),), tool_version=TOOL_VERSION)
    )

    assert "HOW TO RESPOND" not in text


def test_advice_section_is_omitted_for_a_clean_scan() -> None:
    text = render_text(result_for("DEBUG = True\n"))

    assert "HOW TO RESPOND" not in text


def test_findings_of_different_rules_each_get_their_advice() -> None:
    findings = (
        finding_with(rule_id="high-entropy-string", remediation="Entropy advice."),
        finding_with(rule_id="aws-access-key-id", remediation="Vendor advice."),
    )

    text = render_text(ScanResult(findings=findings, tool_version=TOOL_VERSION))

    assert _header_count(text, "HOW TO RESPOND") == 1
    assert "Entropy advice." in text
    assert "Vendor advice." in text


def test_report_sections_appear_in_a_fixed_order() -> None:
    result = result_for(f'A = "{SYNTHETIC_TOKEN}"\n')
    result = ScanResult(
        findings=result.findings,
        errors=(ScanError("boom", path="x", code="oops"),),
        files_scanned=1,
        bytes_scanned=10,
        tool_version=TOOL_VERSION,
    )

    text = render_text(result)

    assert text.index("FINDINGS") < text.index("HOW TO RESPOND")
    assert text.index("HOW TO RESPOND") < text.index("ERRORS")
    assert text.index("ERRORS") < text.index("SUMMARY")


def test_absent_version_renders_as_unknown() -> None:
    result = ScanResult(findings=(), errors=(), tool_version="")

    assert "unknown" in render_text(result)


def test_report_rejects_a_non_result() -> None:
    with pytest.raises(TypeError):
        render_text("not a result")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# the raw secret must not appear
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        SYNTHETIC_TOKEN,
        SYNTHETIC_OTHER,
        SYNTHETIC_HEX,
        "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
    ],
)
def test_raw_secret_never_appears_in_the_report(secret: str) -> None:
    text = render_text(result_for(f'A = "{secret}"\nB = "{secret}"\n'))

    assert len(text) > 0
    assert secret not in text
    assert secret[:12] not in text
    assert secret[:8] not in text


def test_report_shows_only_the_redaction_marker() -> None:
    """Nothing longer than the redaction is shown, even for long candidates.

    A finding produced by the entropy rule uses a fully-redacted policy, so no
    prefix or suffix of the original value survives anywhere in the output.
    """

    text = render_text(result_for(f'A = "{SYNTHETIC_TOKEN}"\n'))

    assert text.count(REDACTION) == 1


def test_masked_value_is_rendered_as_given() -> None:
    """A finding built with a revealing policy shows its masked form, not its raw form."""

    revealing = Finding.from_match(
        rule_id="high-entropy-string",
        rule_name="High-entropy string",
        category=SecretCategory.UNKNOWN,
        severity=Severity.MEDIUM,
        confidence=Confidence.PROBABLE,
        detector=DetectorKind.ENTROPY,
        location=Location(source_kind=SourceKind.FILE, path="a.py", line=1, column=1),
        raw_value=SYNTHETIC_TOKEN,
        entropy=5.04,
    )

    text = render_text(ScanResult(findings=(revealing,), tool_version=TOOL_VERSION))

    assert revealing.masked_value in text
    assert SYNTHETIC_TOKEN not in text
    assert len(revealing.masked_value) < len(SYNTHETIC_TOKEN)


def test_fully_redacted_policy_is_used_by_the_entropy_rule() -> None:
    for finding in result_for(f'A = "{SYNTHETIC_TOKEN}"\n').findings:
        assert finding.masked_value == FULLY_REDACTED.apply(SYNTHETIC_TOKEN)
        assert finding.masked_value == REDACTION


# --------------------------------------------------------------------------
# hostile input
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "\x1b[31mred\x1b[0m.py",
        "\x1b]2;window-title\x07.py",
        "new\nline.py",
        "tab\there.py",
        "bell\x07.py",
        "delete\x7f.py",
        "csi\x9b31m.py",
        "backspace\x08.py",
    ],
)
def test_hostile_filename_cannot_inject_terminal_escapes(name: str) -> None:
    finding = finding_with(location=Location(source_kind=SourceKind.FILE, path=name, line=1, column=1))

    text = render_text(ScanResult(findings=(finding,), tool_version=TOOL_VERSION))

    assert not _TERMINAL_ESCAPES.search(text), f"terminal escape survived: {text!r}"
    assert "\x1b" not in text
    assert "\x07" not in text


def _header_count(text: str, header: str) -> int:
    """Count lines that are exactly ``header``.

    Injecting text that *contains* the word is harmless; injecting text that
    *becomes* the header is not. Only a line that is the header alone counts.
    """

    return sum(1 for line in text.splitlines() if line.strip() == header)


def test_hostile_filename_cannot_inject_a_newline() -> None:
    """One finding must always occupy a predictable block of lines."""

    finding = finding_with(
        location=Location(source_kind=SourceKind.FILE, path="a\nb\nSUMMARY\n", line=1, column=1)
    )

    text = render_text(ScanResult(findings=(finding,), tool_version=TOOL_VERSION))

    assert _header_count(text, "SUMMARY") == 1
    assert "\nSUMMARY" in text  # the genuine one, untouched


def test_hostile_remediation_text_cannot_inject_anything() -> None:
    finding = finding_with(remediation="\x1b[2J\x1b]0;pwned\x07 rotate it\nFAKE SUMMARY\n")

    text = render_text(ScanResult(findings=(finding,), tool_version=TOOL_VERSION))

    assert not _TERMINAL_ESCAPES.search(text)
    assert _header_count(text, "SUMMARY") == 1
    assert _header_count(text, "FINDINGS (1)") == 1


def test_hostile_error_text_cannot_inject_anything() -> None:
    result = ScanResult(
        findings=(),
        errors=(ScanError(reason="\x1b[31mboom\x1b[0m", path="x\x07y", code="oops"),),
        tool_version=TOOL_VERSION,
    )

    text = render_text(result)

    assert not _TERMINAL_ESCAPES.search(text)
    assert "\x1b" not in text


def test_report_has_no_ansi_colour_codes_at_all() -> None:
    text = render_text(result_for(f'A = "{SYNTHETIC_TOKEN}"\n'))

    assert "\x1b[" not in text
    assert "\x9b" not in text


def test_lines_are_wrapped_to_the_declared_width() -> None:
    text = render_text(result_for(f'A = "{SYNTHETIC_TOKEN}"\n'))

    longest = max(len(line) for line in text.splitlines())

    assert longest <= LINE_WIDTH


# --------------------------------------------------------------------------
# purity and determinism
# --------------------------------------------------------------------------


def test_rendering_twice_produces_identical_text() -> None:
    result = result_for(f'A = "{SYNTHETIC_TOKEN}"\nB = "{SYNTHETIC_OTHER}"\n')

    assert render_text(result) == render_text(result)


def test_two_results_with_the_same_content_render_identically() -> None:
    content = f'A = "{SYNTHETIC_TOKEN}"\nB = "{SYNTHETIC_OTHER}"\n'

    assert render_text(result_for(content)) == render_text(result_for(content))


def test_duration_does_not_appear_in_the_report() -> None:
    """Wall-clock time varies between runs, and would defeat diffing.

    The value stays on the result for callers that want it; the text report
    deliberately omits it so that reports are byte-stable.
    """

    slow = ScanResult(findings=(), duration_seconds=1.25, tool_version=TOOL_VERSION)
    fast = ScanResult(findings=(), duration_seconds=0.001, tool_version=TOOL_VERSION)

    assert render_text(slow) == render_text(fast)
    assert "1.25" not in render_text(slow)


def test_rendering_does_not_modify_the_result() -> None:
    result = result_for(f'A = "{SYNTHETIC_TOKEN}"\n')
    before = result.to_dict()

    render_text(result)

    assert result.to_dict() == before


def test_report_is_pure_and_does_no_file_io(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rendering must not read anything, whatever the path in the result."""

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("the reporter performed file I/O")

    monkeypatch.setattr("pathlib.Path.read_text", explode)
    monkeypatch.setattr("pathlib.Path.read_bytes", explode)
    monkeypatch.setattr("builtins.open", explode)

    finding = finding_with(
        location=Location(source_kind=SourceKind.FILE, path="/etc/passwd", line=1, column=1)
    )
    text = render_text(ScanResult(findings=(finding,), tool_version=TOOL_VERSION))

    assert "passwd" in text