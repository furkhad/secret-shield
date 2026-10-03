"""Unit tests for :mod:`secret_shield.scanner`.

The scanner's contract with bad input is the point of most of these tests: a
scan reports, it does not raise. A CI job that dies on the first unreadable
file is worse than one that reports the file as unreadable.
"""

from __future__ import annotations

import dataclasses
import os
import stat
from pathlib import Path

import pytest

from secret_shield.detectors import default_entropy_config
from secret_shield.models import Confidence, Severity, SourceKind
from secret_shield.scanner import (
    BINARY_SNIFF_BYTES,
    DEFAULT_MAX_FILE_SIZE,
    ScanConfig,
    default_scan_config,
    scan_file,
)

SYNTHETIC_TOKEN = "x8Kq2mNvR4pLzW7yB1cF3dH5jS6tG9uA0"
SYNTHETIC_OTHER = "Q7wZ2mNvR4pLzX9yB1cF3dH8jS0tG5uB2"
SYNTHETIC_HEX = "a3f5c9e17b2d4806be35f1c8a07d29e4"


def write(tmp_path: Path, name: str, content: str | bytes) -> Path:
    """Create a file with exactly the given bytes, bypassing newline translation."""

    target = tmp_path / name
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_bytes(content.encode("utf-8"))
    return target


# --------------------------------------------------------------------------
# the happy path
# --------------------------------------------------------------------------


def test_scan_of_a_file_with_a_secret(tmp_path: Path) -> None:
    target = write(tmp_path, "settings.py", f'API_TOKEN = "{SYNTHETIC_TOKEN}"\n')

    result = scan_file(target)

    assert len(result.findings) == 1
    assert result.files_scanned == 1
    assert result.errors == ()
    assert result.findings[0].location.path == str(target)
    assert result.findings[0].location.line == 1
    assert result.findings[0].location.source_kind is SourceKind.FILE


def test_statistics_reflect_the_file_actually_read(tmp_path: Path) -> None:
    content = f'A = "{SYNTHETIC_TOKEN}"\n'
    target = write(tmp_path, "a.py", content)

    result = scan_file(target)

    assert result.files_scanned == 1
    assert result.bytes_scanned == len(content.encode("utf-8"))


def test_several_findings_are_reported(tmp_path: Path) -> None:
    content = (
        f'A = "{SYNTHETIC_TOKEN}"\nB = "{SYNTHETIC_OTHER}"\nC = "{SYNTHETIC_HEX}"\n'
    )
    target = write(tmp_path, "many.py", content)

    result = scan_file(target)

    assert [finding.location.line for finding in result.findings] == [1, 2, 3]


def test_a_clean_file_produces_no_findings(tmp_path: Path) -> None:
    target = write(
        tmp_path,
        "clean.py",
        'DEBUG = True\nNAME = "application"\nLIMIT = "your_key_here"\nCOUNT = 3\n',
    )

    result = scan_file(target)

    assert result.findings == ()
    assert result.errors == ()
    assert result.files_scanned == 1


def test_findings_are_capped_at_medium_with_probable_confidence(tmp_path: Path) -> None:
    target = write(tmp_path, "a.py", f'A = "{SYNTHETIC_TOKEN}"\n')

    finding = scan_file(target).findings[0]

    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.PROBABLE


def test_utf8_content_is_handled(tmp_path: Path) -> None:
    target = write(
        tmp_path, "unicode.py", f'# café naïve 日本語\nA = "{SYNTHETIC_TOKEN}"\n'
    )

    result = scan_file(target)

    assert result.findings[0].location.line == 2


def test_a_byte_order_mark_does_not_shift_columns(tmp_path: Path) -> None:
    target = write(tmp_path, "bom.py", f'﻿A = "{SYNTHETIC_TOKEN}"\n')

    finding = scan_file(target).findings[0]

    assert finding.location.line == 1
    # The BOM is consumed by the utf-8-sig codec, so the columns match the text
    # as an editor would show it: A=1 space=2 ==3 space=4 quote=5, value at 6.
    assert finding.location.column == 6


# --------------------------------------------------------------------------
# unreadable, undecodable and oversized input
# --------------------------------------------------------------------------


def test_missing_file_is_a_scan_error(tmp_path: Path) -> None:
    result = scan_file(tmp_path / "absent.py")

    assert result.findings == ()
    assert len(result.errors) == 1
    assert result.errors[0].code == "not-found"
    assert result.files_scanned == 0
    assert result.bytes_scanned == 0


def test_directory_is_a_scan_error(tmp_path: Path) -> None:
    result = scan_file(tmp_path)

    assert len(result.errors) == 1
    assert result.errors[0].code == "is-directory"


def test_unreadable_file_is_a_scan_error(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root bypasses permission bits")

    target = write(tmp_path, "locked.py", f'A = "{SYNTHETIC_TOKEN}"\n')
    target.chmod(0o000)
    try:
        result = scan_file(target)
    finally:
        target.chmod(stat.S_IRUSR | stat.S_IWUSR)

    assert result.findings == ()
    assert len(result.errors) == 1
    assert result.errors[0].code == "read-failed"
    assert result.files_scanned == 0


def test_invalid_utf8_is_a_scan_error(tmp_path: Path) -> None:
    target = write(tmp_path, "latin1.py", b"# caf\xe9 na\xefve\nA = 1\n")

    result = scan_file(target)

    assert len(result.errors) == 1
    assert result.errors[0].code == "invalid-encoding"
    assert result.files_scanned == 0


def test_binary_content_is_a_scan_error(tmp_path: Path) -> None:
    target = write(
        tmp_path, "blob.bin", b"\x7fELF\x02\x01\x00\x00\x00binary\x00payload"
    )

    result = scan_file(target)

    assert len(result.errors) == 1
    assert result.errors[0].code == "binary"


def test_binary_detection_sniffs_only_a_prefix(tmp_path: Path) -> None:
    """A NUL byte past the sniff window does not mark a file binary.

    Sniffing a prefix keeps the check cheap on large inputs. The trade-off is
    that a file with clean text at the start is decoded as text even if binary
    data follows. That is safe rather than dangerous: U+0000 is valid UTF-8, so
    the content decodes and is scanned, and the tokenizer already handles NUL
    without complaint.
    """

    content = b"#" + b"a" * BINARY_SNIFF_BYTES + b"\x00tail"
    target = write(tmp_path, "mixed.bin", content)

    result = scan_file(target)

    assert result.errors == ()
    assert result.files_scanned == 1
    assert result.bytes_scanned == len(content)


def test_empty_file_is_scanned_without_findings(tmp_path: Path) -> None:
    target = write(tmp_path, "empty.py", "")

    result = scan_file(target)

    assert result.findings == ()
    assert result.errors == ()
    assert result.files_scanned == 1
    assert result.bytes_scanned == 0


def test_file_without_trailing_newline_is_scanned(tmp_path: Path) -> None:
    target = write(tmp_path, "nonewline.py", f'A = "{SYNTHETIC_TOKEN}"')

    assert len(scan_file(target).findings) == 1


def test_oversized_file_is_refused(tmp_path: Path) -> None:
    target = write(tmp_path, "big.py", "#" * 5000)
    config = ScanConfig(max_file_size=1000)

    result = scan_file(target, config)

    assert len(result.errors) == 1
    assert result.errors[0].code == "too-large"
    assert result.bytes_scanned == 0


def test_file_at_exactly_the_size_limit_is_scanned(tmp_path: Path) -> None:
    content = f'A = "{SYNTHETIC_TOKEN}"\n'
    target = write(tmp_path, "exact.py", content)

    result = scan_file(target, ScanConfig(max_file_size=len(content)))

    assert result.errors == ()
    assert result.bytes_scanned == len(content)


def test_default_size_limit_is_ten_mebibytes() -> None:
    assert DEFAULT_MAX_FILE_SIZE == 10 * 1024 * 1024


# --------------------------------------------------------------------------
# determinism
# --------------------------------------------------------------------------


def test_two_scans_of_one_file_agree(tmp_path: Path) -> None:
    content = f'A = "{SYNTHETIC_TOKEN}"\nB = "{SYNTHETIC_OTHER}"\n'
    target = write(tmp_path, "stable.py", content)

    first = scan_file(target)
    second = scan_file(target)

    assert first.findings == second.findings
    assert first.sorted_findings() == second.sorted_findings()
    assert first.summary() == second.summary()


def test_findings_are_returned_in_file_order(tmp_path: Path) -> None:
    content = f'A = "{SYNTHETIC_TOKEN}"\n{"#" * 40}\nC = "{SYNTHETIC_OTHER}"\n'
    target = write(tmp_path, "ordered.py", content)

    result = scan_file(target)

    assert [finding.location.line for finding in result.findings] == [1, 3]


def test_repeated_occurrences_share_one_secret(tmp_path: Path) -> None:
    content = f'A = "{SYNTHETIC_TOKEN}"\nB = "{SYNTHETIC_TOKEN}"\n'
    target = write(tmp_path, "repeat.py", content)

    result = scan_file(target)

    assert result.summary()["total_findings"] == 2
    assert result.summary()["distinct_secrets"] == 1


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


def test_entropy_thresholds_can_be_stricter(tmp_path: Path) -> None:
    target = write(tmp_path, "hex.py", f'A = "{SYNTHETIC_HEX}"\n')
    strict = ScanConfig(
        entropy=dataclasses.replace(default_entropy_config(), min_raw_entropy=5.0)
    )

    assert len(scan_file(target).findings) == 1
    assert scan_file(target, strict).findings == ()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_file_size": 0},
        {"max_file_size": -1},
        {"max_file_size": "10"},
        {"max_file_size": True},
        {"entropy": "strict"},
        {"entropy": None},
    ],
)
def test_invalid_configuration_is_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises((ValueError, TypeError)):
        ScanConfig(**kwargs)  # type: ignore[arg-type]


def test_default_scan_config_returns_independent_copies() -> None:
    first = default_scan_config()
    second = default_scan_config()

    assert first == second
    assert first.entropy is not second.entropy


def test_scan_rejects_a_non_config() -> None:
    with pytest.raises(TypeError):
        scan_file("anything.py", "not a config")  # type: ignore[arg-type]


def test_scan_config_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        default_scan_config().max_file_size = 1


def test_scan_accepts_str_and_path_alike(tmp_path: Path) -> None:
    target = write(tmp_path, "a.py", f'A = "{SYNTHETIC_TOKEN}"\n')

    from_path = scan_file(target)
    from_str = scan_file(str(target))

    assert from_path.findings == from_str.findings


def test_scan_never_raises_on_hostile_content(tmp_path: Path) -> None:
    """Content designed to break a parser must still produce a result."""

    hostile = [
        "\x00\x01\x02\x03",
        "x" * 200_000,
        '"' * 1000,
        "=" * 1000,
        "A" * 999 + '"' + "B" * 999,
        "\n" * 5000,
        "'\\''",
        "`" * 500,
        "$" * 5000 + "{}" * 500,
    ]
    for index, content in enumerate(hostile):
        target = write(tmp_path, f"hostile{index}.txt", content)

        result = scan_file(target)

        assert isinstance(result.files_scanned, int)


def test_a_lone_surrogate_cannot_reach_the_scanner(tmp_path: Path) -> None:
    """``scan_file`` decodes UTF-8, which cannot yield a lone surrogate.

    Worth stating because the tokenizer would happily accept one as a ``str``:
    the scanner's decode step is what makes the input safe, not the tokenizer.
    """

    with pytest.raises(UnicodeEncodeError):
        write(tmp_path, "surrogate.txt", "\ud800")


def test_scan_never_raises_on_hostile_paths(tmp_path: Path) -> None:
    weird = [
        "\x1b[31mred.txt",
        "file with spaces.txt",
        "file\twith\ttabs.txt",
        "\u202eevtxet.txt",
        "'quoted'.txt",
    ]
    for index, name in enumerate(weird):
        write(tmp_path, name, "A = 1\n")
        result = scan_file(tmp_path / name)

        assert isinstance(result.files_scanned, int)
