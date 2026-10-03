"""Scanning a single text file.

Stage 1 scope: one file, in memory, no directory traversal, no Git, no
threads. The API is deliberately small so that later stages can add sources
without changing how this one behaves.

Two rules govern everything here:

* **A scan never raises for bad input.** A missing file, a directory, a
  permission error, undecodable bytes or an oversized file all produce a
  :class:`~secret_shield.models.ScanError` inside the result. A scanner that
  dies on the first bad file is useless in CI.
* **A scan never prints.** Not the file, not a candidate, not a finding's raw
  value. Returning a :class:`~secret_shield.models.ScanResult` is the only
  output; rendering it is the reporter's job, and the reporter only ever sees
  redacted values.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from .detectors import EntropyRuleConfig, default_entropy_config
from .detectors import detect as detect_entropy
from .filters.binary import has_nul_byte
from .models import TOOL_VERSION, Finding, ScanError, ScanResult
from .tokenizer import candidates

__all__ = [
    "DEFAULT_MAX_FILE_SIZE",
    "BINARY_SNIFF_BYTES",
    "ScanConfig",
    "default_scan_config",
    "scan_file",
]

DEFAULT_MAX_FILE_SIZE: Final[int] = 10 * 1024 * 1024
"""Largest file that will be read, in bytes (10 MiB).

A hard ceiling is a denial-of-service control: the scanner parses untrusted
content, so it must not be able to be made to allocate without bound.
"""

BINARY_SNIFF_BYTES: Final[int] = 8192
"""How much of a file is inspected for NUL bytes when deciding it is binary.

Text files essentially never contain NUL, so its presence in the first block
is a reliable signal. Sniffing a prefix rather than the whole file keeps the
check cheap on large inputs.
"""


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Settings for a scan.

    Attributes:
        max_file_size: Largest file to read, in bytes.
        entropy: Thresholds for the entropy detector.
    """

    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    entropy: EntropyRuleConfig = field(default_factory=default_entropy_config)

    def __post_init__(self) -> None:
        if isinstance(self.max_file_size, bool) or not isinstance(self.max_file_size, int):
            raise TypeError(f"max_file_size must be an int, got {type(self.max_file_size).__name__}")
        if self.max_file_size < 1:
            raise ValueError("max_file_size must be at least 1")
        if not isinstance(self.entropy, EntropyRuleConfig):
            raise TypeError(
                f"entropy must be an EntropyRuleConfig, got {type(self.entropy).__name__}"
            )


DEFAULT_SCAN_CONFIG: Final[ScanConfig] = ScanConfig()
"""The shipped defaults: 10 MiB file limit and the standard entropy gates."""


def default_scan_config() -> ScanConfig:
    """Return a fresh copy of the default scan configuration."""

    return ScanConfig(max_file_size=DEFAULT_MAX_FILE_SIZE, entropy=default_entropy_config())


def scan_file(path: str | Path, config: ScanConfig | None = None) -> ScanResult:
    """Scan one text file and return the result.

    Args:
        path: File to scan. Directories are refused.
        config: Scan settings. Defaults to :data:`DEFAULT_SCAN_CONFIG`.

    Returns:
        A :class:`~secret_shield.models.ScanResult`. Failures appear in
        ``errors`` rather than as exceptions; the finding list is then empty.
        Findings are returned in file order, which makes the result
        deterministic for a given input.

    Raises:
        TypeError: If ``config`` is not a :class:`ScanConfig`.
    """

    if config is not None and not isinstance(config, ScanConfig):
        raise TypeError(f"config must be a ScanConfig, got {type(config).__name__}")

    settings = config if config is not None else DEFAULT_SCAN_CONFIG
    target = Path(path)
    started = time.monotonic()

    text, size, error = _read_text_file(target, settings)
    findings: tuple[Finding, ...] = ()
    files_scanned = 0
    bytes_scanned = 0
    errors: tuple[ScanError, ...] = ()

    if error is not None:
        errors = (error,)
    else:
        assert text is not None  # guaranteed when error is None
        files_scanned = 1
        bytes_scanned = size
        findings = detect_entropy(candidates(text), str(target), settings.entropy)

    return ScanResult(
        findings=findings,
        errors=errors,
        files_scanned=files_scanned,
        bytes_scanned=bytes_scanned,
        duration_seconds=time.monotonic() - started,
        tool_version=TOOL_VERSION,
    )


def _read_text_file(
    path: Path, config: ScanConfig
) -> tuple[str | None, int, ScanError | None]:
    """Read ``path`` as text, or explain why it cannot be read.

    Returns:
        ``(text, byte_count, error)``. Exactly one of ``text`` and ``error`` is
        set. The byte count is ``0`` when nothing was read, so statistics never
        claim work that did not happen.
    """

    if not path.exists():
        return None, 0, ScanError("file does not exist", path=str(path), code="not-found")

    try:
        if path.is_dir():
            return None, 0, ScanError("path is a directory", path=str(path), code="is-directory")
        size = path.stat().st_size
    except OSError as exc:
        return None, 0, ScanError(
            f"cannot read file metadata: {exc.strerror or exc.__class__.__name__}",
            path=str(path),
            code="stat-failed",
        )

    if size > config.max_file_size:
        return (
            None,
            0,
            ScanError(
                f"file is larger than the {config.max_file_size} byte limit",
                path=str(path),
                code="too-large",
            ),
        )

    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, 0, ScanError(
            f"cannot read file: {exc.strerror or exc.__class__.__name__}",
            path=str(path),
            code="read-failed",
        )

    if has_nul_byte(data[:BINARY_SNIFF_BYTES]):
        return None, 0, ScanError(
            "file looks binary (NUL byte in the first "
            f"{BINARY_SNIFF_BYTES} bytes)",
            path=str(path),
            code="binary",
        )

    try:
        # utf-8-sig transparently drops a byte-order mark and still reads plain
        # UTF-8, so a BOM does not become part of the first column number.
        return data.decode("utf-8-sig"), len(data), None
    except UnicodeDecodeError:
        return (
            None,
            0,
            ScanError(
                "file is not valid UTF-8 text",
                path=str(path),
                code="invalid-encoding",
            ),
        )