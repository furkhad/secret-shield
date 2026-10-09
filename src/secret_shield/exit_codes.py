"""Process exit codes for SecretShield.

Exit codes are part of the tool's public contract. CI pipelines, pre-commit
hooks and shell scripts branch on them, so the numeric values must remain
stable for the lifetime of the 0.x series.

Nothing in this module inspects secrets; it only describes how the process
ended.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, Mapping

__all__ = [
    "EXIT_SUCCESS",
    "EXIT_FINDINGS",
    "EXIT_USAGE",
    "EXIT_SCAN_ERROR",
    "EXIT_INTERNAL_ERROR",
    "EXIT_NOT_IMPLEMENTED",
    "EXIT_INTERRUPTED",
    "DESCRIPTIONS",
    "describe_exit_code",
]

EXIT_SUCCESS: Final[int] = 0
"""The scan completed and nothing met the failure threshold."""

EXIT_FINDINGS: Final[int] = 1
"""The scan completed and reported findings at or above the failure threshold."""

EXIT_USAGE: Final[int] = 2
"""Invalid command line usage or invalid configuration.

This matches the convention ``argparse`` already uses for bad arguments, so
scripts written against argparse behave the same way with SecretShield.
"""

EXIT_SCAN_ERROR: Final[int] = 3
"""The scan ran but at least one unit of work failed.

An unreadable file, a missing ``git`` binary or a corrupt repository produce
this code rather than aborting the run.
"""

EXIT_INTERNAL_ERROR: Final[int] = 4
"""An unexpected internal error. A traceback may follow."""

EXIT_NOT_IMPLEMENTED: Final[int] = 5
"""A requested capability does not exist in this release.

Reserved for a capability not yet implemented. No subcommand returns it: a
flag is only added once the code behind it exists.
"""

EXIT_INTERRUPTED: Final[int] = 130
"""Interrupted by the user (SIGINT). 128 + signal number, per shell convention."""


DESCRIPTIONS: Final[Mapping[int, str]] = MappingProxyType(
    {
        EXIT_SUCCESS: "Success: no findings at or above the failure threshold.",
        EXIT_FINDINGS: "Findings: the scan detected reportable findings.",
        EXIT_USAGE: "Usage error: invalid arguments or configuration.",
        EXIT_SCAN_ERROR: "Scan error: the run completed with failures.",
        EXIT_INTERNAL_ERROR: "Internal error: an unexpected exception occurred.",
        EXIT_NOT_IMPLEMENTED: "Not implemented: this capability is unavailable.",
        EXIT_INTERRUPTED: "Interrupted: the user cancelled the run.",
    }
)


def describe_exit_code(code: int) -> str:
    """Return a human-readable description of a SecretShield exit code.

    Unknown codes are described rather than rejected, because a wrapper script
    may legitimately receive a signal-derived value such as ``143`` (SIGTERM).
    """

    return DESCRIPTIONS.get(code, f"Unknown exit code: {code}")
