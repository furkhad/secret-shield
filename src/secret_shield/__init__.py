"""SecretShield: find accidentally exposed secrets.

This package deliberately holds no scan logic yet. Stage 0 provides the
foundations the rest of the tool is built on:

* :mod:`secret_shield.masking` -- redaction, so a detected secret can never be
  printed, logged or stored.
* :mod:`secret_shield.models` -- the data model, whose central invariant is
  that a :class:`~secret_shield.models.Finding` cannot hold raw secret
  material.
* :mod:`secret_shield.exit_codes` -- the exit-code contract CI will rely on.

Importing this package has no side effects: no configuration is read, no
filesystem is touched and nothing is printed.
"""

from __future__ import annotations

from .exit_codes import (
    EXIT_FINDINGS,
    EXIT_INTERNAL_ERROR,
    EXIT_INTERRUPTED,
    EXIT_NOT_IMPLEMENTED,
    EXIT_SCAN_ERROR,
    EXIT_SUCCESS,
    EXIT_USAGE,
)
from .masking import (
    FULLY_REDACTED,
    REDACTION,
    MaskPolicy,
    fingerprint,
    is_fingerprint,
    mask,
    sanitize_excerpt,
)
from .models import (
    SCHEMA_VERSION,
    TOOL_NAME,
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

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "TOOL_NAME",
    "SCHEMA_VERSION",
    # Enumerations
    "Severity",
    "Confidence",
    "SecretCategory",
    "SourceKind",
    "DetectorKind",
    # Data model
    "Location",
    "Finding",
    "ScanError",
    "ScanResult",
    # Redaction
    "REDACTION",
    "FULLY_REDACTED",
    "MaskPolicy",
    "mask",
    "fingerprint",
    "is_fingerprint",
    "sanitize_excerpt",
    # Exit codes
    "EXIT_SUCCESS",
    "EXIT_FINDINGS",
    "EXIT_USAGE",
    "EXIT_SCAN_ERROR",
    "EXIT_INTERNAL_ERROR",
    "EXIT_NOT_IMPLEMENTED",
    "EXIT_INTERRUPTED",
]