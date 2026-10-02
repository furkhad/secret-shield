"""SecretShield: find accidentally exposed secrets.

Scan one file and read the result::

    import secret_shield

    result = secret_shield.scan_file("config/settings.py")
    print(secret_shield.render_text(result))

What is implemented, and what each layer guarantees:

* :mod:`secret_shield.masking` -- redaction, so a detected secret can never be
  printed, logged or stored.
* :mod:`secret_shield.models` -- the data model, whose central invariant is
  that a :class:`~secret_shield.models.Finding` cannot hold raw secret
  material.
* :mod:`secret_shield.exit_codes` -- the exit-code contract CI will rely on.
* :mod:`secret_shield.entropy` -- Shannon entropy, an alphabet-independent
  evenness ratio, and charset classification.
* :mod:`secret_shield.tokenizer` -- conservative candidate extraction, with
  filters for the code-shaped values that entropy alone cannot distinguish from
  secrets.
* :mod:`secret_shield.detectors` -- the detection rules; today exactly one,
  capped at MEDIUM severity and PROBABLE confidence because entropy alone
  cannot establish what a value is.
* :mod:`secret_shield.scanner` -- reading one text file safely and reporting
  what it could not read, rather than raising.
* :mod:`secret_shield.report` -- rendering a result as plain text.

Not implemented yet: a CLI, directory traversal, vendor rules, JSON and
Markdown output, and Git history scanning.

Importing this package has no side effects: no configuration is read, no
filesystem is touched and nothing is printed.
"""

from __future__ import annotations

from .detectors import EntropyRuleConfig, default_entropy_config
from .entropy import (
    classify_charset,
    normalized_entropy,
    shannon_entropy,
)
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
from .report import render_text
from .scanner import ScanConfig, default_scan_config, scan_file
from .tokenizer import Token, candidates

__version__ = TOOL_VERSION

__all__ = [
    "__version__",
    "TOOL_NAME",
    "TOOL_VERSION",
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
    # Analysis
    "shannon_entropy",
    "normalized_entropy",
    "classify_charset",
    "Token",
    "candidates",
    # Detection and scanning
    "EntropyRuleConfig",
    "default_entropy_config",
    "ScanConfig",
    "default_scan_config",
    "scan_file",
    # Reporting
    "render_text",
    # Exit codes
    "EXIT_SUCCESS",
    "EXIT_FINDINGS",
    "EXIT_USAGE",
    "EXIT_SCAN_ERROR",
    "EXIT_INTERNAL_ERROR",
    "EXIT_NOT_IMPLEMENTED",
    "EXIT_INTERRUPTED",
]