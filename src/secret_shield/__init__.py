"""SecretShield: find accidentally exposed secrets.

Scan a file or a whole tree::

    import secret_shield

    result = secret_shield.scan_path(".")
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
* :mod:`secret_shield.detectors` -- the detection rules: vendor patterns with
  the context logic that supports them, plus the entropy rule for values no
  vendor claims.
* :mod:`secret_shield.pipeline` -- turning two detectors into one answer:
  overlap fusion, deduplication and the canonical ordering a scan reports in.
* :mod:`secret_shield.filters` -- whether a file is text, and whether its path
  may be looked at at all.
* :mod:`secret_shield.scanner` -- reading one text file safely and reporting
  what it could not read, rather than raising.
* :mod:`secret_shield.sources` -- where secrets are looked for: a file, a whole
  directory tree, or a Git repository's history.
* :mod:`secret_shield.report` -- rendering a result as plain text, JSON,
  Markdown or SARIF.
* :mod:`secret_shield.baseline` -- suppressing known findings so a scan can
  fail only on new ones.
* :mod:`secret_shield.cli` -- the ``secret-shield`` command line front end.

Not implemented yet: allowlists, custom user-supplied rules, and network
verification of a finding.

Importing this package has no side effects: no configuration is read, no
filesystem is touched and nothing is printed.
"""

from __future__ import annotations

from .detectors import (
    EntropyCandidate,
    EntropyRuleConfig,
    default_entropy_config,
    entropy_candidates,
)
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
from .filters import (
    BinaryConfig,
    BinaryVerdict,
    Decision,
    PathFilterConfig,
    SkipReason,
    classify_bytes,
    default_binary_config,
    default_path_filter_config,
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
from .pipeline import (
    ENTROPY_CONFIDENCE,
    MAX_CONFIDENCE,
    MergedMatch,
    analyze_text,
    dedupe,
    describes_same_value,
    fuse,
    pattern_order,
)
from .report import render_text
from .scanner import ScanConfig, default_scan_config, scan_file
from .sources import (
    PathScanConfig,
    WalkResult,
    default_path_scan_config,
    scan_path,
    walk,
)
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
    "EntropyCandidate",
    "entropy_candidates",
    "ScanConfig",
    "default_scan_config",
    "scan_file",
    # Fusion
    "MergedMatch",
    "analyze_text",
    "fuse",
    "dedupe",
    "describes_same_value",
    "pattern_order",
    "MAX_CONFIDENCE",
    "ENTROPY_CONFIDENCE",
    # Sources
    "PathScanConfig",
    "default_path_scan_config",
    "scan_path",
    "walk",
    "WalkResult",
    # Filters
    "BinaryConfig",
    "BinaryVerdict",
    "classify_bytes",
    "default_binary_config",
    "PathFilterConfig",
    "default_path_filter_config",
    "Decision",
    "SkipReason",
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
