# SecretShield independent CI credential guard
#
# The repository's own .secretshield.toml exists so the self-scan stays quiet
# about example strings in documentation. That is fine for this repository,
# but a scanner's config file must never be the only thing standing between a
# live credential and the release pipeline. This guard therefore runs the
# scanner with DEFAULT configuration only -- no repo config file, no
# environment variables, no overrides -- and fails when a vendor-rule match
# (HIGH_CONFIDENCE or VERIFIED) appears in any file outside tests/.
#
# Entropy findings (PROBABLE) are expected noise in docs, examples and build
# metadata and are allowed. Only vendor-rule matches at HIGH_CONFIDENCE or
# VERIFIED are treated as real credential patterns.
#
# Exit codes mirror the CLI contract: 0 clean, 1 real credential patterns
# found, 3 the scan could not read every input (a truncated scan must never
# pass a pipeline that only distinguishes 0 from 1).
#
# This script is the body of the "Credential-Shaped Text Guard" job in
# .github/workflows/ci.yml. Run it as: python scripts/ci_credential_guard.py [ROOT]

from __future__ import annotations

import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from secret_shield.config import load_config
from secret_shield.models import Finding, ScanResult
from secret_shield.sources.filesystem import scan_path

#: Files under this prefix are synthetic test fixtures, never production data.
_TESTS_PREFIX = "tests/"

#: Confidence at or above which a vendor-rule match is a real credential
#: pattern. PROBABLE (2) entropy noise is explicitly allowed.
_HIGH_CONFIDENCE_VALUE = 3


def scan_with_defaults(root: Path) -> ScanResult:
    """Scan ``root`` using default configuration only.

    The config is loaded from an empty temporary directory with an empty
    environment so that no repository file and no ambient ``SECRETSHIELD_*``
    variable can mute the guard.
    """

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = load_config(project_root=Path(tmpdir), environ={})
        return scan_path(root, cfg.path_scan_config())


def suspicious_findings(result: ScanResult) -> list[Finding]:
    """Filter to vendor-rule matches at HIGH_CONFIDENCE+ outside ``tests/``."""

    return [
        finding
        for finding in result.findings
        if not finding.location.path.startswith(_TESTS_PREFIX)
        and finding.confidence.value >= _HIGH_CONFIDENCE_VALUE
    ]


def report_suspicious(suspicious: Sequence[Finding]) -> None:
    """Print path, line and rule for each suspicious finding, never its value."""

    print("FAIL: Real credential patterns found in non-test files:", file=sys.stderr)
    for finding in suspicious:
        print(
            f"  {finding.location.path}:{finding.location.line} "
            f"{finding.rule_id} conf={finding.confidence.label}",
            file=sys.stderr,
        )


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    root = Path(args[0]) if args else Path(".")

    result = scan_with_defaults(root)
    if result.errors:
        print(
            "ERROR: scan could not read every input; refusing to approve",
            file=sys.stderr,
        )
        for error in result.errors:
            print(f"  {error.path} {error.code}", file=sys.stderr)
        return 3

    suspicious = suspicious_findings(result)
    if suspicious:
        report_suspicious(suspicious)
        return 1

    print("OK: No real credential patterns (vendor rule matches) in non-test files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
