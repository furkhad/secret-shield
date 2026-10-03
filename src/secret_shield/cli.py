"""The ``secret-shield`` command line interface.

Stage 8 puts a production interface around the scanner, the layered
configuration and the three report renderers. This module contains **no
detection logic at all**: it parses arguments, resolves configuration, calls
:func:`~secret_shield.sources.filesystem.scan_path`, hands the resulting
:class:`~secret_shield.models.ScanResult` to a renderer, and turns the result
into an exit code. Anything that decides whether a file contains a secret is
still the scanner's business, in the layers below.

Three contracts
---------------

**The exit code is the API.** CI branches on it, so
:mod:`secret_shield.exit_codes` is the single source of truth and this module
only chooses between its values. Nothing here collapses every failure into
``1``. The precedence, in the order it is decided:

==============================  ==========================================
``0``                           Nothing met the failure threshold.
``1``                           Findings at or above ``--fail-on``.
``3``                           The scan finished with errors, so the result
                                is partial. **Beats 1**: a truncated scan
                                must never be able to look like a clean one,
                                and an unreadable file must never be hidden
                                behind a findings headline.
``2``                           Bad arguments, an invalid target, or an
                                unreadable configuration file.
``4``                           An unexpected internal exception.
``130``                         Interrupted.
==============================  ==========================================

``5`` (``EXIT_NOT_IMPLEMENTED``) is not reachable from this release. Git
history scanning, SARIF and baselines are deliberately absent rather than
stubs, so there is no flag that promises them.

**stdout is the report; stderr is everything else.** A report on stdout is
pipeable: ``secret-shield scan . --format json | jq`` works, and nothing
except the report is ever written there. Warnings, per-file failures and the
"report written" confirmation go to stderr. With ``--output`` stdout stays
completely empty, so a CI job can capture stdout for its own purposes without
the report getting in the way.

**Nothing secret can reach either stream.** The renderers only ever see
:class:`~secret_shield.models.Finding` objects, which by construction cannot
hold a raw value, and they never quote a source line. This module adds three
more guarantees on top:

* Every string this module prints -- a target path, a configuration error, an
  OS message -- goes through :func:`~secret_shield.masking.strip_control_characters`
  and is folded onto one line first. A file named ``\\x1b[31mevil`` is a legal
  Linux filename, and a diagnostic that can repaint a terminal is a forged CI
  log line.
* An unexpected exception is reported by **type and location only**. Its
  message is never printed, because a message is the one string in a program
  most likely to quote something that was read from a file.
* No shell, no ``eval``, no ``exec``, no ``pickle``, and no user-supplied
  pattern is ever compiled. Argument values reach a scanner only through
  :func:`~secret_shield.config.load_config`, which type-checks and range-checks
  every one of them, so ``--jobs`` cannot become a negative thread count.

Determinism
-----------

Two runs of the same command over an unchanged tree produce byte-identical
reports, and ``--jobs 1`` and ``--jobs 8`` produce the same report as each
other. Nothing in the rendered output depends on wall-clock time, on the
machine, or on which worker finished first. Fingerprints are only stable
across runs when ``--fingerprint`` is ``sha256`` or ``hmac`` with a fixed key;
see :func:`_resolve_fingerprint`.

What this release does not have
-------------------------------

No Git history scanning, no SARIF, no baseline, no allowlists, no network
verification, and no coloured output -- the reports are deliberately plain
text, so there is no ``--no-color`` to pass. There is no flag for a custom
rule, because there is no safe way to accept one from a configuration file.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import stat
import sys
import tempfile
import textwrap
from collections.abc import Sequence
from pathlib import Path
from typing import IO, Any, Final

from .config import ENV_PREFIX, ConfigError, load_config
from .detectors.base import Rule
from .detectors.catalog import CATALOG_VERSION, default_registry
from .detectors.entropy_rule import (
    FALSE_POSITIVE_NOTES as ENTROPY_FALSE_POSITIVE_NOTES,
)
from .detectors.entropy_rule import (
    REMEDIATION as ENTROPY_REMEDIATION,
)
from .detectors.entropy_rule import (
    RULE_ID as ENTROPY_RULE_ID,
)
from .detectors.entropy_rule import (
    RULE_NAME as ENTROPY_RULE_NAME,
)
from .detectors.entropy_rule import default_entropy_config
from .exit_codes import (
    EXIT_FINDINGS,
    EXIT_INTERRUPTED,
    EXIT_INTERNAL_ERROR,
    EXIT_SCAN_ERROR,
    EXIT_SUCCESS,
    EXIT_USAGE,
)
from .filters.paths import default_path_filter_config
from .masking import strip_control_characters
from .models import TOOL_NAME, TOOL_VERSION, Confidence, ScanResult, Severity
from .report import render_json, render_markdown, render_text
from .scanner import ScanConfig
from .sources import GitScanConfig, HistoryScan, PathScanConfig, scan_history, scan_path
from .sources.git_cmd import MAX_TIMEOUT_SECONDS, MIN_TIMEOUT_SECONDS
from .sources.git_history import (
    DEFAULT_MAX_BLOBS,
    DEFAULT_MAX_BLOB_SIZE,
    DEFAULT_MAX_REFS,
)

__all__ = [
    "FINGERPRINT_KEY_ENV",
    "FORMATS",
    "build_parser",
    "main",
]


PROGRAM: Final[str] = TOOL_NAME
"""Program name used in usage text, diagnostics and ``--version``.

Fixed rather than taken from ``sys.argv[0]`` so that ``python -m
secret_shield`` and the installed ``secret-shield`` script produce byte-identical
help, version and error output. Otherwise argparse would report the program as
``__main__.py`` under one invocation and ``secret-shield`` under the other, and
a diff of two runs of "the same" command would never be empty.
"""

FORMATS: Final[tuple[str, ...]] = ("text", "json", "markdown")
"""Report renderings the CLI can select. One name per renderer."""

RENDERERS: Final[dict[str, Any]] = {
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
}

FINGERPRINT_MODES: Final[tuple[str, ...]] = ("sha256", "hmac", "none")
"""Correlation-digest modes. See ``scan --fingerprint`` in the parser."""

FINGERPRINT_KEY_ENV: Final[str] = ENV_PREFIX + "FINGERPRINT_KEY"
"""Environment variable holding the HMAC key for ``--fingerprint hmac``.

The ``SECRETSHIELD_`` prefix is what :mod:`secret_shield.config` reserves for
settings, and it rejects any variable it does not recognise. This one is not a
setting -- it is a key, and a key is not something that belongs in a committed
configuration file -- so :func:`_configuration_environ` removes it before the
configuration layer sees it. Without that, using ``--fingerprint hmac`` would
fail with "unknown setting" on a perfectly correct key.
"""

FAIL_ON_CHOICES: Final[tuple[str, ...]] = ("none",) + tuple(
    severity.label for severity in Severity
)
"""``--fail-on`` accepts every severity label, plus ``none``."""

DEFAULT_FAIL_ON: Final[str] = "low"
"""Findings at *any* severity fail the run unless the user says otherwise.

A scanner that finds something and exits 0 is a scanner CI learns to ignore.
``--fail-on none`` is the escape hatch, and ``--min-confidence`` is the other
way to keep the noise down.
"""

CONFIDENCE_CHOICES: Final[tuple[str, ...]] = tuple(
    confidence.label for confidence in Confidence
)
"""``--min-confidence`` accepts every confidence label."""

_STRICT_INTEGER: Final[re.Pattern[str]] = re.compile(r"[+-]?[0-9]+")
"""The only integer spellings accepted from the command line.

Hand-rolled to match :data:`secret_shield.config._INTEGER_PATTERN` rather than
handed to :func:`int`, which also accepts ``"1_0"``, ``" 10 "`` and a Unicode
digit. The configuration module deliberately rejects those, and a CLI that
accepted them would let an argument take a path through validation that the
same value cannot take in a file.
"""

_RULE_WIDTH: Final[int] = 78
"""Wrapping width for the ``rules list`` listing."""


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def _diagnostic(message: str) -> None:
    """Write one sanitized diagnostic line to stderr.

    Every message this process emits about its own behaviour goes through here.
    The two transformations are not cosmetic:

    * Control, format and bidirectional-override characters are removed, so a
      hostile filename cannot repaint the terminal or disguise a line.
    * All whitespace is folded to single spaces, so one diagnostic can never
      occupy two lines of a log.
    """

    safe = " ".join(strip_control_characters(message).split())
    print(f"{PROGRAM}: {safe}", file=sys.stderr)


def _use_utf8(stream: IO[str]) -> None:
    """Ask ``stream`` for UTF-8 with replacement, when it can be asked.

    A report can contain a filename, and a filename can be anything. Under a
    ``LC_ALL=C`` CI runner the default encoding is ASCII, and a single
    non-ASCII path would raise :class:`UnicodeEncodeError` *after* the scan had
    already finished -- turning a successful scan into an internal error.
    ``errors="replace"`` cannot raise, and a mangled character in a report is a
    far better outcome than a traceback.
    """

    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    try:
        reconfigure(encoding="utf-8", errors="replace")
    except (ValueError, OSError, LookupError):  # pragma: no cover - platform dependent
        pass


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _integer(text: str) -> int:
    """argparse ``type`` for a base-10 integer with no exotic spellings.

    Raises:
        argparse.ArgumentTypeError: If ``text`` is not ``[+-]?digits``.
            argparse turns that into its own usage error, which already exits
            with :data:`~secret_shield.exit_codes.EXIT_USAGE`.
    """

    if not _STRICT_INTEGER.fullmatch(text):
        # repr() rather than the bare value: it escapes control characters, so a
        # crafted argument cannot forge a line in the usage message.
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a base-10 integer such as '4096'"
        )
    return int(text)


def _positive(text: str) -> str:
    """argparse ``type`` for a path-like argument that must not be empty."""

    if not text.strip():
        raise argparse.ArgumentTypeError("path must not be empty")
    return text


_STRICT_DECIMAL: Final[re.Pattern[str]] = re.compile(
    r"[+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)"
)
"""The only decimal spellings accepted for a seconds value.

Same reasoning as :data:`_STRICT_INTEGER`: ``float()`` would also accept
``"1_0"``, ``" 1.0 "``, ``"nan"``, ``"inf"`` and a Unicode digit. ``nan`` and
``inf`` are the ones that matter here -- a timeout of ``nan`` silently disables
the very check the option exists to configure -- so the spelling is validated
rather than handed to ``float`` and compared afterwards.
"""


def _positive_float(text: str) -> float:
    """argparse ``type`` for a bounded number of seconds.

    The bounds are ``git_cmd``'s own, applied here rather than left to raise
    later: a value outside them is a mistake in the command line, so it belongs
    in the usage-error path. Validating twice would produce an internal error
    for something the user typed, which is both the wrong exit code and an
    unhelpful message.

    Raises:
        argparse.ArgumentTypeError: If ``text`` is not a finite decimal within
            ``[MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS]``.
    """

    if not _STRICT_DECIMAL.fullmatch(text):
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a number of seconds such as '30'"
        )
    value = float(text)
    if value != value or value in (float("inf"), float("-inf")):
        raise argparse.ArgumentTypeError("seconds must be a finite number")
    if not MIN_TIMEOUT_SECONDS <= value <= MAX_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(
            f"seconds must be between {MIN_TIMEOUT_SECONDS:g} and {MAX_TIMEOUT_SECONDS:g}"
        )
    return value


def _severity_threshold(text: str) -> Severity | None:
    """Parse a ``--fail-on`` value into a threshold, or ``None`` for ``none``."""

    if text == "none":
        return None
    return Severity.from_label(text)


def _confidence_threshold(text: str) -> Confidence:
    """Parse a ``--min-confidence`` value. ``-`` and ``_`` are interchangeable."""

    return Confidence.from_label(text)


_EPILOG = f"""\
exit codes:
  0    no findings at or above the failure threshold
  1    findings reached the failure threshold
  2    usage error: bad arguments, an invalid target, or bad configuration
  3    the scan finished with errors, so the result is partial
  4    internal error
  5    not implemented (no such capability in {TOOL_VERSION})
  130  interrupted

The report goes to stdout and nothing else does, so `--format json` is always
pipeable. Warnings and per-file failures go to stderr. No raw secret, and no
source line, is ever printed by either.

Examples:
  {PROGRAM} scan config/settings.py
  {PROGRAM} scan . --format json --output report.json
  {PROGRAM} scan . --jobs 8 --fail-on high --max-depth 3
  {PROGRAM} scan src --min-confidence probable --fingerprint none
  {PROGRAM} git .
  {PROGRAM} git . --max-commits 500 --format json --output history.json
  {PROGRAM} git ~/work/repo --since "2 years ago" --fail-on high
  {PROGRAM} rules list
  {PROGRAM} rules list --format json

`{PROGRAM} git` reads a repository's history, so it finds secrets in files that
were committed and then deleted -- which `{PROGRAM} scan` cannot see, because they
are no longer there to read. It checks out nothing and writes nothing.
"""


def build_parser() -> argparse.ArgumentParser:
    """Build the whole command line parser.

    Returned rather than used inline so that a test can assert on the interface
    itself -- that ``--version`` exists, that a required subcommand is required
    -- without running a scan.

    Note:
        ``prog`` is fixed to :data:`PROGRAM` so that ``python -m secret_shield``
        and the installed script produce identical text.
    """

    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "Find accidentally exposed secrets in files and directories. "
            "Detected values are always masked: the tool reports that something "
            "secret-shaped exists, never the secret itself."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {TOOL_VERSION}",
        help="print the version and exit",
    )

    commands = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    _add_scan_parser(commands)
    _add_git_parser(commands)
    _add_rules_parser(commands)
    return parser


def _add_scan_parser(commands: Any) -> None:
    """Register the ``scan`` subcommand."""

    scan = commands.add_parser(
        "scan",
        help="scan a file or a directory for secrets",
        description=(
            "Scan one file or a whole directory tree. Every analysed file is "
            "checked by every enabled rule: the vendor patterns, the context "
            "logic that supports them, and the entropy screen for values no "
            "vendor claims."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument(
        "target",
        metavar="TARGET",
        type=_positive,
        help="file or directory to scan; use '.' for the current directory",
    )

    limits = scan.add_argument_group("scan limits")
    limits.add_argument(
        "--jobs",
        type=_integer,
        default=None,
        metavar="N",
        help="worker threads, 1-64 (default 1, which is serial and deterministic)",
    )
    limits.add_argument(
        "--max-file-size",
        type=_integer,
        default=None,
        metavar="N",
        help="largest file read, in bytes (default 10485760)",
    )
    limits.add_argument(
        "--max-files",
        type=_integer,
        default=None,
        metavar="N",
        help="most files one scan will read before stopping (default 100000)",
    )
    limits.add_argument(
        "--max-depth",
        type=_integer,
        default=None,
        metavar="N",
        help="deepest directory level to descend; 0 scans only the root's own files",
    )
    limits.add_argument(
        "--max-line-length",
        type=_integer,
        default=None,
        metavar="N",
        help="longest line handed to entropy analysis, in characters (default 65536)",
    )
    limits.add_argument(
        "--follow-symlinks",
        action="store_true",
        default=None,
        help=(
            "follow symbolic links found inside a scanned directory; even then, "
            "a link resolving outside the root is skipped"
        ),
    )

    _add_reporting_arguments(scan)

    configuration = scan.add_argument_group("configuration")
    configuration.add_argument(
        "--project-root",
        metavar="DIR",
        type=_positive,
        help=(
            "directory to resolve configuration from (default: the current "
            "directory). Reads pyproject.toml [tool.secretshield], then "
            ".secretshield.toml, then .secretshield.json, then SECRETSHIELD_* "
            "environment variables. Command line options win over all of them."
        ),
    )


def _add_reporting_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the output and exit-status options shared by the scanners.

    One definition for both ``scan`` and ``git``, so the two cannot drift into
    disagreeing about what ``--format json`` means or which exit code a partial
    result produces. A user who learns ``--fail-on`` from ``scan`` gets the same
    behaviour from ``git`` for free, which is the point of sharing rather than
    copying.
    """

    output = parser.add_argument_group("output")
    output.add_argument(
        "--format",
        choices=FORMATS,
        default="text",
        help="report rendering (default: text)",
    )
    output.add_argument(
        "--output",
        metavar="FILE",
        type=_positive,
        help=(
            "write the report to FILE instead of stdout, replacing it "
            "atomically with owner-only permissions; stdout then stays empty"
        ),
    )
    output.add_argument(
        "--fingerprint",
        choices=FINGERPRINT_MODES,
        default="sha256",
        help=(
            "correlation digest for findings: 'sha256' (default) is an unkeyed "
            "digest; 'hmac' keys it with $" + FINGERPRINT_KEY_ENV + " so a "
            "low-entropy value cannot be brute-forced from a published report, "
            "at the cost of digests differing when the key changes; 'none' "
            "omits the digest from the report entirely"
        ),
    )
    output.add_argument(
        "--min-confidence",
        type=_confidence_threshold,
        default=Confidence.CANDIDATE,
        metavar="LABEL",
        help=(
            "report only findings at or above this confidence: "
            + ", ".join(CONFIDENCE_CHOICES)
            + " ('-' and '_' are interchangeable). Default: "
            + Confidence.CANDIDATE.label
        ),
    )

    reporting = parser.add_argument_group("exit status")
    reporting.add_argument(
        "--fail-on",
        type=_severity_threshold,
        default=_severity_threshold(DEFAULT_FAIL_ON),
        metavar="LEVEL",
        help=(
            "lowest severity that makes the run exit 1: "
            + ", ".join(FAIL_ON_CHOICES)
            + ". Default: "
            + DEFAULT_FAIL_ON
            + ", meaning any reported finding fails"
        ),
    )


def _add_git_parser(commands: Any) -> None:
    """Register the ``git`` subcommand.

    A separate subcommand rather than a ``scan --git`` flag, because the two do
    genuinely different things and share no limits worth sharing. ``scan`` reads
    the files that are present now and its limits are about a filesystem:
    directory depth, symlinks, file counts. ``git`` reads objects that may not
    exist on disk at all and its limits are about a commit graph and an object
    database: how many commits to walk, how many distinct blobs to read, how
    large a blob may be. Folding one into the other as a flag would mean every
    ``scan`` invocation carried a dozen options that do nothing unless a
    repository happened to be underneath it.
    """

    git = commands.add_parser(
        "git",
        help="scan a repository's history for secrets that were removed",
        description=(
            "Scan every blob reachable from HEAD, including content that was "
            "committed and then deleted. Nothing is checked out, written or "
            "fetched: the working tree, the index and HEAD are exactly as they "
            "were before the scan.\n\n"
            "Each distinct blob is read once no matter how many commits or paths "
            "it appeared at, and each finding names the newest commit in which "
            "that content was present at that path. Objects are reachable from "
            "HEAD only, and only SHA-1 repositories are supported."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    git.add_argument(
        "target",
        metavar="TARGET",
        type=_positive,
        help="repository to scan; use '.' for the current directory",
    )

    limits = git.add_argument_group("history limits")
    limits.add_argument(
        "--max-commits",
        type=_integer,
        default=None,
        metavar="N",
        help="stop after this many commits; the newest are scanned first (default: all)",
    )
    limits.add_argument(
        "--max-blobs",
        type=_integer,
        default=None,
        metavar="N",
        help=f"most distinct objects to read (default {DEFAULT_MAX_BLOBS})",
    )
    limits.add_argument(
        "--max-refs",
        type=_integer,
        default=None,
        metavar="N",
        help="most distinct file paths to index (default %d)" % DEFAULT_MAX_REFS,
    )
    limits.add_argument(
        "--max-blob-size",
        type=_integer,
        default=None,
        metavar="N",
        help=f"largest blob read into memory, in bytes (default {DEFAULT_MAX_BLOB_SIZE})",
    )
    limits.add_argument(
        "--max-line-length",
        type=_integer,
        default=None,
        metavar="N",
        help="longest line handed to entropy analysis, in characters (default 65536)",
    )
    limits.add_argument(
        "--timeout",
        type=_positive_float,
        default=None,
        metavar="SECONDS",
        help=(
            "wall-clock limit for each Git command, so a hung Git is killed "
            f"rather than waited on, {MIN_TIMEOUT_SECONDS:g}-"
            f"{MAX_TIMEOUT_SECONDS:g} seconds (default 300)"
        ),
    )
    limits.add_argument(
        "--since",
        default=None,
        metavar="WHEN",
        help='only commits at or after this date, e.g. "2 years ago" or 2024-01-01',
    )
    limits.add_argument(
        "--until",
        default=None,
        metavar="WHEN",
        help="only commits at or before this date",
    )
    limits.add_argument(
        "--respect-path-filters",
        action="store_true",
        default=False,
        help=(
            "skip the dependency, cache and build paths 'scan' skips by "
            "default (node_modules, .venv, __pycache__ and the rest), and no "
            "others. Off by default: a path ignored today may not have been "
            "ignored when the secret was committed"
        ),
    )

    _add_reporting_arguments(git)


def _add_rules_parser(commands: Any) -> None:
    """Register the ``rules list`` subcommand."""

    rules = commands.add_parser(
        "rules",
        help="inspect the detection rules that are registered",
        description="Inspect the rules SecretShield applies.",
    )
    rules_commands = rules.add_subparsers(
        dest="rules_command", metavar="ACTION", required=True
    )

    listing = rules_commands.add_parser(
        "list",
        help="list every registered rule and how it behaves",
        description=(
            "List every registered rule with its category, severity, base "
            "confidence, specificity, known false positives and remediation. "
            "Patterns are never printed, and no example credential is shown, so "
            "the output is safe to paste into an issue."
        ),
        epilog=(
            "Rules are disabled through configuration, not through a flag: put "
            'rules.disabled = ["<rule-id>"] in .secretshield.toml. '
            "This listing always describes the shipped catalog.\n\n" + _EPILOG
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    listing.add_argument(
        "--format",
        choices=FORMATS,
        default="text",
        help="listing rendering (default: text)",
    )


# ---------------------------------------------------------------------------
# Argument values
# ---------------------------------------------------------------------------


#: Each command line limit is the same value as a Stage 5 configuration setting.
#: The mapping is written out rather than derived, because a wrong mapping would
#: silently apply a limit the user did not ask for -- and the setting name is the
#: one thing the user can look up.
_CLI_TO_SETTING: Final[tuple[tuple[str, str], ...]] = (
    ("jobs", "scan.jobs"),
    ("max_file_size", "scan.max_file_size"),
    ("max_files", "scan.max_files"),
    ("max_line_length", "scan.max_line_length"),
    ("max_depth", "paths.max_depth"),
    ("follow_symlinks", "paths.follow_symlinks"),
)

_GIT_TO_SETTING: Final[tuple[tuple[str, str], ...]] = (
    ("max_commits", "max_commits"),
    ("max_blobs", "max_blobs"),
    ("max_refs", "max_refs"),
    ("max_blob_size", "max_blob_size"),
    ("max_line_length", "max_line_length"),
    ("timeout", "timeout"),
    ("since", "since"),
    ("until", "until"),
)
"""``git`` command line options mapped onto :class:`GitScanConfig` fields.

Named, and referenced by :func:`_git_scan_config`, so that adding an option
means adding one pair here rather than writing another positional call that can
transpose two same-typed limits without the reader noticing.
"""


def _overrides(args: argparse.Namespace) -> dict[str, object]:
    """Return only the settings the user actually named on the command line.

    Every one of them is handed to :func:`~secret_shield.config.load_config` as
    the highest-precedence ``overrides`` layer rather than assigned onto a
    config object afterwards. That is the whole point: the CLI cannot invent a
    value the configuration schema would have rejected, and ``--jobs 0`` fails
    with the same message and the same exit code as ``jobs = 0`` in a file.

    An option left at its ``None`` default contributes nothing, so a
    configuration file is never silently overridden by a default the user did
    not type.
    """

    values: dict[str, object] = {}
    for attribute, key in _CLI_TO_SETTING:
        value = getattr(args, attribute)
        if value is not None:
            values[key] = value
    return values


def _configuration_environ() -> dict[str, str]:
    """Return the environment with this CLI's own variables removed.

    :func:`~secret_shield.config.load_config` treats an unrecognised
    ``SECRETSHIELD_*`` variable as a hard error, which is the correct default
    for a settings namespace. The HMAC key is not a setting, so it is removed
    here rather than made an exception in the configuration layer.
    """

    return {
        name: value
        for name, value in os.environ.items()
        if name not in (FINGERPRINT_KEY_ENV,)
    }


class _UsageError(Exception):
    """A command line value cannot be used. Reported as a usage error."""


def _resolve_fingerprint(args: argparse.Namespace) -> tuple[bytes | None, bool]:
    """Return ``(hmac_key, include_fingerprint)`` for ``--fingerprint``.

    Args:
        args: Parsed ``scan`` arguments.

    Returns:
        The key to use when building findings, and whether the rendered report
        should carry each finding's correlation digest.

    Raises:
        _UsageError: If ``--fingerprint hmac`` was requested without a key.

    Note:
        ``hmac`` has no random default, on purpose. A per-run random key would
        make two runs of the same command disagree, which defeats the
        determinism every other part of the tool keeps; requiring the key means
        the digest is reproducible *because the operator chose it*, and a
        forgotten key is a loud usage error rather than a silent loss of
        cross-run correlation.
    """

    mode = args.fingerprint
    if mode == "sha256":
        return None, True
    if mode == "none":
        return None, False

    raw = os.environ.get(FINGERPRINT_KEY_ENV, "")
    if not raw:
        raise _UsageError(
            f"--fingerprint hmac needs a key: set {FINGERPRINT_KEY_ENV} to a "
            "non-empty value. Its UTF-8 bytes are the HMAC-SHA-256 key. Keep it "
            "out of version control; the same key must be reused for digests to "
            "be comparable between runs."
        )
    return raw.encode("utf-8"), True


def _apply_fingerprint_key(
    settings: PathScanConfig, key: bytes | None
) -> PathScanConfig:
    """Return ``settings`` with ``key`` installed, or unchanged for ``None``.

    ``ScanConfig`` validates the key's type and emptiness, so an unusable one
    fails here as a :class:`TypeError` or :class:`ValueError` from the class that
    owns the rule rather than as a scan-time crash from :mod:`hmac`.
    """

    if key is None:
        return settings
    return dataclasses.replace(
        settings, scan=dataclasses.replace(settings.scan, fingerprint_key=key)
    )


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------


def _invalid_target(target: str) -> str | None:
    """Return why ``target`` cannot be scanned, or ``None`` if it can.

    The scanner would rather collect this as a :class:`ScanError` than raise,
    which is right for a thousand files and wrong for the one path the user
    typed. A mistyped target is a usage error, reported before any work starts
    and with an empty stdout, so a CI pipeline fails with a message instead of a
    report about nothing.

    Only ``OSError.strerror`` and the exception class name are ever surfaced;
    the path itself is sanitized separately by the caller.
    """

    try:
        info = os.stat(target)
    except FileNotFoundError:
        return "no such file or directory"
    except NotADirectoryError:
        return "a path component is not a directory"
    except PermissionError:
        return "permission denied"
    except OSError as exc:
        detail = strip_control_characters(exc.strerror or type(exc).__name__)
        return f"cannot read metadata ({detail})"

    if stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode):
        return None
    # Sockets, FIFOs and devices are refused rather than scanned: opening a FIFO
    # blocks until a writer appears, and a device offers no bound on a read.
    return "not a regular file or directory"


# ---------------------------------------------------------------------------
# Writing the report
# ---------------------------------------------------------------------------


class _OutputError(Exception):
    """The report could not be written.

    ``usage`` marks a structurally impossible destination -- a missing directory
    or a path that is not a file -- which is a mistake in the command line and
    therefore :data:`~secret_shield.exit_codes.EXIT_USAGE`. Everything else, such
    as a permission denied at write time, is a failure of work the scan had
    already finished, and is :data:`~secret_shield.exit_codes.EXIT_SCAN_ERROR`.
    """

    def __init__(self, message: str, *, usage: bool) -> None:
        super().__init__(message)
        self.usage = usage


def _write_report(destination: Path, report: str) -> None:
    """Write ``report`` to ``destination`` atomically and privately.

    The file is created under a temporary name in the destination's own
    directory, written, flushed, ``fsync``-ed, given mode ``0600``, and only
    then moved into place with :func:`os.replace`. Three properties follow, and
    all three matter for a report about secrets:

    * **An existing report is never corrupted.** A full disk, a closed pipe or a
      full quota fails on the temporary file, and the previous report is still
      exactly where it was. :func:`os.replace` itself is atomic, so a reader
      never sees a half-written report even momentarily.
    * **The report is never world-readable,** not even briefly: the temporary
      file is created with ``mkstemp`` (mode ``0600``) and the mode is set
      explicitly before the rename, so a permissive umask cannot widen it.
    * **A symlink at the destination is replaced, not followed**, because
      ``replace`` acts on the name. A report cannot be redirected into someone
      else's file by a planted link.

    Raises:
        _OutputError: If the destination is unusable or the write failed.
    """

    parent = destination.parent if str(destination.parent) else Path(".")
    if not parent.is_dir():
        raise _OutputError(
            f"output directory {_one_line(str(parent))} does not exist", usage=True
        )
    if destination.is_dir():
        raise _OutputError(
            f"output path {_one_line(str(destination))} is a directory", usage=True
        )
    if destination.exists() and not destination.is_file():
        raise _OutputError(
            f"output path {_one_line(str(destination))} is not a regular file",
            usage=True,
        )

    try:
        # mkstemp returns an already-open descriptor with 0600, which is the only
        # reason this is safe: a plain open() would create the file under the
        # process umask first and tighten it afterwards, if at all.
        handle, temporary = tempfile.mkstemp(
            dir=str(parent), prefix=".secret-shield-", suffix=".tmp"
        )
    except OSError as exc:
        raise _OutputError(
            f"cannot create a temporary file in {_one_line(str(parent))} "
            f"({_one_line(exc.strerror or type(exc).__name__)})",
            usage=False,
        ) from None

    temporary_path = Path(temporary)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(report)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, destination)
    except OSError as exc:
        # Best effort: the temporary file may already be gone if replace()
        # succeeded and something after it did not.
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise _OutputError(
            f"cannot write {_one_line(str(destination))} "
            f"({_one_line(exc.strerror or type(exc).__name__)}); "
            "any previous report was left untouched",
            usage=False,
        ) from None


def _one_line(text: str) -> str:
    """Strip control characters and fold whitespace, for a diagnostic."""

    return " ".join(strip_control_characters(str(text)).split())


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _apply_min_confidence(result: ScanResult, threshold: Confidence) -> ScanResult:
    """Drop findings below ``threshold`` so the report states only what it shows.

    The filter runs *before* rendering rather than being left to the reader, so
    the counts in the summary always describe the findings actually listed. A
    report claiming three findings while showing one would be a report nobody can
    check.
    """

    kept = tuple(
        finding for finding in result.findings if finding.confidence >= threshold
    )
    if len(kept) == len(result.findings):
        return result
    return dataclasses.replace(result, findings=kept)


def _exit_code(result: ScanResult, fail_on: Severity | None) -> int:
    """Return the exit code for a completed scan.

    Errors are checked before findings. A scan that could not read every input
    describes a partial tree, and reporting that as ``1`` would let a truncated
    scan pass a pipeline that only distinguishes ``0`` from ``1``.
    """

    if result.errors:
        return EXIT_SCAN_ERROR
    if fail_on is None:
        return EXIT_SUCCESS
    if any(finding.severity >= fail_on for finding in result.findings):
        return EXIT_FINDINGS
    return EXIT_SUCCESS


def _report_errors(result: ScanResult) -> None:
    """Summarise partial failures on stderr.

    The report itself already carries the detail -- an ``errors`` array in JSON,
    an ``ERRORS`` section in text -- but a report redirected to a file must not
    be able to hide the fact that it is incomplete from the CI job that is
    watching stderr.
    """

    if not result.errors:
        return
    count = len(result.errors)
    plural = "" if count == 1 else "s"
    codes = sorted({error.code or "unknown" for error in result.errors})
    _diagnostic(
        f"{count} input{plural} could not be read ({', '.join(codes)}); "
        "the report lists each one. The result is partial."
    )


def _render_and_write(
    args: argparse.Namespace, result: ScanResult, *, include_fingerprint: bool
) -> int | None:
    """Render ``result`` and put it where ``--output`` says, or on stdout.

    Returns:
        ``None`` when the report was written, or the exit code to return when it
        could not be. The caller still has to add the summary diagnostics and
        the finding exit code; only the write failure is reported here, because
        nothing else has happened at that point.
    """

    report = RENDERERS[args.format](result, include_fingerprint=include_fingerprint)

    destination = Path(args.output) if args.output else None
    if destination is None:
        sys.stdout.write(report)
        sys.stdout.flush()
        return None

    try:
        _write_report(destination, report)
    except _OutputError as exc:
        _diagnostic(str(exc))
        return EXIT_USAGE if exc.usage else EXIT_SCAN_ERROR
    _diagnostic(f"wrote {_one_line(str(destination))} (mode 0600)")
    return None


def _command_scan(args: argparse.Namespace) -> int:
    """Run ``secret-shield scan`` and return its exit code."""

    target = args.target
    problem = _invalid_target(target)
    if problem is not None:
        _diagnostic(f"cannot scan {_one_line(target)}: {problem}")
        return EXIT_USAGE

    try:
        fingerprint_key, include_fingerprint = _resolve_fingerprint(args)
    except _UsageError as exc:
        _diagnostic(str(exc))
        return EXIT_USAGE

    try:
        project_root = Path(args.project_root) if args.project_root else Path.cwd()
    except OSError as exc:
        _diagnostic(
            f"cannot determine the configuration root ({_one_line(exc.strerror or type(exc).__name__)})"
        )
        return EXIT_USAGE

    try:
        config = load_config(
            project_root=project_root,
            overrides=_overrides(args),
            environ=_configuration_environ(),
        )
    except ConfigError as exc:
        # ConfigError already strips control characters from its own message,
        # and never quotes the contents of the file it rejected.
        _diagnostic(f"configuration error: {exc}")
        return EXIT_USAGE

    settings = _apply_fingerprint_key(config.path_scan, fingerprint_key)
    result = _apply_min_confidence(scan_path(target, settings), args.min_confidence)

    failure = _render_and_write(args, result, include_fingerprint=include_fingerprint)
    if failure is not None:
        return failure

    _report_errors(result)
    return _exit_code(result, args.fail_on)


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------


def _not_a_directory(target: str) -> str | None:
    """Return why ``target`` cannot be a repository, or ``None`` if it can be.

    A Git repository is a directory: the non-bare form contains a ``.git``
    directory, and the bare form *is* one. A regular file never is, and pointing
    ``git`` at one is a mistake worth naming rather than a scan to attempt --
    ``git -C somefile rev-parse`` would answer "not a repository" anyway, but
    three layers down and without the path the user typed.
    """

    try:
        info = os.stat(target)
    except OSError:
        # ``_invalid_target`` already reported this; returning the same kind of
        # answer keeps the caller from needing two checks.
        return "no such file or directory"
    if stat.S_ISDIR(info.st_mode):
        return None
    return "a Git repository is a directory"


def _git_scan_config(
    args: argparse.Namespace, fingerprint_key: bytes | None
) -> GitScanConfig:
    """Build a :class:`GitScanConfig` from ``git`` command line arguments.

    Every option left at its ``None`` default contributes nothing, so a setting
    the user did not type cannot silently override :data:`DEFAULT_GIT_SCAN_CONFIG`
    -- the same rule :func:`_overrides` follows for ``scan``.

    The ``git`` subcommand deliberately does **not** read configuration files.
    The settings that shape a history scan -- ``max_commits``, ``max_blobs``,
    ``since`` -- are arguments about a particular investigation, and a value
    pinned in ``pyproject.toml`` months ago would decide which commits are
    examined without anyone remembering they had asked for that. Argument errors
    surface as :class:`ValueError` from the config's own validation and become
    exit code 2, exactly as they would in a file.
    """

    chosen: dict[str, object] = {}
    for attribute, keyword in _GIT_TO_SETTING:
        value = getattr(args, attribute)
        if value is not None:
            chosen[keyword] = value

    scan = ScanConfig()
    if fingerprint_key is not None:
        scan = dataclasses.replace(scan, fingerprint_key=fingerprint_key)

    return GitScanConfig(
        scan=scan,
        path_filters=default_path_filter_config()
        if args.respect_path_filters
        else None,
        **chosen,  # type: ignore[arg-type]
    )


def _report_history_coverage(scan: HistoryScan) -> None:
    """State, on stderr, what a history scan could not look at.

    The report says what was *found*; it has no field for what was skipped,
    because "0 findings" and "nothing was searched" must not look the same. This
    line is where the difference is stated. Skipped binary objects are named
    because they are the common case and a user deserves to know the scan was
    not claiming more than it did.

    One line, on stderr and never on stdout, and only when there is something
    to disclose. That silence is safe rather than merely quiet: the line appears
    precisely when part of the history was *not* examined, so its absence means
    the scan looked at everything reachable from ``HEAD`` and the report's
    finding count is the whole story.
    """

    notes: list[str] = []
    if scan.truncated:
        notes.append(
            "history NOT examined in full (" + "; ".join(scan.truncated_because) + ")"
        )
    if scan.paths_filtered:
        notes.append(f"{scan.paths_filtered} path(s) skipped by --respect-path-filters")
    if scan.blobs_binary:
        notes.append(f"{scan.blobs_binary} binary object(s) not searched")
    if scan.blobs_too_large:
        notes.append(f"{scan.blobs_too_large} object(s) over the size limit not read")
    if not notes:
        return
    _diagnostic(
        f"walked {scan.commits} commit(s); searched {scan.blobs_scanned} of "
        f"{scan.blobs_seen} distinct object(s). " + "; ".join(notes) + "."
    )


def _command_git(args: argparse.Namespace) -> int:
    """Run ``secret-shield git`` and return its exit code."""

    target = args.target
    problem = _invalid_target(target) or _not_a_directory(target)
    if problem is not None:
        _diagnostic(f"cannot scan {_one_line(target)}: {problem}")
        return EXIT_USAGE

    try:
        fingerprint_key, include_fingerprint = _resolve_fingerprint(args)
    except _UsageError as exc:
        _diagnostic(str(exc))
        return EXIT_USAGE

    try:
        config = _git_scan_config(args, fingerprint_key)
    except (TypeError, ValueError) as exc:
        # Raised by ``GitScanConfig.__post_init__``: a hostile ``--since``, a
        # zero ``--timeout``. These are mistakes in the command line, not
        # properties of a repository, so they are usage errors.
        _diagnostic(_one_line(str(exc)))
        return EXIT_USAGE

    scan = scan_history(target, config)
    result = _apply_min_confidence(scan.result, args.min_confidence)

    failure = _render_and_write(args, result, include_fingerprint=include_fingerprint)
    if failure is not None:
        return failure

    _report_errors(result)
    _report_history_coverage(scan)
    return _exit_code(result, args.fail_on)


# ---------------------------------------------------------------------------
# rules list
# ---------------------------------------------------------------------------


def _rule_entry(
    rule_id: str,
    name: str,
    *,
    category: str,
    severity: str,
    base_confidence: str,
    specificity: str,
    detector: str,
    false_positive_notes: str,
    remediation: str,
) -> dict[str, str]:
    """Build one listing entry with a fixed key order."""

    return {
        "id": rule_id,
        "name": _one_line(name),
        "category": category,
        "severity": severity,
        "base_confidence": base_confidence,
        "specificity": specificity,
        "detector": detector,
        "false_positive_notes": _one_line(false_positive_notes),
        "remediation": _one_line(remediation),
    }


def _rule_entry_from(rule: Rule) -> dict[str, str]:
    """Describe one catalog rule."""

    return _rule_entry(
        rule.id,
        rule.name,
        category=rule.category.value,
        severity=rule.severity.label,
        base_confidence=rule.confidence_floor.label,
        specificity=rule.specificity.value,
        detector="pattern",
        false_positive_notes=rule.false_positive_notes,
        remediation=rule.remediation,
    )


def _entropy_rule_entry() -> dict[str, str]:
    """Describe the entropy rule.

    It is not in the vendor catalog -- it has no pattern to register -- but it
    does produce findings, so omitting it would make this listing a list of the
    rules a reader cannot account for in a report. Its severity is read from the
    shipped entropy configuration rather than written here, so the listing
    cannot drift from what a scan would actually produce.
    """

    entropy = default_entropy_config()
    return _rule_entry(
        ENTROPY_RULE_ID,
        ENTROPY_RULE_NAME,
        category="unknown",
        severity=entropy.severity_ceiling.label,
        base_confidence=Confidence.PROBABLE.label,
        specificity="heuristic",
        detector="entropy",
        false_positive_notes=ENTROPY_FALSE_POSITIVE_NOTES,
        remediation=ENTROPY_REMEDIATION,
    )


def _rule_entries() -> tuple[dict[str, str], ...]:
    """Return every registered rule, in a stable order.

    Catalog rules come first in the registry's own evaluation order, which is
    ``(priority, id)`` -- a property of the data, not of this file. The entropy
    rule follows, because it is a different kind of detector rather than a
    lower-priority vendor rule.
    """

    entries = [_rule_entry_from(rule) for rule in default_registry().rules()]
    entries.append(_entropy_rule_entry())
    return tuple(entries)


def _render_rules_text(entries: Sequence[dict[str, str]]) -> str:
    """Render the rule listing for a human, one wrapped block per rule."""

    lines = [
        f"{PROGRAM} {TOOL_VERSION} - registered detection rules",
        f"catalog version {CATALOG_VERSION}",
        "",
    ]
    for entry in entries:
        lines.append(entry["id"])
        lines.append(_field("name", entry["name"], first=True))
        lines.append(_field("category", entry["category"]))
        lines.append(_field("severity", entry["severity"]))
        lines.append(_field("base confidence", entry["base_confidence"]))
        lines.append(_field("specificity", entry["specificity"]))
        lines.append(_field("detector", entry["detector"]))
        lines.append(
            _field(
                "false positives", entry["false_positive_notes"] or "(none recorded)"
            )
        )
        lines.append(_field("remediation", entry["remediation"] or "(none recorded)"))
        lines.append("")
    lines.append(
        f"{len(entries) - 1} catalog rules and 1 entropy rule. Patterns are not "
        "listed: a pattern is detection logic, not documentation, and printing "
        "it invites copying it into an allowlist that will silently stop "
        "matching when the rule changes."
    )
    return "\n".join(lines) + "\n"


def _field(label: str, value: str, *, first: bool = False) -> str:
    """Format one listing field, wrapped to :data:`_RULE_WIDTH`."""

    cleaned = _one_line(value)
    if not cleaned:
        return f"  {label:<18}: (none recorded)"
    if first:
        return f"  {label:<18}: {cleaned}"
    return textwrap.fill(
        cleaned,
        width=_RULE_WIDTH,
        initial_indent=f"  {label:<18}: ",
        subsequent_indent=" " * 21,
        break_on_hyphens=False,
    )


def _render_rules_json(entries: Sequence[dict[str, str]]) -> str:
    """Render the rule listing as deterministic JSON."""

    payload = {
        "schema_version": "1.0",
        "tool": {"name": PROGRAM, "version": TOOL_VERSION},
        "catalog_version": CATALOG_VERSION,
        "rule_count": len(entries),
        "rules": [dict(entry) for entry in entries],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _command_rules_list(args: argparse.Namespace) -> int:
    """Run ``secret-shield rules list`` and return its exit code."""

    entries = _rule_entries()
    if args.format == "json":
        sys.stdout.write(_render_rules_json(entries))
    else:
        sys.stdout.write(_render_rules_text(entries))
    sys.stdout.flush()
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_HANDLERS: Final[dict[str, Any]] = {
    ("scan", None): _command_scan,
    ("git", None): _command_git,
    ("rules", "list"): _command_rules_list,
}


def _dispatch(args: argparse.Namespace) -> int:
    """Send parsed arguments to the handler for the chosen subcommand."""

    handler = _HANDLERS[(args.command, getattr(args, "rules_command", None))]
    return handler(args)


def _describe_exception(exc: BaseException) -> str:
    """Describe an unexpected exception without repeating anything it says.

    The message of an exception raised deep inside the scanner may quote a value
    that came from a file. It is therefore never printed; the type and the place
    it happened are enough to locate the bug and cannot leak scanned content.
    """

    frame = exc.__traceback__
    where = "unknown"
    while frame is not None and frame.tb_next is not None:
        frame = frame.tb_next
    if frame is not None:
        where = f"{frame.tb_frame.f_code.co_name}"
    return _one_line(f"{type(exc).__name__} raised in {where}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface and return an exit code.

    Args:
        argv: Arguments without the program name. ``None`` means ``sys.argv[1:]``.

    Returns:
        One of the values in :mod:`secret_shield.exit_codes`. Never raises for a
        bad command line, a failed scan or an interrupted run: this is the outer
        boundary of the process, and an uncaught traceback is both a worse
        message and a worse exit code than any of them.
    """

    _use_utf8(sys.stdout)
    _use_utf8(sys.stderr)

    parser = build_parser()
    try:
        args = parser.parse_args(None if argv is None else [str(item) for item in argv])
    except SystemExit as exc:
        # argparse has already written help to stdout or a usage error to
        # stderr, and its error code is already EXIT_USAGE.
        code = exc.code
        if code is None:
            return EXIT_SUCCESS
        return code if isinstance(code, int) else EXIT_USAGE

    try:
        return _dispatch(args)
    except KeyboardInterrupt:
        _diagnostic("interrupted before the scan finished; no report was produced")
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        # `secret-shield scan . --format json | head -1` closes the pipe early.
        # The scan succeeded; delivering the whole report did not, and exit 0
        # would claim a complete result nobody received.
        _use_utf8(sys.stderr)
        try:
            sys.stderr.close()
        except OSError:
            pass
        return EXIT_SCAN_ERROR
    except Exception as exc:  # noqa: BLE001 - the process boundary
        _diagnostic(f"internal error: {_describe_exception(exc)}")
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":  # pragma: no cover - exercised via __main__.py
    raise SystemExit(main())
