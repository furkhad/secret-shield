"""The Git history source: find secrets that were committed and then removed.

A repository is not a tree. The file a credential was pasted into may have been
deleted in the very next commit, and the credential is still there, still in the
object database, still fetchable by anyone who clones. ``secret-shield scan``
cannot see that -- it reads the files that are present now. This module reads the
ones that are not.

No process handling lives here
------------------------------

This module does not import :mod:`subprocess` and does not know what a command
line is. It asks :mod:`secret_shield.sources.git_cmd` for object *names* and for
object *bytes*, and receives them. Every guarantee about how Git is invoked --
``shell=False``, an explicit timeout, a scrubbed environment, ``--no-pager``,
``--no-replace-objects``, and above all the promise that no writing subcommand is
ever constructed -- belongs to that module and is checked there. Keeping the
split here is the reason an auditor can answer "could a hostile repository make
this run something?" by reading one file.

Why blobs, and why not ``log -p``
---------------------------------

Git stores content, not files. The same blob can be the current contents of
``config.py`` and the contents of ``old/config.yml`` and the contents of a file
deleted two years ago. A history scan that walked diffs would decompress and
rescan that content once per appearance.

So the shape of the scan is:

1. ``git log --raw`` (:class:`~secret_shield.sources.git_cmd.HistoryWalk`) says
   which blob each commit put at which path. This is a **names-only** pass: Git
   never sends file content here, so the cost is a few hundred bytes per commit
   no matter how large the repository is.
2. The references are reduced to the set of *distinct blobs*, keeping every path
   each one was seen at. This is the deduplication step, and it is the difference
   between a scan that reads a repository once and one that reads it as many
   times as it has commits.
3. ``git cat-file --batch-check`` gives each distinct blob's type and size, so a
   2 GiB object in the history is skipped without a content byte moving.
4. ``git cat-file --batch`` returns the contents of the survivors, once each,
   and each is scanned exactly once.

A secret committed and then deleted is found at step 4, attributed to the commit
that introduced it, even though nothing on disk mentions it.

What is deliberately *not* done
-------------------------------

* **Today's ignore rules are not applied to history.** A file committed in 2019
  and deleted in 2020 is not covered by the ``.gitignore`` that exists today, and
  applying today's rules to it would hide exactly the committed-then-deleted
  secrets this module exists to find. Path filters are available through
  :attr:`GitScanConfig.path_filters`, and are off unless asked for.
* **Nothing is checked out.** No branch is created, no worktree is written, no
  ref moves. The working tree, the index and ``HEAD`` are exactly as they were
  before the scan, which :mod:`~secret_shield.sources.git_cmd` guarantees by
  never constructing a writing subcommand.
* **Only blobs are read.** Commits, trees and tags carry no user content worth
  scanning, and skipping them keeps the object pass cheap.
* **Git's own stderr is never shown.** It is discarded in
  :mod:`~secret_shield.sources.git_cmd`, so nothing a repository puts in a commit
  message reaches a SecretShield report.

One finding per (blob, path), not one per commit
------------------------------------------------

A secret that sat in ``settings.py`` across two hundred commits is one secret at
one path, and reporting it two hundred times would bury the report. Each
``(blob, path)`` pair therefore produces its findings once, attributed to the
**newest** commit in which that blob appeared at that path -- the commit a user
would run ``git show`` against. :attr:`BlobRecord.occurrences` counts how many
commits the content was seen in, so a caller can say "present in 200 commits"
without listing 200 locations. The trade-off is explicit rather than hidden: the
full commit list for a finding is not in the report.

What is counted rather than reported
------------------------------------

Skipped blobs appear in :class:`HistoryScan` counters, not in ``errors``. Most
repositories contain far more images, archives and lockfiles than secrets, and a
per-object error list would be unusable noise -- worse, it would make
``errors`` non-empty on essentially every repository, which the CLI turns into
exit code 3 on every clean scan. A *binary blob* is a decision this module made
correctly; a *missing object* is a failure, and that one is an error.

Truncation is the exception that proves the rule. If a limit stopped the scan
early, the result is partial and cannot be presented as clean, so it carries a
``history-truncated`` error naming every limit that fired.

Known limits
------------

* **SHA-256 repositories are refused.** ``extensions.objectFormat = sha256``
  exists; this module does not support it. The refusal is explicit and tested
  rather than a silent partial scan:
  :mod:`~secret_shield.sources.git_cmd` raises a
  :class:`~secret_shield.sources.git_cmd.GitError` whose kind is
  ``unsupported-object-format``, and this module turns that into a
  :class:`~secret_shield.models.ScanError` with the same ``code``, no findings
  and exit code 3. Supporting it means widening the object-name parsers in
  ``git_cmd`` from 40 to 64 characters, which is deliberately not faked by
  pattern-matching around the code that already exists.
* **Blameless by commit.** Findings carry the commit where the content *was*,
  never the author, because "who wrote this secret" is an access-control
  question that a log line has no business answering.
* **Reachable objects only.** ``rev-list``-style walks start at ``HEAD``, so a
  secret in an unreachable object -- one orphaned by a ``git gc`` that has not
  run yet, or one reachable only from a ref that no longer exists -- is not
  found. That is the same set of objects anyone who clones the repository would
  receive, which is the useful boundary.
* **Per-command timeout, not a per-scan one.** ``timeout`` bounds each Git
  command. A scan of a large repository legitimately runs for minutes, so a
  whole-scan deadline would be the wrong control; what the per-command limit
  prevents is a *hung* Git, which is killed rather than waited on.
* **Text only, as everywhere else.** Binary blobs are classified and counted,
  never scanned.
"""

from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..detectors import DetectorRegistry, find_matches, findings_from
from ..detectors import detect as detect_entropy
from ..detectors.catalog import default_registry
from ..filters.binary import BinaryConfig, classify_bytes
from ..filters.paths import PathFilterConfig, normalize_relative_path
from ..masking import strip_control_characters
from ..models import TOOL_VERSION, Finding, ScanError, ScanResult, SourceKind
from ..pipeline import analyze_text
from ..scanner import ScanConfig
from ..tokenizer import candidates
from . import git_cmd
from .filesystem import DEFAULT_MAX_LINE_LENGTH, FileOutcome

__all__ = [
    "DEFAULT_MAX_BLOBS",
    "DEFAULT_MAX_BLOB_SIZE",
    "DEFAULT_MAX_REFS",
    "MAX_PATH_LENGTH",
    "BlobRecord",
    "GitScanConfig",
    "HistoryScan",
    "default_git_scan_config",
    "scan_history",
]


DEFAULT_MAX_BLOB_SIZE: Final[int] = 10 * 1024 * 1024
"""Largest blob whose contents will be read into memory, in bytes (10 MiB).

Matches :data:`secret_shield.scanner.DEFAULT_MAX_FILE_SIZE` on purpose: the bound
exists because the scanner parses untrusted content, and a blob is the historical
equivalent of a file. Anything larger is counted and skipped rather than read --
and because the size is known from ``--batch-check`` before a single content byte
moves, "skipped" costs nothing but two integers.
"""

DEFAULT_MAX_BLOBS: Final[int] = 200_000
"""Most distinct blobs one history scan will consider.

A memory bound, like :data:`~secret_shield.sources.filesystem.DEFAULT_MAX_FILES`.
Each entry is one object name, one decoded path and its reference, so a
repository with millions of objects would otherwise allocate without limit.
Reaching it makes the scan partial, and a partial scan says so.
"""

DEFAULT_MAX_REFS: Final[int] = 4 * DEFAULT_MAX_BLOBS
"""Most ``(blob, path)`` pairs one history scan will index.

The other half of the memory bound behind :data:`DEFAULT_MAX_BLOBS`: one blob can
be recorded at thousands of paths, and paths are what a finding is addressed by.
"""

MAX_PATH_LENGTH: Final[int] = 4096
"""Longest path a finding may be reported at, in characters.

The longest path a Linux filesystem accepts is 4096 bytes. A Git tree entry has
no such limit, so a crafted repository can name a blob with a path longer than
``git checkout`` would ever produce. Such a path is dropped rather than
truncated: two paths sharing a truncated prefix would merge into one finding at
an address that is wrong for both, and a wrong address is worse than a declared
gap. Dropping it makes the scan partial, which is the honest report.

Note:
    Paths are *not* truncated to :data:`secret_shield.tokenizer.MAX_TOKEN_LENGTH`.
    That constant bounds a token, not a location.
"""

_BLOB_KIND: Final[str] = "blob"
"""The only object type whose contents are scanned."""

_TRUNCATED_CODE: Final[str] = "history-truncated"
"""Error code for a scan that stopped before seeing the whole history."""

_UNREADABLE_CODE: Final[str] = "object-unreadable"
"""Error code for an object the history names and Git cannot produce."""


def _require_positive_int(value: object, name: str) -> None:
    """Validate an integer setting that must be at least one.

    Defined above :class:`GitScanConfig` for the reason
    :mod:`secret_shield.sources.filesystem` defines its copy: the module-level
    default below is built at *import* time, and Python resolves a global name
    when that line executes, not when the function body is compiled.
    """

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 1:
        raise ValueError(f"{name} must be at least 1")


def _require_optional_positive(value: object, name: str) -> None:
    """Validate an integer setting that may be ``None`` for "no limit"."""

    if value is None:
        return
    _require_positive_int(value, name)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GitScanConfig:
    """Settings for :func:`scan_history`.

    Attributes:
        scan: Per-content settings inherited from Stage 1. ``max_file_size``
            here is the **blob** limit: it is the same number the working-tree
            scan uses for a file, and the same reasoning applies. Also carries
            the entropy thresholds and the optional fingerprint key.
        registry: Pattern rules to apply. ``None`` means the shipped catalog.
        binary: How blob bytes are classified as text or binary. See
            :class:`~secret_shield.filters.binary.BinaryConfig`.
        path_filters: Which historical paths are eligible. ``None`` -- the
            default -- applies **no** filtering, because today's ignore rules do
            not describe what was committed years ago and applying them would
            hide exactly the deleted-secret case this source exists to find. Set
            it to a :class:`~secret_shield.filters.paths.PathFilterConfig` to
            opt in to the same pruning ``secret-shield scan`` does.
        max_line_length: Longest line handed to entropy analysis. See
            :data:`~secret_shield.sources.filesystem.DEFAULT_MAX_LINE_LENGTH`.
        max_commits: Stop after this many commits. ``None`` means no limit.
            Reaching it makes the scan partial.
        max_blobs: Most distinct blobs to consider. See :data:`DEFAULT_MAX_BLOBS`.
        max_refs: Most ``(blob, path)`` pairs to index. See
            :data:`DEFAULT_MAX_REFS`.
        max_blob_size: Largest blob to read, overriding ``scan.max_file_size``.
            See :data:`DEFAULT_MAX_BLOB_SIZE`.
        timeout: Wall-clock limit, in seconds, for **each** Git command this
            scan runs. Not for the scan as a whole; see the module docstring.
        since: Only commits at or after this date expression. Rejects anything
            beginning with ``-``, so a date can never be read as an option.
        until: Only commits at or before this date expression.

    Raises:
        TypeError: If a field has the wrong type.
        ValueError: If a limit is out of range or a date expression is unusable.
    """

    scan: ScanConfig = ScanConfig()
    registry: DetectorRegistry | None = None
    binary: BinaryConfig = BinaryConfig()
    path_filters: PathFilterConfig | None = None
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH
    max_commits: int | None = None
    max_blobs: int | None = DEFAULT_MAX_BLOBS
    max_refs: int | None = DEFAULT_MAX_REFS
    max_blob_size: int | None = None
    timeout: float = git_cmd.DEFAULT_TIMEOUT_SECONDS
    since: str | None = None
    until: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scan, ScanConfig):
            raise TypeError(f"scan must be a ScanConfig, got {type(self.scan).__name__}")
        if not isinstance(self.binary, BinaryConfig):
            raise TypeError(f"binary must be a BinaryConfig, got {type(self.binary).__name__}")
        if self.path_filters is not None and not isinstance(self.path_filters, PathFilterConfig):
            raise TypeError(
                "path_filters must be a PathFilterConfig or None, got "
                f"{type(self.path_filters).__name__}"
            )
        if self.registry is not None and not isinstance(self.registry, DetectorRegistry):
            raise TypeError(
                f"registry must be a DetectorRegistry or None, got {type(self.registry).__name__}"
            )
        _require_positive_int(self.max_line_length, "max_line_length")
        _require_optional_positive(self.max_commits, "max_commits")
        _require_optional_positive(self.max_blobs, "max_blobs")
        _require_optional_positive(self.max_refs, "max_refs")
        _require_optional_positive(self.max_blob_size, "max_blob_size")
        if isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float)):
            raise TypeError(f"timeout must be a number, got {type(self.timeout).__name__}")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        # Checked here as well as inside ``git_cmd`` so a hand-built config fails
        # at construction. ``git_cmd`` keeps its own check because it is
        # reachable without this module.
        for expression, name in ((self.since, "since"), (self.until, "until")):
            if expression is not None:
                git_cmd.validate_revision_argument(expression, name)

    def blob_size_limit(self) -> int:
        """Return the effective blob size limit in bytes.

        ``max_blob_size`` wins when set, otherwise ``scan.max_file_size``, so the
        common case needs no second setting to say the same thing.
        """

        if self.max_blob_size is not None:
            return self.max_blob_size
        return self.scan.max_file_size


DEFAULT_GIT_SCAN_CONFIG: Final[GitScanConfig] = GitScanConfig()
"""The shipped defaults. See :class:`GitScanConfig` for each field."""


def default_git_scan_config() -> GitScanConfig:
    """Return a fresh copy of the default Git history scan configuration."""

    return GitScanConfig()


# ---------------------------------------------------------------------------
# What a history scan found out
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BlobRecord:
    """One distinct blob, and everywhere in the history it was found.

    Attributes:
        name: The blob's 40-character SHA-1 object name. Recorded so a finding
            can be traced to the exact object and the blob re-read on demand.
        paths: The reference to attribute a finding to, one per distinct path,
            sorted by path so iteration is deterministic. Each is the *newest*
            commit in which this blob appeared at that path.
        occurrences: How many ``(commit, path)`` triples this blob appeared in.
            Counted rather than expanded: the full list is unbounded work for no
            extra information, and the newest commit per path is the one a user
            acts on.
    """

    name: str
    paths: tuple[git_cmd.HistoryRef, ...] = ()
    occurrences: int = 0


@dataclass(frozen=True, slots=True)
class HistoryScan:
    """The outcome of one history scan: a result, plus what was skipped.

    :attr:`result` is an ordinary :class:`~secret_shield.models.ScanResult` and
    goes straight to :func:`~secret_shield.report.render_text`,
    :func:`~secret_shield.report.render_json` or
    :func:`~secret_shield.report.render_markdown`. The remaining fields are
    statistics a report cannot show, and they exist so that "0 findings" and
    "I looked at nothing" can never be confused.

    Attributes:
        result: Findings, errors and counts, ready to render.
        commits: Distinct commits walked.
        blobs_seen: Distinct blobs named by the history.
        blobs_scanned: Blobs whose contents were read and analysed. Always equal
            to ``result.files_scanned``, which counts blobs where a directory
            scan counts files.
        blobs_binary: Blobs skipped as binary or undecodable.
        blobs_too_large: Blobs skipped for exceeding the size limit.
        blobs_unreadable: Blobs Git could not produce. These are also ``errors``,
            because unlike a binary blob this is a failure, not a decision.
        paths_filtered: ``(blob, path)`` pairs dropped by
            :attr:`GitScanConfig.path_filters`.
        truncated: Whether any limit stopped the scan early. Always accompanied
            by a ``history-truncated`` error.
        truncated_because: Every limit that fired, sorted. Empty when not
            truncated.
    """

    result: ScanResult
    commits: int = 0
    blobs_seen: int = 0
    blobs_scanned: int = 0
    blobs_binary: int = 0
    blobs_too_large: int = 0
    blobs_unreadable: int = 0
    paths_filtered: int = 0
    truncated: bool = False
    truncated_because: tuple[str, ...] = ()

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Convenience accessor for ``result.findings``."""

        return self.result.findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def scan_history(
    repo: str | Path,
    config: GitScanConfig | None = None,
) -> HistoryScan:
    """Scan every blob reachable from ``HEAD`` in a repository's history.

    Read-only in the strong sense: no file is written, no ref moves, no branch is
    created and nothing is checked out. The working tree is exactly as it was
    before the call.

    Args:
        repo: Path to a Git repository. A subdirectory of one works, because Git
            resolves it. A plain directory that is not a repository produces one
            error and no findings.
        config: Scan settings. Defaults to :data:`DEFAULT_GIT_SCAN_CONFIG`.

    Returns:
        A :class:`HistoryScan`. Its :attr:`~HistoryScan.result` is ready for any
        reporter.

    Note:
        Nothing raises for a repository that cannot be scanned. A missing ``git``
        binary, a path that is not a repository, a SHA-256 repository, a corrupt
        object and a timeout are all reported as entries in ``errors`` carrying a
        stable ``code``, and the scan returns with an empty finding list. Only a
        programming error -- a wrongly typed configuration -- raises.

    Note:
        A repository with no commits is **not** an error. ``HEAD`` is unborn,
        there is no history, and reporting nothing is the truthful answer.
    """

    settings = _coerce_config(config)
    target = Path(repo)
    started = time.monotonic()

    if not target.exists():
        # Asked for, because Git would answer a path that does not exist with
        # "not a git repository" -- true, and no use to anyone holding a typo.
        return _failed(
            started,
            ScanError("path does not exist", path=str(target), code="not-found"),
        )

    try:
        resolved = target.resolve(strict=True)
    except OSError:
        return _failed(
            started,
            ScanError("path cannot be resolved", path=str(target), code="not-found"),
        )

    try:
        state = git_cmd.head_state(resolved, timeout=settings.timeout)
    except git_cmd.GitError as exc:
        return _failed(started, _error_for(exc, resolved))

    if state is git_cmd.HeadState.INVALID:
        return _failed(
            started,
            ScanError(
                "path is not a Git repository, or its object database cannot be read",
                path=str(resolved),
                code=git_cmd.KIND_NOT_A_REPOSITORY,
            ),
        )

    if state is git_cmd.HeadState.UNBORN:
        # ``git init`` and nothing more. ``rev-list HEAD`` would fail here, and
        # that failure is Git saying "this ref does not resolve", not the object
        # database being damaged. Reporting nothing is the truthful answer, and
        # it must not be dressed up as an error: a freshly created repository is
        # not a broken one.
        return HistoryScan(
            result=ScanResult(
                duration_seconds=time.monotonic() - started,
                tool_version=TOOL_VERSION,
            )
        )

    try:
        return _scan_repository(resolved, settings, started)
    except git_cmd.GitError as exc:
        # A Git failure that escaped per-stage handling. The message was written
        # by ``git_cmd`` from a fixed vocabulary and never quotes Git's stderr,
        # so it is safe to surface; ``ScanError`` strips control characters on
        # construction regardless.
        return _failed(started, _error_for(exc, resolved))


# ---------------------------------------------------------------------------
# The scan proper
# ---------------------------------------------------------------------------


def _scan_repository(repo: Path, config: GitScanConfig, started: float) -> HistoryScan:
    """Index the history, read the distinct blobs, scan each one exactly once."""

    index, walk_commits, walk_truncated, reasons, filtered = _index_history(repo, config)

    blobs_binary = 0
    blobs_too_large = 0
    blobs_unreadable = 0
    findings: list[Finding] = []
    errors: list[ScanError] = []
    bytes_scanned = 0
    blobs_scanned = 0

    # Sorted object names: the set of blobs is a set, and Git's enumeration order
    # is not a promise. Sorting here is what makes two scans of an unchanged
    # repository produce byte-identical output.
    names = sorted(index)
    headers = _read_headers(repo, names, config, errors)
    limit = config.blob_size_limit()

    readable: list[str] = []
    for name in names:
        header = headers.get(name)
        if header is None or header.kind != _BLOB_KIND:
            # Git named this object as a blob's destination and then did not
            # produce it as a blob. A missing or corrupt object, not a decision.
            blobs_unreadable += 1
            errors.append(
                ScanError(
                    "an object named by this history could not be read from the "
                    "object database",
                    path=name,
                    code=_UNREADABLE_CODE,
                )
            )
            continue
        if header.size > limit:
            blobs_too_large += 1
            continue
        readable.append(name)

    payloads = _read_payloads(repo, readable, config)
    for name in readable:
        data = payloads.get(name)
        if data is None:
            blobs_unreadable += 1
            errors.append(
                ScanError(
                    "an object named by this history could not be read from the "
                    "object database",
                    path=name,
                    code=_UNREADABLE_CODE,
                )
            )
            continue

        # A bounded prefix, exactly as the filesystem source classifies a file.
        # Deciding on the whole blob would cost as much as reading it, which is
        # the thing the size limit exists to avoid.
        if classify_bytes(data[: config.binary.max_sniff_bytes], config.binary).is_binary:
            blobs_binary += 1
            continue

        outcome = _analyze_blob(data, index[name], config)
        blobs_scanned += 1
        bytes_scanned += outcome.size
        findings.extend(outcome.findings)
        errors.extend(outcome.errors)

    truncated = walk_truncated or bool(reasons)
    if truncated:
        errors.append(
            ScanError(
                "this history was not examined in full ("
                + "; ".join(sorted(reasons))
                + "), so a clean result is not a guarantee",
                path=str(repo),
                code=_TRUNCATED_CODE,
            )
        )

    return HistoryScan(
        result=ScanResult(
            findings=tuple(sorted(findings, key=lambda finding: finding.sort_key)),
            errors=tuple(
                sorted(errors, key=lambda e: (e.path or "", e.code or "", e.reason))
            ),
            files_scanned=blobs_scanned,
            bytes_scanned=bytes_scanned,
            duration_seconds=time.monotonic() - started,
            tool_version=TOOL_VERSION,
        ),
        commits=walk_commits,
        blobs_seen=len(index),
        blobs_scanned=blobs_scanned,
        blobs_binary=blobs_binary,
        blobs_too_large=blobs_too_large,
        blobs_unreadable=blobs_unreadable,
        paths_filtered=filtered,
        truncated=truncated,
        truncated_because=tuple(sorted(reasons)),
    )


# ---------------------------------------------------------------------------
# Stage 1: index the history, names only
# ---------------------------------------------------------------------------


def _index_history(
    repo: Path, config: GitScanConfig
) -> tuple[dict[str, BlobRecord], int, bool, set[str], int]:
    """Build ``blob name -> where it was found`` in one names-only pass.

    This is the deduplication step, and the reason the scan is affordable. Git
    emits one record per ``(commit, path)`` pair, so a repository with ten
    thousand commits produces millions of them. Recording them all is what makes
    ``blobs_seen`` far smaller than that, and it is the number of distinct blobs
    -- not the number of records -- that decides how many objects are read.

    Returns:
        ``(index, commit_count, truncated_by_git, reasons, paths_filtered)``.
        ``truncated_by_git`` is Git's own ``--max-count`` limit firing, which the
        walk reports separately because Git applied it, not this module.
    """

    walk = git_cmd.HistoryWalk(
        repo,
        timeout=config.timeout,
        max_commits=config.max_commits,
        since=config.since,
        until=config.until,
    )

    index: dict[str, BlobRecord] = {}
    # path -> reference, so the newest reference per path is the one kept. Git
    # walks newest commit first, so the first reference seen for a path is the
    # newest one and it is deliberately not overwritten.
    buckets: dict[str, dict[str, git_cmd.HistoryRef]] = {}
    occurrences: dict[str, int] = {}
    reasons: set[str] = set()
    refs_used = 0
    paths_filtered = 0

    max_blobs = config.max_blobs
    max_refs = config.max_refs

    for reference in walk:
        path = _report_path(reference.path)
        if path is None:
            # Too long to report, or normalises to nothing. Dropped rather than
            # mangled: see :data:`MAX_PATH_LENGTH`.
            reasons.add("a path in the history was too long to report at")
            continue

        if config.path_filters is not None and not _path_allowed(config.path_filters, path):
            paths_filtered += 1
            continue

        bucket = buckets.get(reference.object_name)
        if bucket is None:
            if max_blobs is not None and len(buckets) >= max_blobs:
                reasons.add(f"the history names more than {max_blobs} distinct objects")
                continue
            bucket = {}
            buckets[reference.object_name] = bucket
            occurrences[reference.object_name] = 0

        occurrences[reference.object_name] += 1
        if path in bucket:
            # Already indexed at this path, and the reference held is the newer
            # one. Git's order made that decision, not a comparison here.
            continue
        if max_refs is not None and refs_used >= max_refs:
            reasons.add(f"the history has more than {max_refs} distinct path references")
            continue
        refs_used += 1
        bucket[path] = dataclasses.replace(reference, path=path)

    for name, bucket in buckets.items():
        index[name] = BlobRecord(
            name=name,
            paths=tuple(bucket[path] for path in sorted(bucket)),
            occurrences=occurrences[name],
        )

    if walk.truncated and config.max_commits is not None:
        reasons.add(f"the walk stopped at the {config.max_commits} commit limit")

    return index, walk.commit_count, walk.truncated, reasons, paths_filtered


def _path_allowed(filters: PathFilterConfig, path: str) -> bool:
    """Return whether ``path`` survives ``filters``.

    A history index has no traversal order, so :meth:`PathFilterConfig.decide` --
    which expects a directory to be visited before its contents -- is applied once
    to the final component, and every ancestor is offered to the directory-name
    rule by hand. The result is the same decision a directory walk would reach
    for the same file, which is what "opt in to the same pruning" means.
    """

    parts = path.split("/")
    for part in parts[:-1]:
        if filters.ignores_directory_name(part):
            return False
    return bool(filters.decide(parts[-1], path, is_directory=False))


def _report_path(raw: str) -> str | None:
    """Return ``raw`` as a safe report path, or ``None`` if it cannot be one.

    A path out of a Git tree is attacker-controlled in exactly the way a filename
    on disk is: it may contain a newline, an ANSI escape, a bidirectional
    override, an absolute prefix or a ``..`` segment. Three things happen here.

    * **Control characters are stripped.** A report is read by a terminal. A
      repository that commits a file called ``evil\\e[31mFAKE`` must not be able
      to repaint the CI log of whoever scans it.
    * **Segments are normalised.** ``.``, ``..`` and empty segments are *removed*
      rather than resolved, so a crafted path can never be printed as something
      outside the repository. The path is a label, never a filesystem path, and
      nothing in this module opens one.
    * **Length is bounded.** See :data:`MAX_PATH_LENGTH`.

    Returns ``None`` when nothing usable is left, rather than substituting a
    placeholder that would merge two real paths into a single finding.
    """

    cleaned = strip_control_characters(raw)
    if len(cleaned) > MAX_PATH_LENGTH:
        return None
    normalized = normalize_relative_path(cleaned)
    if not normalized or len(normalized) > MAX_PATH_LENGTH:
        return None
    return normalized


# ---------------------------------------------------------------------------
# Stages 2 and 3: read the distinct blobs
# ---------------------------------------------------------------------------


def _read_headers(
    repo: Path,
    names: list[str],
    config: GitScanConfig,
    errors: list[ScanError],
) -> dict[str, git_cmd.ObjectHeader]:
    """Return each object's type and size, from one ``cat-file --batch-check``.

    This is a size filter that costs no content transfer. Without it a repository
    holding one 2 GiB blob would push all 2 GiB through a pipe for the scanner to
    decide, at the far end, that it was over its limit.

    A Git failure here is recorded and the scan continues: every name Git did not
    answer about is treated as unreadable, so one bad batch cannot lose the
    findings from every other object.
    """

    headers: dict[str, git_cmd.ObjectHeader] = {}
    if not names:
        return headers
    try:
        for header in git_cmd.iter_object_headers(repo, names, timeout=config.timeout):
            if header is not None:
                headers[header.name] = header
    except git_cmd.GitError as exc:
        errors.append(_error_for(exc, repo))
    return headers


def _read_payloads(repo: Path, names: list[str], config: GitScanConfig) -> dict[str, bytes]:
    """Return the contents of each named blob, read once each.

    ``max_payload`` is passed as well, so ``git_cmd`` keeps its own memory
    backstop: the size filter above is this module's policy decision, and this is
    the promise that a payload over the limit is never held whole even if the
    size Git reported were wrong.
    """

    payloads: dict[str, bytes] = {}
    if not names:
        return payloads
    for payload in git_cmd.iter_object_payloads(
        repo, names, timeout=config.timeout, max_payload=config.blob_size_limit()
    ):
        if payload is not None:
            payloads[payload.name] = payload.data
    return payloads


# ---------------------------------------------------------------------------
# Stage 4: scan one blob's contents
# ---------------------------------------------------------------------------


def _analyze_blob(data: bytes, record: BlobRecord, config: GitScanConfig) -> FileOutcome:
    """Scan one blob's bytes once, then attribute the findings to every path.

    The content is analysed exactly once no matter how many paths or commits it
    was seen at; only the :class:`~secret_shield.models.Location` on each finding
    is rewritten afterwards. That is the whole deduplication argument: the
    expensive part -- decode, tokenize, run every rule -- happens per *blob*, and
    the cheap part happens per path.
    """

    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        # ``classify_bytes`` called this text on a bounded prefix. The full decode
        # is the stricter test, and it is the same one the filesystem source
        # applies: searching a mangled rendering means reporting on something the
        # author never wrote.
        return FileOutcome(
            errors=(
                ScanError(
                    "blob is not valid UTF-8 text",
                    path=_report_name(record),
                    code="invalid-encoding",
                ),
            )
        )

    canonical = _report_name(record)
    fingerprint_key = config.scan.fingerprint_key
    capped, over_length = _cap_long_lines(text, config.max_line_length)

    if over_length:
        # Fusion compares offsets, and two detectors can only be compared when
        # they measure the same string. Capping changes the string, so this blob
        # is analysed unfused and the partial analysis is declared by an error --
        # exactly the trade the filesystem source makes, for the same reason.
        found = _analyze_unfused(text, capped, canonical, config, fingerprint_key)
    else:
        found = analyze_text(
            text,
            canonical,
            registry=config.registry,
            entropy=config.scan.entropy,
            source_kind=SourceKind.GIT,
            fingerprint_key=fingerprint_key,
        )

    findings = [
        _relabel(finding, reference) for finding in found for reference in record.paths
    ]

    errors: tuple[ScanError, ...] = ()
    if over_length:
        errors = (
            ScanError(
                f"{over_length} line(s) exceed the {config.max_line_length} character "
                "limit; entropy analysis used only the start of those lines",
                path=canonical,
                code="line-too-long",
            ),
        )

    return FileOutcome(findings=tuple(findings), errors=errors, size=len(data), analyzed=True)


def _analyze_unfused(
    text: str,
    capped: str,
    path: str,
    config: GitScanConfig,
    fingerprint_key: bytes | None,
) -> tuple[Finding, ...]:
    """Run each detector on its own, for a blob whose lines had to be capped.

    Pattern rules see the whole text, because a private key block legitimately
    spans thousands of characters and truncating it would turn a certain finding
    into a missed one. Entropy sees the capped copy, because that is the copy the
    tokenizer produced. Neither claim is fused to the other: fusion compares
    offsets, and the two strings do not agree.
    """

    rules = config.registry if config.registry is not None else default_registry()
    patterns = findings_from(
        find_matches(text, rules),
        path,
        source_kind=SourceKind.GIT,
        fingerprint_key=fingerprint_key,
    )
    return patterns + detect_entropy(
        candidates(capped),
        path,
        config.scan.entropy,
        source_kind=SourceKind.GIT,
        fingerprint_key=fingerprint_key,
    )


def _relabel(finding: Finding, reference: git_cmd.HistoryRef) -> Finding:
    """Return ``finding`` addressed at ``reference``'s path and commit.

    Only the location changes. The masked value, the fingerprint, the severity
    and the confidence are properties of the *content*, which by construction is
    the same content for every reference this blob was found at; recomputing them
    would mean re-deriving a secret this module has deliberately not kept.
    """

    location = finding.location
    if (
        location.path == reference.path
        and location.commit == reference.commit
        and location.commit_time == reference.commit_time
    ):
        return finding
    return dataclasses.replace(
        finding,
        location=dataclasses.replace(
            location,
            path=reference.path,
            commit=reference.commit,
            commit_time=reference.commit_time,
        ),
    )


def _report_name(record: BlobRecord) -> str:
    """Return the path a blob-level error or analysis pass should be named by.

    One blob can be indexed at many paths, and a blob-level problem -- invalid
    UTF-8, a line too long -- is a property of the bytes, not of where they
    happened to live. It is reported at the first path in sorted order, so the
    choice is deterministic. The object name is the fallback for a blob with no
    usable path at all, which cannot normally happen but keeps the message from
    being anonymous.
    """

    return record.paths[0].path if record.paths else f"object:{record.name[:12]}"


def _cap_long_lines(text: str, limit: int) -> tuple[str, int]:
    """Return ``text`` with every line truncated to ``limit``, and how many were.

    Newlines are preserved exactly, so line numbers in findings are identical
    whether or not the cap applied. Character *offsets* are not: truncating a
    line shifts every offset after it, which is why
    :func:`_analyze_unfused` gives the pattern rules the uncapped text and the
    entropy detector the capped copy, and fuses nothing.

    Deliberately duplicated from :func:`secret_shield.sources.filesystem._cap_long_lines`
    rather than imported: it is module-private there, and a source reaching into
    another source's internals would be a worse coupling than twenty lines of
    duplication. A test in ``tests/unit/test_git_history.py`` runs both copies
    over the same inputs and requires identical output, so a change to one that
    is not made to the other fails the suite instead of silently giving blobs and
    working-tree files different entropy thresholds.
    """

    if len(text) <= limit:
        return text, 0

    lines = text.split("\n")
    over = sum(1 for line in lines if len(line) > limit)
    if over == 0:
        return text, 0

    return "\n".join(line[:limit] for line in lines), over


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _failed(started: float, error: ScanError) -> HistoryScan:
    """Return an empty scan carrying one error.

    Used for the failures that stop a scan before any content exists to scan: no
    repository, no Git, no SHA-1 object names, a timeout. ``files_scanned`` is
    ``0``, so a reader can tell this apart from a clean history.
    """

    return HistoryScan(
        result=ScanResult(
            findings=(),
            errors=(error,),
            files_scanned=0,
            bytes_scanned=0,
            duration_seconds=time.monotonic() - started,
            tool_version=TOOL_VERSION,
        )
    )


def _error_for(exc: git_cmd.GitError, repo: Path) -> ScanError:
    """Turn a :class:`~secret_shield.sources.git_cmd.GitError` into an error entry.

    The ``kind`` becomes the ``code``, verbatim, so every failure this module can
    produce has a stable identifier a caller can branch on -- and so the SHA-256
    case is distinguishable from every other failure by equality with
    ``unsupported-object-format`` rather than by reading prose.

    The message is passed through rather than reworded: ``git_cmd`` builds every
    message from a fixed vocabulary and never includes Git's own stderr, which is
    the one thing on this path a repository controls.
    """

    return ScanError(str(exc), path=str(repo), code=exc.kind)


def _coerce_config(config: GitScanConfig | None) -> GitScanConfig:
    """Validate the caller's configuration.

    Raises:
        TypeError: If ``config`` is neither ``None`` nor a
            :class:`GitScanConfig`. A wrong type is a bug in the caller, not a
            property of a repository, so it is loud rather than collected.
    """

    if config is None:
        return DEFAULT_GIT_SCAN_CONFIG
    if not isinstance(config, GitScanConfig):
        raise TypeError(f"config must be a GitScanConfig, got {type(config).__name__}")
    return config