"""Scanning a file or a whole directory tree.

:func:`scan_path` is the entry point. Given a file it behaves like
:func:`secret_shield.scanner.scan_file`; given a directory it walks the tree
and analyses every file the filters allow.

What a directory scan runs
--------------------------

Every file is analysed by the **full** rule set: the Stage 2 vendor patterns,
the Stage 2 context logic that decides whether surrounding words support a
match, and the Stage 1 entropy rule for values no vendor claims. That is a
deliberate choice about the single-file case too.

:func:`secret_shield.scanner.scan_file` is untouched and still runs the entropy
rule alone, because that is the Stage 1 API and changing it would be changing
history. But :func:`scan_path` runs the full set whether it was handed a file
or a directory, because the alternative is a security hole with a very ordinary
shape: a user who scans one file would see no vendor keys, and a user who scans
the directory containing that same file would. A scanner that reports less when
asked precisely is a scanner nobody should trust. The difference is documented
on both functions so the choice is visible rather than surprising.

Running both detectors means a file that earns two matches from two rules, so
the per-file analysis goes through :func:`secret_shield.pipeline.analyze_text`
rather than calling each detector in turn. Fusion compares character offsets
between the two, and one exception to it is worth stating here: a file whose
lines exceeded ``max_line_length`` is analysed **unfused**, because the capped
copy the entropy rule reads no longer shares coordinates with the full text the
pattern rules read. See :func:`_analyze_file`.

Determinism
-----------

The filesystem does not promise an enumeration order, and on several platforms
actively varies it. So the walk collects candidates first and **sorts them by
root-relative path** before anything is analysed. Every subsequent ordering --
findings, skips, errors -- follows from that one sort. Two scans of an
unchanged tree produce byte-identical results, which is what makes the output
diffable and a CI result reproducible. Directory entries are also sorted as
they are read, so memory use stays predictable on a tree that is mostly
subdirectories.

Findings are returned in the canonical :attr:`~secret_shield.models.Finding.sort_key`
order rather than in the order files happened to be read, so ``result.findings``
and ``result.sorted_findings()`` agree instead of merely being both sorted.

Paths in the result are **root-relative, POSIX-style**: ``src/app/settings.py``,
never ``/home/someone/project/src/app/settings.py``. A report that embedded the
scanner's own absolute path would leak the scanning machine's directory layout
into CI logs and would differ between a developer's laptop and a CI runner.
For a single explicit file, the path is reported exactly as the caller spelled
it, matching :func:`~secret_shield.scanner.scan_file`.

Failure policy
--------------

Nothing here raises for a bad file. A file that is unreadable, binary, enormous,
malformed, or that vanishes mid-scan produces a
:class:`~secret_shield.models.ScanError` and the walk continues. A scanner that
stops at the first unreadable file is useless in CI, where one stray permission
denial is normal.

What is *not* an error is a policy skip. Skipping ``node_modules`` is the
filter working, not a failure, so expected skips are not reported as errors.
They are available through :func:`walk`, which returns every skip with its
:class:`~secret_shield.filters.paths.SkipReason`, for callers that need to
explain why a file was not scanned.

Size and safety limits
----------------------

Every read is bounded, twice over. ``ScanConfig.max_file_size`` caps a file, and
the read itself asks for at most that many bytes *plus one*, so a file that
grows between the ``stat`` and the read is caught rather than trusted. The
binary sniff reads at most ``BinaryConfig.max_sniff_bytes`` and rewinds, so a
large file is classified without being held in memory twice.

``max_files`` bounds how many candidates one scan will collect. Without it, a
hostile or merely enormous tree could make the scan allocate a path object per
file with no upper limit, which is the same denial-of-service shape as reading
an unbounded file. Exceeding it is reported as an error, so a truncated scan is
never mistaken for a clean one.
"""

from __future__ import annotations

import errno
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final

from ..detectors import DetectorRegistry, find_matches, findings_from
from ..detectors import detect as detect_entropy
from ..detectors.catalog import default_registry
from ..filters.binary import BinaryConfig, BinaryVerdict, classify_bytes
from ..filters.binary import default_binary_config
from ..filters.paths import (
    PathFilterConfig,
    SkipReason,
    default_path_filter_config,
    resolve_within,
)
from ..models import TOOL_VERSION, Finding, ScanError, ScanResult
from ..pipeline import analyze_text
from ..scanner import ScanConfig
from ..tokenizer import candidates

__all__ = [
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_LINE_LENGTH",
    "FileEntry",
    "PathScanConfig",
    "SkippedEntry",
    "WalkResult",
    "default_path_scan_config",
    "scan_path",
    "walk",
]


DEFAULT_MAX_LINE_LENGTH: Final[int] = 65_536
"""Longest line handed to the candidate extractor, in characters (64 KiB).

A credential is never this long -- the longest vendor pattern in the catalog
allows far less -- so a line this size is a minified bundle, a data blob or an
attempt to make the scanner do unnecessary work. Capping it bounds the work per
line without touching the file-size cap that bounds memory.

The cap applies to entropy analysis only. Pattern rules still see the whole
text, because a private key block legitimately spans thousands of characters
and truncating it would turn a certain finding into a missed one. When any line
is capped, the file also produces a ``line-too-long`` error, so a partial
analysis is never reported as a complete one.
"""

DEFAULT_MAX_FILES: Final[int] = 100_000
"""Most candidate files one scan will collect.

Memory, not time, is the reason: each candidate is a path object and a relative
string, so a tree with ten million files would otherwise allocate without bound.
The default is far above any real repository. Reaching it produces a
``too-many-files`` error, so the resulting partial result cannot be mistaken for
a clean scan.
"""

#: Maps a binary verdict onto the error code Stage 1 already established, so
#: that a file skipped by :func:`scan_path` and the same file skipped by
#: :func:`~secret_shield.scanner.scan_file` report identically.
_BINARY_ERROR_CODES: Final[dict[BinaryVerdict, str]] = {
    BinaryVerdict.NUL_BYTE: "binary",
    BinaryVerdict.CONTROL_HEAVY: "binary",
    BinaryVerdict.UNDECODABLE: "invalid-encoding",
}


def _require_positive_int(value: object, name: str) -> None:
    """Validate an integer setting that must be at least one.

    Defined above :class:`PathScanConfig` on purpose.
    ``DEFAULT_PATH_SCAN_CONFIG`` below builds one at *import* time, and
    Python resolves a global name when that line runs -- not when the function
    body is compiled -- so a helper defined further down the module raises
    ``NameError`` during import instead of at first use.
    """

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 1:
        raise ValueError(f"{name} must be at least 1")


@dataclass(frozen=True, slots=True)
class PathScanConfig:
    """Settings for :func:`scan_path` and :func:`walk`.

    Attributes:
        scan: Per-file settings inherited from Stage 1 -- the maximum file
            size and the entropy thresholds.
        filters: Which paths are eligible. See
            :class:`~secret_shield.filters.paths.PathFilterConfig`.
        binary: How bytes are classified as text or binary. See
            :class:`~secret_shield.filters.binary.BinaryConfig`.
        registry: Pattern rules to apply. ``None`` means the shipped catalog.
        max_line_length: Longest line passed to entropy analysis. See
            :data:`DEFAULT_MAX_LINE_LENGTH`.
        max_files: Most files one scan will collect. See
            :data:`DEFAULT_MAX_FILES`.
    """

    scan: ScanConfig = ScanConfig()
    filters: PathFilterConfig = PathFilterConfig()
    binary: BinaryConfig = BinaryConfig()
    registry: DetectorRegistry | None = None
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH
    max_files: int = DEFAULT_MAX_FILES

    def __post_init__(self) -> None:
        if not isinstance(self.scan, ScanConfig):
            raise TypeError(f"scan must be a ScanConfig, got {type(self.scan).__name__}")
        if not isinstance(self.filters, PathFilterConfig):
            raise TypeError(
                f"filters must be a PathFilterConfig, got {type(self.filters).__name__}"
            )
        if not isinstance(self.binary, BinaryConfig):
            raise TypeError(f"binary must be a BinaryConfig, got {type(self.binary).__name__}")
        if self.registry is not None and not isinstance(self.registry, DetectorRegistry):
            raise TypeError(
                f"registry must be a DetectorRegistry or None, got "
                f"{type(self.registry).__name__}"
            )
        _require_positive_int(self.max_line_length, "max_line_length")
        _require_positive_int(self.max_files, "max_files")

    def rules(self) -> DetectorRegistry:
        """Return the pattern rules to use, defaulting to the shipped catalog.

        Resolved once per scan rather than per file, because building the
        catalog compiles fifteen regular expressions and there is no reason to
        pay for that once per candidate.
        """

        return default_registry() if self.registry is None else self.registry


DEFAULT_PATH_SCAN_CONFIG: Final[PathScanConfig] = PathScanConfig()
"""The shipped defaults."""


def default_path_scan_config() -> PathScanConfig:
    """Return a fresh copy of the default filesystem scan configuration."""

    return PathScanConfig(
        scan=ScanConfig(),
        filters=default_path_filter_config(),
        binary=default_binary_config(),
        registry=None,
        max_line_length=DEFAULT_MAX_LINE_LENGTH,
        max_files=DEFAULT_MAX_FILES,
    )


@dataclass(frozen=True, slots=True)
class FileEntry:
    """One file the walk decided to read.

    Attributes:
        path: The path to open. This may be a symlink the walk has already
            resolved and verified to point inside the root.
        relative: Root-relative POSIX path, used for reporting.
        size: Size in bytes at the time the directory was read.
        identity: ``(st_dev, st_ino)`` of the file the walk resolved to. Used
            after opening to detect a path that was swapped between the
            containment check and the read. ``None`` means "do not check".
    """

    path: Path
    relative: str
    size: int
    identity: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class SkippedEntry:
    """One path the walk declined, and why.

    Attributes:
        relative: Root-relative POSIX path.
        reason: The specific cause. Never a summary, so "why was my file not
            scanned?" always has a precise answer.
    """

    relative: str
    reason: SkipReason


@dataclass(frozen=True, slots=True)
class WalkResult:
    """What a traversal found: candidates, skips and failures.

    Separated from :func:`scan_path` on purpose. Deciding *which files to read*
    and *what those files contain* are different questions with different
    failure modes, and a caller that wants to explain a scan -- a reporter, a
    dry-run mode, a test -- needs the first answer without paying for the
    second.

    Attributes:
        root: The root that was walked, as given.
        files: Candidate files, sorted by :attr:`FileEntry.relative`.
        skipped: Every path not considered, sorted by path.
        errors: Failures that prevented traversal, sorted for determinism.
        truncated: Whether ``max_files`` stopped the walk early. When true,
            ``errors`` contains a ``too-many-files`` entry.
    """

    root: str
    files: tuple[FileEntry, ...] = ()
    skipped: tuple[SkippedEntry, ...] = ()
    errors: tuple[ScanError, ...] = ()
    truncated: bool = False

    def __post_init__(self) -> None:
        for name, expected in (
            ("files", FileEntry),
            ("skipped", SkippedEntry),
            ("errors", ScanError),
        ):
            values = getattr(self, name)
            object.__setattr__(self, name, tuple(values))
            for item in values:
                if not isinstance(item, expected):
                    raise TypeError(
                        f"{name} must contain only {expected.__name__} instances"
                    )
        if not isinstance(self.truncated, bool):
            raise TypeError(f"truncated must be a bool, got {type(self.truncated).__name__}")

    def skipped_by(self, reason: SkipReason) -> tuple[str, ...]:
        """Return the relative paths skipped for one specific reason."""

        return tuple(entry.relative for entry in self.skipped if entry.reason is reason)

    def counts_by_reason(self) -> dict[str, int]:
        """Count skips per reason label, sorted, for a summary line."""

        counts: dict[str, int] = {}
        for entry in self.skipped:
            counts[entry.reason.value] = counts.get(entry.reason.value, 0) + 1
        return dict(sorted(counts.items()))


@dataclass(frozen=True, slots=True)
class FileOutcome:
    """What analysing one file produced.

    Internal to this module but a dataclass rather than a tuple because it has
    four values that are easy to transpose by accident.

    Attributes:
        findings: Redacted findings, or empty on any failure.
        errors: Zero or one error explaining why the file was not analysed.
        size: Bytes actually read. Zero when nothing was analysed, so statistics
            never claim work that did not happen.
        analyzed: Whether the file was searched at all.
    """

    findings: tuple[Finding, ...] = ()
    errors: tuple[ScanError, ...] = ()
    size: int = 0
    analyzed: bool = False


def walk(root: str | Path, config: PathScanConfig | None = None) -> WalkResult:
    """Traverse ``root`` and return the files a scan should read.

    Does not read file contents and applies no detection rules. Every decision
    is a *filesystem* decision: is this path eligible, is it safe to follow,
    is it a regular file, is it within the size limit.

    Args:
        root: A directory to walk. It is resolved once, so a symlink passed as
            the root is honoured -- the caller named it explicitly.
        config: Scan settings. Defaults to
            :data:`DEFAULT_PATH_SCAN_CONFIG`.

    Returns:
        A :class:`WalkResult` whose ``files`` are sorted by relative path, so
        the order does not depend on how the filesystem enumerated anything.

    Note:
        Files that turn out to be binary, undecodable or too large are *not*
        decided here. That needs the contents, and it happens in
        :func:`scan_path`, which is why ``files_scanned`` can be lower than
        ``len(files)``.
    """

    settings = _coerce_config(config)
    root_path = Path(root)
    display_root = str(root_path)

    resolved, failure = _resolve_root(root_path)
    if failure is not None:
        return WalkResult(root=display_root, errors=(failure,))
    assert resolved is not None

    try:
        root_info = os.stat(resolved)
    except OSError as exc:
        return WalkResult(
            root=display_root,
            errors=(_os_error("cannot read directory metadata", display_root, "stat-failed", exc),),
        )

    files: list[FileEntry] = []
    skipped: list[SkippedEntry] = []
    errors: list[ScanError] = []

    # A directory is identified by its inode, which is the only way to notice
    # that two paths in the tree are the same directory. With symlink following
    # off this can never fire; it is here because the failure it prevents is an
    # unbounded walk rather than a wrong answer.
    visited: set[tuple[int, int]] = {(root_info.st_dev, root_info.st_ino)}
    # Each stack item is (directory to list, prefix for relative paths, depth).
    pending: list[tuple[Path, str, int]] = [(root_path, "", 0)]
    truncated = False

    while pending:
        directory, prefix, depth = pending.pop()
        entries, listing_error = _list_directory(directory, prefix or display_root)
        if listing_error is not None:
            errors.append(listing_error)
            continue

        children: list[tuple[Path, str, int]] = []

        for entry in entries:
            name = entry.name
            relative = f"{prefix}/{name}" if prefix else name
            # Depth is derived from the path itself rather than counted as the
            # walk recurses, so it cannot drift and it means the same thing at
            # every level: a file directly in the root is depth 0.
            entry_depth = relative.count("/")

            try:
                info = os.lstat(entry.path)
            except FileNotFoundError:
                # Listed, then gone. A build running alongside the scan does this
                # routinely; it is a skip, not a failure.
                skipped.append(SkippedEntry(relative, SkipReason.VANISHED))
                continue
            except OSError:
                skipped.append(SkippedEntry(relative, SkipReason.UNREADABLE))
                continue

            is_link = stat.S_ISLNK(info.st_mode)

            # Name policy first, and a symlink is judged as a directory if it
            # could be one. That way a link named ".git" is reported as an
            # ignored directory rather than as a symlink, which is the more
            # useful of the two true statements.
            could_be_directory = stat.S_ISDIR(info.st_mode) or is_link
            decision = settings.filters.decide(name, relative, is_directory=could_be_directory)
            if not decision.include:
                skipped.append(SkippedEntry(relative, _reason_of(decision)))
                continue

            if is_link:
                if not settings.filters.follow_symlinks:
                    skipped.append(SkippedEntry(relative, SkipReason.SYMLINK))
                    continue
                # ``entry.path`` is a str, because ``DirEntry`` yields the path
                # type it was handed. Convert once, for the containment check.
                link = Path(entry.path)

                # Stat through the link first, so that "this link is broken" is
                # reported as broken rather than as "points outside the root".
                # ``resolve_within`` returns ``None`` for both cases and cannot
                # tell them apart; the distinction matters, because a symlink to
                # a deleted file is a routine event in a live tree while a
                # symlink out of the root is the case a user must hear about.
                try:
                    info = os.stat(link)
                except FileNotFoundError:
                    skipped.append(SkippedEntry(relative, SkipReason.VANISHED))
                    continue
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        skipped.append(SkippedEntry(relative, SkipReason.VANISHED))
                    else:
                        skipped.append(SkippedEntry(relative, SkipReason.UNREADABLE))
                    continue

                # Now the containment decision, on its own terms.
                target = resolve_within(link, resolved)
                if target is None:
                    skipped.append(SkippedEntry(relative, SkipReason.SYMLINK_OUTSIDE_ROOT))
                    continue
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    skipped.append(SkippedEntry(relative, SkipReason.NOT_A_REGULAR_FILE))
                    continue

            if stat.S_ISDIR(info.st_mode):
                # Descending would put files at entry_depth + 1, so the limit is
                # checked against what the children would be, not against this
                # directory. max_depth=0 therefore scans the root's own files
                # and nothing below them.
                limit = settings.filters.max_depth
                if limit is not None and entry_depth + 1 > limit:
                    skipped.append(SkippedEntry(relative, SkipReason.IGNORED_DEPTH))
                    continue
                identity = (info.st_dev, info.st_ino)
                if identity in visited:
                    skipped.append(SkippedEntry(relative, SkipReason.CIRCULAR_SYMLINK))
                    continue
                visited.add(identity)
                children.append((entry.path, relative, entry_depth))
                continue

            if not stat.S_ISREG(info.st_mode):
                # FIFOs, sockets, devices, doors. Opening a FIFO blocks until a
                # writer appears and a device offers no bound on a read, so
                # these are skipped rather than scanned.
                skipped.append(SkippedEntry(relative, SkipReason.NOT_A_REGULAR_FILE))
                continue

            limit = settings.filters.max_depth
            if limit is not None and entry_depth > limit:
                skipped.append(SkippedEntry(relative, SkipReason.IGNORED_DEPTH))
                continue

            if info.st_size > settings.scan.max_file_size:
                skipped.append(SkippedEntry(relative, SkipReason.TOO_LARGE))
                continue

            if len(files) >= settings.max_files:
                truncated = True
                break

            identity = (info.st_dev, info.st_ino) if is_link else None
            files.append(FileEntry(entry.path, relative, info.st_size, identity))

        if truncated:
            errors.append(
                ScanError(
                    f"stopped after {settings.max_files} files; raise max_files to scan more",
                    path=display_root,
                    code="too-many-files",
                )
            )
            break

        # Reversed, because the stack pops from the end. Combined with the
        # sorted listing this makes the traversal order itself deterministic,
        # which keeps memory access patterns reproducible even though the final
        # sort already guarantees the result is.
        children.reverse()
        pending.extend(children)

    return WalkResult(
        root=display_root,
        files=tuple(sorted(files, key=lambda entry: entry.relative)),
        skipped=tuple(sorted(skipped, key=lambda entry: (entry.relative, entry.reason.value))),
        errors=tuple(
            sorted(
                errors,
                key=lambda error: (error.path or "", error.code or "", error.reason),
            )
        ),
        truncated=truncated,
    )


def scan_path(path: str | Path, config: PathScanConfig | None = None) -> ScanResult:
    """Scan a file or a directory tree and return one result.

    Args:
        path: A file or a directory. A symlink passed here is followed, because
            the caller named it explicitly -- the containment rule protects
            *traversal*, not the root of a scan the user asked for by name.
        config: Scan settings. Defaults to
            :data:`DEFAULT_PATH_SCAN_CONFIG`.

    Returns:
        A :class:`~secret_shield.models.ScanResult`. Per-file failures appear in
        ``errors``; the rest of the scan continues. Nothing raises for a bad
        file, and nothing raises for a bad path.

    Note:
        Every analysed file goes through the full rule set -- vendor patterns,
        context logic and the entropy rule -- including when ``path`` names a
        single file. :func:`secret_shield.scanner.scan_file` remains
        entropy-only, as it has always been. The difference is deliberate and is
        covered by a test, because a scanner that reports less when asked about
        one precise file than about the directory holding it would be a trap.
    """

    settings = _coerce_config(config)
    target = Path(path)
    display = str(target)
    started = time.monotonic()

    try:
        info = os.stat(target)
    except FileNotFoundError:
        return _result(
            started,
            errors=(
                ScanError("path does not exist", path=display, code="not-found"),
            ),
        )
    except OSError as exc:
        return _result(
            started, errors=(_os_error("cannot read path metadata", display, "stat-failed", exc),)
        )

    if stat.S_ISREG(info.st_mode):
        # A single file the caller named. The path filters deliberately do not
        # apply: they exist to prune a traversal, and overriding an explicit
        # request would mean a user could not scan a file inside node_modules
        # even when they meant to.
        outcome = _analyze_file(FileEntry(target, display, info.st_size), settings)
        return _result(
            started,
            findings=outcome.findings,
            errors=outcome.errors,
            files_scanned=1 if outcome.analyzed else 0,
            bytes_scanned=outcome.size,
        )

    if not stat.S_ISDIR(info.st_mode):
        return _result(
            started,
            errors=(
                ScanError(
                    "path is not a regular file or directory",
                    path=display,
                    code="not-a-regular-file",
                ),
            ),
        )

    walked = walk(target, settings)
    registry = settings.rules()
    findings: list[Finding] = []
    errors: list[ScanError] = list(walked.errors)
    files_scanned = 0
    bytes_scanned = 0

    for entry in walked.files:
        outcome = _analyze_file(entry, settings, registry=registry)
        findings.extend(outcome.findings)
        errors.extend(outcome.errors)
        if outcome.analyzed:
            files_scanned += 1
            bytes_scanned += outcome.size

    return _result(
        started,
        # Files are already in sorted order, so this sorts within files rather
        # than across the tree. Both halves matter: the result of a scan should
        # not depend on the order the filesystem handed entries back, and
        # ``sorted_findings`` exists for callers who want a fresh view rather
        # than the one the scan already produced.
        findings=tuple(sorted(findings, key=lambda finding: finding.sort_key)),
        errors=tuple(errors),
        files_scanned=files_scanned,
        bytes_scanned=bytes_scanned,
    )


# ---------------------------------------------------------------------------
# Reading one file
# ---------------------------------------------------------------------------


def _analyze_file(
    entry: FileEntry,
    config: PathScanConfig,
    *,
    registry: DetectorRegistry | None = None,
) -> FileOutcome:
    """Read and search one file, or explain why it could not be.

    Every failure path returns rather than raises. The read is bounded twice:
    the sniff reads at most ``config.binary.max_sniff_bytes``, and the body
    reads at most ``max_file_size + 1`` so that a file which grew since the
    directory was listed is caught instead of trusted.
    """

    display = entry.relative
    limit = config.scan.max_file_size

    try:
        with open(entry.path, "rb") as handle:
            if entry.identity is not None and not _identity_matches(handle, entry.identity):
                # The path was a symlink into the root when it was resolved and
                # points somewhere else now. Refusing is the whole point of the
                # containment rule, so a swap must not defeat it.
                return FileOutcome(
                    errors=(
                        ScanError(
                            "file was replaced by a different file while the scan was running",
                            path=display,
                            code="vanished",
                        ),
                    )
                )

            head = handle.read(config.binary.max_sniff_bytes)
            verdict = classify_bytes(head, config.binary)
            if verdict.is_binary:
                return FileOutcome(
                    errors=(
                        ScanError(
                            f"file {verdict.description} "
                            f"(checked the first {len(head)} bytes)",
                            path=display,
                            code=_BINARY_ERROR_CODES[verdict],
                        ),
                    )
                )

            handle.seek(0)
            data = handle.read(limit + 1)

            if entry.identity is not None and not _identity_matches(handle, entry.identity):
                return FileOutcome(
                    errors=(
                        ScanError(
                            "file was replaced by a different file while the scan was running",
                            path=display,
                            code="vanished",
                        ),
                    )
                )

    except FileNotFoundError:
        return FileOutcome(
            errors=(
                ScanError("file disappeared before it could be read", path=display, code="vanished"),
            )
        )
    except PermissionError as exc:
        return FileOutcome(
            errors=(_os_error("permission denied", display, "read-failed", exc),)
        )
    except OSError as exc:
        return FileOutcome(errors=(_os_error("cannot read file", display, "read-failed", exc),))

    if len(data) > limit:
        return FileOutcome(
            errors=(
                ScanError(
                    f"file is larger than the {limit} byte limit",
                    path=display,
                    code="too-large",
                ),
            )
        )

    # utf-8-sig drops a byte-order mark and still reads plain UTF-8, so a BOM
    # does not shift every column number in the file. Matches Stage 1 exactly.
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return FileOutcome(
            errors=(
                ScanError("file is not valid UTF-8 text", path=display, code="invalid-encoding"),
            )
        )

    rules = registry if registry is not None else config.rules()
    capped, over_length = _cap_long_lines(text, config.max_line_length)

    if over_length:
        # Fusion compares offsets, and two detectors can only be compared when
        # they are measuring the same string. ``capped`` and ``text`` agree up
        # to the first truncated line and disagree after it, so a file whose
        # lines were capped has no coordinate system the two detectors share.
        #
        # Rather than guess at a mapping, this file is analysed unfused: each
        # detector reports what it found on its own. The cost is a duplicate
        # finding on a line that also drew a ``line-too-long`` error, which is
        # a file the result already declares as only partly analysed. The
        # alternative -- fusing on offsets known to be wrong -- can attach a
        # vendor rule's severity to an unrelated value.
        findings = findings_from(find_matches(text, rules), display)
        findings = findings + detect_entropy(candidates(capped), display, config.scan.entropy)
    else:
        findings = analyze_text(
            text,
            display,
            registry=rules,
            entropy=config.scan.entropy,
        )

    errors: tuple[ScanError, ...] = ()
    if over_length:
        errors = (
            ScanError(
                f"{over_length} line(s) exceed the {config.max_line_length} character limit; "
                "entropy analysis used only the start of those lines",
                path=display,
                code="line-too-long",
            ),
        )

    return FileOutcome(findings=findings, errors=errors, size=len(data), analyzed=True)


def _identity_matches(handle: IO[bytes], expected: tuple[int, int]) -> bool:
    """Return whether the open file is still the one the walk resolved.

    Closes most of the window between resolving a symlink and reading through
    it. It cannot close all of it -- that needs descriptor-relative opens with
    ``O_NOFOLLOW`` -- so this is a mitigation, not a proof.
    """

    try:
        info = os.fstat(handle.fileno())
    except (OSError, ValueError, AttributeError):
        return False
    return (info.st_dev, info.st_ino) == expected


def _cap_long_lines(text: str, limit: int) -> tuple[str, int]:
    """Return ``text`` with every line truncated to ``limit``, and how many were.

    Newlines are preserved exactly, so line numbers in findings are identical
    whether or not the cap applied. Character *offsets* are not: truncating a
    line shifts every offset after it. The pattern rules are always given the
    uncapped text, and when this function reports a truncation the caller skips
    fusion rather than comparing two coordinate systems that disagree.
    """

    if len(text) <= limit:
        return text, 0

    lines = text.split("\n")
    over = sum(1 for line in lines if len(line) > limit)
    if over == 0:
        return text, 0

    return "\n".join(line[:limit] for line in lines), over


# ---------------------------------------------------------------------------
# Traversal helpers
# ---------------------------------------------------------------------------


def _resolve_root(path: Path) -> tuple[Path | None, ScanError | None]:
    """Resolve the scan root, or explain why it cannot be scanned."""

    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        return None, ScanError("path does not exist", path=str(path), code="not-found")
    except RuntimeError:
        # A symlink loop at the root itself.
        return None, ScanError("path is a symlink loop", path=str(path), code="stat-failed")
    except (OSError, ValueError) as exc:
        return None, _os_error("cannot read path metadata", str(path), "stat-failed", exc)

    if not resolved.is_dir():
        return None, ScanError(
            "path is not a directory",
            path=str(path),
            code="root-not-a-directory",
        )

    return resolved, None


def _list_directory(
    directory: Path, display: str
) -> tuple[list[os.DirEntry[str]], ScanError | None]:
    """List one directory, sorted by name, or explain the failure.

    ``display`` is the root-relative path used in any error. The directory's
    real path is deliberately not used: an error is the one string guaranteed to
    reach a log, and embedding the scanner's own absolute directory layout there
    would defeat the relative-path guarantee the rest of this module makes.
    """

    try:
        with os.scandir(directory) as scan:
            entries = sorted(scan, key=lambda entry: entry.name)
    except FileNotFoundError:
        return [], ScanError(
            "directory disappeared while the scan was running",
            path=display,
            code="vanished",
        )
    except PermissionError as exc:
        return [], _os_error("permission denied", display, "read-failed", exc)
    except OSError as exc:
        return [], _os_error("cannot list directory", display, "read-failed", exc)

    return list(entries), None


def _reason_of(decision: object) -> SkipReason:
    """Return a rejected decision's reason.

    A decision built by :meth:`PathFilterConfig.decide` always carries one, and
    the fallback exists only so that a future change to that invariant produces
    a recorded skip with an honest reason rather than an ``AttributeError``
    halfway through a scan.
    """

    reason = getattr(decision, "reason", None)
    return reason if isinstance(reason, SkipReason) else SkipReason.IGNORED_PATH


def _os_error(prefix: str, path: str, code: str, exc: OSError) -> ScanError:
    """Build a :class:`ScanError` from an ``OSError``.

    Only ``strerror`` and the exception class name are used. Never the path, the
    filename or any part of the message a library might have built from file
    contents -- an error string is the easiest place in a program to leak the
    thing being looked for, and it is the one string guaranteed to reach a log.
    """

    detail = exc.strerror or exc.__class__.__name__
    return ScanError(f"{prefix}: {detail}", path=path, code=code)


def _result(
    started: float,
    *,
    findings: tuple[Finding, ...] = (),
    errors: tuple[ScanError, ...] = (),
    files_scanned: int = 0,
    bytes_scanned: int = 0,
) -> ScanResult:
    """Assemble a result with the timing and version every scan carries."""

    return ScanResult(
        findings=findings,
        errors=errors,
        files_scanned=files_scanned,
        bytes_scanned=bytes_scanned,
        duration_seconds=time.monotonic() - started,
        tool_version=TOOL_VERSION,
    )


def _coerce_config(config: PathScanConfig | None) -> PathScanConfig:
    """Validate the caller's configuration.

    Raises:
        TypeError: If ``config`` is neither ``None`` nor a
            :class:`PathScanConfig`. A wrong type is a programming error
            in the caller, not a property of the filesystem, so it is loud.
    """

    if config is None:
        return DEFAULT_PATH_SCAN_CONFIG
    if not isinstance(config, PathScanConfig):
        raise TypeError(
            f"config must be a PathScanConfig, got {type(config).__name__}"
        )
    return config
