"""Where secrets are looked for.

A *source* is a place a secret can be: a file, a directory tree, a Git history.
Each gets its own module here, so that adding a source never means changing the
detection rules.

There are three, and they divide by what they *read* rather than by what they
find:

* :mod:`secret_shield.sources.filesystem` -- a file or a directory tree.
  :func:`scan_path` returns one :class:`~secret_shield.models.ScanResult`,
  delegating the per-file work to the same detection layers a single-file scan
  uses. Its settings object is :class:`PathScanConfig`.
* :mod:`secret_shield.sources.git_cmd` -- the one module that starts a process.
  It knows how Git is invoked and nothing about what is found in the output. It
  is deliberately not a source: it exposes no way to turn bytes into findings.
* :mod:`secret_shield.sources.git_history` -- a Git history. :func:`scan_history`
  returns a :class:`HistoryScan`, whose ``result`` attribute is an ordinary
  :class:`~secret_shield.models.ScanResult` any reporter accepts. It reads
  objects through ``git_cmd`` and imports no process machinery of its own.

That last split is the security boundary of the whole feature: exactly one module
in the package imports :mod:`subprocess`, and answering "could a hostile
repository make SecretShield run something?" means reading that one file.

Design rules that hold for every source in this package:

* **A scan does not raise for bad input.** Unreadable, binary, enormous and
  vanished files become entries in ``errors``. A source that stopped at the
  first unreadable file would be useless in CI.
* **Reported paths are root-relative and POSIX-style.** A report that embedded
  the scanning machine's absolute directory layout would leak it into CI logs
  and would differ between a laptop and a runner.
* **Every read is bounded.** Nothing here will allocate in proportion to
  attacker-chosen file size without a limit.
* **Order is deterministic.** Filesystem enumeration order is not promised by any
  operating system and varies in practice; Git's object enumeration order is not
  promised either. Results are sorted before use, so two scans of an unchanged
  target agree exactly.
* **Partial means declared.** A scan that hit a limit says so through
  ``errors``, never by being silent about what it did not see.
* **Nothing is written.** No source creates, moves or deletes anything. A
  scanner that could modify the tree it is scanning would be a scanner nobody
  should point at their working directory.
"""

from __future__ import annotations

from .filesystem import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_LINE_LENGTH,
    FileEntry,
    PathScanConfig,
    SkippedEntry,
    WalkResult,
    default_path_scan_config,
    scan_path,
    walk,
)
from .git_history import (
    DEFAULT_MAX_BLOBS,
    DEFAULT_MAX_BLOB_SIZE,
    DEFAULT_MAX_REFS,
    BlobRecord,
    GitScanConfig,
    HistoryScan,
    default_git_scan_config,
    scan_history,
)

__all__ = [
    "DEFAULT_MAX_BLOBS",
    "DEFAULT_MAX_BLOB_SIZE",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_LINE_LENGTH",
    "DEFAULT_MAX_REFS",
    "BlobRecord",
    "FileEntry",
    "GitScanConfig",
    "HistoryScan",
    "PathScanConfig",
    "SkippedEntry",
    "WalkResult",
    "default_git_scan_config",
    "default_path_scan_config",
    "scan_history",
    "scan_path",
    "walk",
]
