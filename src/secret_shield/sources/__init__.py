"""Where secrets are looked for.

A *source* is a place a secret can be: a file, a directory tree, and in a later
stage a Git history. Each gets its own module here, so that adding a source
never means changing the detection rules.

:mod:`secret_shield.sources.filesystem` is the first. :func:`scan_path` takes
either a file or a directory and returns one
:class:`~secret_shield.models.ScanResult`, delegating the per-file work to the
same detection layers a single-file scan uses. Its settings object is
:class:`PathScanConfig`.

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
  operating system and varies in practice, so results are sorted before use and
  two scans of an unchanged tree agree exactly.
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
