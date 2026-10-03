"""Deciding what a scan is allowed to look at.

Two filters, answering two different questions about a path before any of its
contents are read:

* :mod:`secret_shield.filters.binary` -- **is this text?** The bytes, judged on
  a bounded prefix. A NUL byte is the primary signal; undecodable UTF-8 and a
  high proportion of non-printable characters are the backstops.
* :mod:`secret_shield.filters.paths` -- **should this path be considered, and is
  it safe to read?** Policy on one side (``.git``, ``node_modules``, ignored
  extensions), filesystem safety on the other (symlink containment, regular
  files only, no loops).

The split matters because the two have different failure modes. A wrong binary
verdict silently loses a file. A wrong path decision either wastes time or walks
outside the directory the user asked about, which is a security problem rather
than a quality one. Keeping them apart means each can be tested, configured and
audited on its own terms.

Neither filter ever looks at a file's contents to decide whether to read it, and
neither puts any part of those contents into a reason string.
"""

from __future__ import annotations

from .binary import (
    ALLOWED_CONTROL_CHARACTERS,
    ALLOWED_SEPARATORS,
    DEFAULT_MAX_CONTROL_RATIO,
    DEFAULT_SNIFF_BYTES,
    BinaryConfig,
    BinaryVerdict,
    classify_bytes,
    default_binary_config,
    has_nul_byte,
)
from .paths import (
    DEFAULT_IGNORED_DIRECTORIES,
    DEFAULT_IGNORED_EXTENSIONS,
    DEFAULT_IGNORED_FILENAMES,
    Decision,
    PathFilterConfig,
    SkipReason,
    default_path_filter_config,
    is_regular_file,
    is_within,
    matches_ignored_path,
    normalize_relative_path,
    resolve_within,
)

__all__ = [
    # Binary detection
    "BinaryConfig",
    "BinaryVerdict",
    "classify_bytes",
    "default_binary_config",
    "has_nul_byte",
    "DEFAULT_SNIFF_BYTES",
    "DEFAULT_MAX_CONTROL_RATIO",
    "ALLOWED_CONTROL_CHARACTERS",
    "ALLOWED_SEPARATORS",
    # Path filtering
    "Decision",
    "PathFilterConfig",
    "SkipReason",
    "default_path_filter_config",
    "is_regular_file",
    "is_within",
    "matches_ignored_path",
    "normalize_relative_path",
    "resolve_within",
    "DEFAULT_IGNORED_DIRECTORIES",
    "DEFAULT_IGNORED_EXTENSIONS",
    "DEFAULT_IGNORED_FILENAMES",
]
