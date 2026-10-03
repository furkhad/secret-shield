"""Deciding which files a directory scan is allowed to look at.

Two questions are answered here, and they are different questions.

**Should this path be considered at all?** That is policy: ``.git``,
``node_modules`` and ``.venv`` are skipped by default because nothing a human
wrote by hand lives in them, and because they are enormous. The policy is data
on :class:`PathFilterConfig`, so it is configurable without touching this code.

**Is this path safe to follow and safe to read?** That is a property of the
filesystem, not a policy choice. Symlinks are the interesting case, because a
symlink is a pointer the scan did not create and the target is not in the tree
being walked. Reading through it can walk the scan out of the directory the
user asked about and into, say, ``/etc``, or into a parent directory that
contains an ancestor of the root, and a loop can make it walk forever.

The rules enforced here:

* A symlink is never followed unless :attr:`PathFilterConfig.follow_symlinks` is
  explicitly turned on, and even then only when its resolved target is inside
  the scan root. **A symlink outside the root is skipped, not followed.**
* Directories are visited at most once, tracked by device and inode, so a link
  that points at an ancestor cannot produce an unbounded walk.
* Only regular files are read. FIFOs, sockets, block devices, character devices
  and doors are skipped: reading a FIFO blocks forever waiting for a writer, and
  a device node has no size to bound a read by.
* Every name is judged by an exact match, never a substring match, so a file
  called ``envs.py`` or ``.gitignore`` is not mistaken for ``env`` or ``.git``.

Paths are matched as POSIX-style relative paths so that the result does not
depend on the platform's separator, and so that a caller can pass the same
ignore list on Windows and Linux.
"""

from __future__ import annotations

import enum
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

__all__ = [
    "DEFAULT_IGNORED_DIRECTORIES",
    "DEFAULT_IGNORED_EXTENSIONS",
    "DEFAULT_IGNORED_FILENAMES",
    "Decision",
    "PathFilterConfig",
    "SkipReason",
    "default_path_filter_config",
    "is_regular_file",
    "is_within",
    "matches_ignored_path",
    "normalize_relative_path",
    "resolve_within",
]


DEFAULT_IGNORED_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {
        # Version-control metadata. Every object in here is a compressed copy of
        # something already in the working tree or in history, so scanning it
        # finds nothing new and would be scanning zlib streams. Git history is a
        # separate source, not something to reach through the object store.
        ".git",
        ".hg",
        ".svn",
        # Virtual environments and dependency trees. Installed packages are
        # third-party code and are frequently shipped with example credentials
        # in their test fixtures, which would be pure false positives.
        ".venv",
        "venv",
        "env",
        "node_modules",
        # Regenerated caches. Enormous, and contain no author-written content.
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
    }
)
"""Directories skipped unless the caller asks for them.

The line drawn is *nothing a person wrote by hand lives here*. That excludes
version-control metadata, installed dependencies and tool caches. It
deliberately does **not** exclude ``dist``, ``build``, ``target`` or
``vendor``: build output is where a copied ``.env`` or an inlined bundle tends
to end up, and a secret scanner that skips build directories has opted out of
looking where leaked secrets actually land. Configure
:attr:`PathFilterConfig.ignored_directories` if a project disagrees.
"""

DEFAULT_IGNORED_FILENAMES: Final[frozenset[str]] = frozenset(
    {".DS_Store", "Thumbs.db", "desktop.ini", ".Spotlight-V100"}
)
"""Exact filenames skipped by default: operating-system indexer metadata.

They carry no source and no credentials, and they are regenerated constantly,
so scanning them wastes time and produces noise when they change under a build.
"""

DEFAULT_IGNORED_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        # Images
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff",
        ".tif", ".avif", ".heic", ".psd", ".ai", ".eps",
        # Fonts
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        # Audio and video
        ".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a",
        ".mp4", ".mov", ".avi", ".mkv", ".webm", ".wmv",
        # Archives
        ".zip", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".tar", ".tgz",
        ".jar", ".war", ".whl", ".iso", ".dmg",
        # Compiled objects
        ".class", ".pyc", ".pyo", ".pyd", ".so", ".dylib", ".dll", ".exe",
        ".bin", ".o", ".obj", ".a", ".lib", ".wasm", ".beam",
        # Documents and databases
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".db", ".sqlite", ".sqlite3", ".mdb", ".dat",
        # Debugging and profiling output
        # Lowercase: .dSYM bundles are named that way on disk, but extension
        # matching folds case, so the shipped default must already be in
        # normalised form or the config would not compare equal to itself.
        ".pdb", ".dsym", ".prof", ".core",
    }
)
"""Extensions skipped as a cheap pre-filter.

This is an optimisation and a policy knob, not the safety property:
:mod:`secret_shield.filters.binary` is what actually decides whether a file is
searchable. Filtering by extension first means a multi-megabyte PNG is never
opened at all.

Note what is *absent*. ``.svg`` is text and is scannable, ``.env`` has no
extension and is the single most likely place for a secret, and ``.pem`` and
``.key`` are text containing private keys that the scanner must reach. Only
formats that cannot contain searchable text are listed.
"""

class SkipReason(enum.StrEnum):
    """Why a path was not scanned.

    Every skip is one of these, so "my file was not scanned" always has a
    specific, reportable answer rather than a silent omission.

    The first five are policy -- the path was never a candidate. The rest are
    filesystem facts -- the path was a candidate and turned out not to be
    readable, or not to be what it appeared to be.
    """

    IGNORED_PATH = "ignored-path"
    """Matched a configured relative-path rule."""

    IGNORED_DIRECTORY = "ignored-directory"
    """Its name is a configured or default ignored directory name."""

    IGNORED_FILENAME = "ignored-filename"
    """Its exact name is a configured or default ignored filename."""

    IGNORED_EXTENSION = "ignored-extension"
    """Its extension is a configured or default ignored extension."""

    IGNORED_DEPTH = "ignored-depth"
    """It sits deeper than :attr:`PathFilterConfig.max_depth`."""

    SYMLINK = "symlink"
    """A symlink, and following symlinks is turned off."""

    SYMLINK_OUTSIDE_ROOT = "symlink-outside-root"
    """A symlink whose target resolves outside the scan root."""

    NOT_A_REGULAR_FILE = "not-a-regular-file"
    """A FIFO, socket, device, door or other non-regular file."""

    CIRCULAR_SYMLINK = "circular-symlink"
    """A directory already visited in this walk, reached again through a link."""

    TOO_LARGE = "too-large"
    """Larger than the configured maximum file size."""

    BINARY = "binary"
    """Classified as binary by :mod:`secret_shield.filters.binary`."""

    UNDECODABLE = "undecodable"
    """Not valid UTF-8, so not searchable source."""

    VANISHED = "vanished"
    """Disappeared between being listed and being opened."""

    UNREADABLE = "unreadable"
    """The filesystem refused the read, usually a permission error."""

    @property
    def is_policy(self) -> bool:
        """Whether this skip was a configured choice rather than a filesystem fact.

        Useful for separating "we decided not to look here" from "we looked and
        could not", which are different problems with different fixes.
        """

        return self in _POLICY_REASONS

    @property
    def description(self) -> str:
        """A fixed explanation, safe to put in a report.

        Never contains any part of the path or the file's contents, so a hostile
        filename cannot smuggle terminal escapes into a log through an error
        message.
        """

        return _SKIP_DESCRIPTIONS[self]


_POLICY_REASONS: Final[frozenset[SkipReason]] = frozenset(
    {
        SkipReason.IGNORED_PATH,
        SkipReason.IGNORED_DIRECTORY,
        SkipReason.IGNORED_FILENAME,
        SkipReason.IGNORED_EXTENSION,
        SkipReason.IGNORED_DEPTH,
        SkipReason.SYMLINK,
        SkipReason.SYMLINK_OUTSIDE_ROOT,
    }
)
"""The skips that were a configured choice rather than a filesystem fact."""

_SKIP_DESCRIPTIONS: Final[dict[SkipReason, str]] = {
    SkipReason.IGNORED_PATH: "matched a configured ignore rule",
    SkipReason.IGNORED_DIRECTORY: "directory name is on the ignore list",
    SkipReason.IGNORED_FILENAME: "filename is on the ignore list",
    SkipReason.IGNORED_EXTENSION: "file extension is on the ignore list",
    SkipReason.IGNORED_DEPTH: "deeper than the configured depth limit",
    SkipReason.SYMLINK: "is a symlink and following symlinks is disabled",
    SkipReason.SYMLINK_OUTSIDE_ROOT: "is a symlink pointing outside the scan root",
    SkipReason.NOT_A_REGULAR_FILE: "is not a regular file",
    SkipReason.CIRCULAR_SYMLINK: "directory was already visited in this scan",
    SkipReason.TOO_LARGE: "is larger than the configured size limit",
    SkipReason.BINARY: "looks like a binary file",
    SkipReason.UNDECODABLE: "is not valid UTF-8 text",
    SkipReason.VANISHED: "disappeared while the scan was running",
    SkipReason.UNREADABLE: "could not be read",
}


@dataclass(frozen=True, slots=True)
class Decision:
    """The filter's answer for one path: look at it, or do not.

    A decision is either accept or reject, never neither, and the two are
    constructed through :meth:`accept` and :meth:`reject` so the invariant
    cannot be violated by hand.
    """

    include: bool
    reason: SkipReason | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.include, bool):
            raise TypeError(f"include must be a bool, got {type(self.include).__name__}")
        if self.reason is not None and not isinstance(self.reason, SkipReason):
            raise TypeError(f"reason must be a SkipReason, got {type(self.reason).__name__}")
        if self.include and self.reason is not None:
            raise ValueError("an accepted path cannot carry a skip reason")
        if not self.include and self.reason is None:
            raise ValueError("a rejected path must carry a skip reason")

    @classmethod
    def accept(cls) -> Decision:
        """Return a decision to consider this path."""

        return cls(include=True, reason=None)

    @classmethod
    def reject(cls, reason: SkipReason) -> Decision:
        """Return a decision to skip this path, for ``reason``."""

        return cls(include=False, reason=reason)

    def __bool__(self) -> bool:
        # A plain method, deliberately not a @property.
        #
        # Writing `__bool__` as a property looks equivalent and is not: on
        # CPython 3.14 `bool(decision)` raises "TypeError: 'bool' object is not
        # callable" for a property-based `__bool__`, on every class, dataclass
        # or not. The method form has no such problem, and a test asserts that
        # `bool()` works so the property form cannot come back unnoticed.
        return self.include

    def __repr__(self) -> str:
        if self.include:
            return "Decision(include=True)"
        return f"Decision(include=False, reason={self.reason.value!r})"


ACCEPT: Final[Decision] = Decision.accept()
"""A shared accepted decision, so the common path allocates nothing."""


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------
#
# These live above ``PathFilterConfig`` because that class's ``__post_init__``
# calls them, and because ``DEFAULT_PATH_FILTER_CONFIG`` below constructs one
# at *import* time. Python resolves a global name when the line runs, not when
# the function is compiled, so a validator defined further down the module would
# raise ``NameError`` during import rather than at first use.


def _validate_names(values: object, name: str) -> frozenset[str]:
    """Validate a set of exact names and return it as a frozen set.

    Empty names are rejected rather than skipped: an empty string in an ignore
    list can never match anything, so it is always a mistake, and silently
    dropping it would hide a configuration bug that matters.

    A name containing a separator is rejected rather than quietly taking its
    last component. ``ignored_directories=("src/lib",)`` almost certainly means
    the caller wanted a *path*, and silently reducing it to ``lib`` would scan
    the wrong directories while appearing to work.
    """

    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be a collection of strings, not a string")
    try:
        items = frozenset(values)
    except TypeError:
        raise TypeError(f"{name} must be a collection of strings") from None

    for item in items:
        if not isinstance(item, str):
            raise TypeError(
                f"{name} must contain only strings, got {type(item).__name__}"
            )
        if not item:
            raise ValueError(f"{name} must not contain an empty name")
        if "/" in item or "\\" in item:
            raise ValueError(
                f"{name} entries must be bare names, not paths; got {item!r}. "
                "Use ignored_paths for paths."
            )
    return items


def _validate_extensions(values: object, name: str) -> frozenset[str]:
    """Validate extensions, normalising to lowercase with a leading dot.

    ``"png"``, ``".png"`` and ``".PNG"`` all mean the same thing, so all three
    are accepted and stored as ``".png"``. Accepting them is kinder than
    rejecting them, and normalising means the hot path compares one form.
    """

    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be a collection of strings, not a string")
    try:
        items = list(values)
    except TypeError:
        raise TypeError(f"{name} must be a collection of strings") from None

    normalized: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            raise TypeError(
                f"{name} must contain only strings, got {type(item).__name__}"
            )
        lowered = item.lower()
        if not lowered:
            raise ValueError(f"{name} must not contain an empty extension")
        if "/" in lowered or "\\" in lowered:
            raise ValueError(f"{name} entries must be extensions, not paths; got {item!r}")
        if lowered.startswith(".") and len(lowered) > 1:
            normalized.add(lowered)
        elif lowered.startswith("."):
            raise ValueError(f"{name} must not contain a bare dot; got {item!r}")
        else:
            normalized.add("." + lowered)
    return frozenset(normalized)


def _validate_paths(values: object, name: str) -> tuple[str, ...]:
    """Validate relative ignore paths, normalising separators.

    Absolute paths and ``..`` segments are rejected. An ignore list is a
    statement about what lies *inside* the scan root, and a rule that could
    reach outside it would be a rule whose meaning depends on where the scan
    happens to be rooted -- which is exactly the kind of location-dependent
    behaviour that makes a scanner's results unreproducible.
    """

    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be a collection of strings, not a string")
    try:
        items = list(values)
    except TypeError:
        raise TypeError(f"{name} must be a collection of strings") from None

    normalized: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise TypeError(
                f"{name} must contain only strings, got {type(item).__name__}"
            )
        if not item.strip():
            raise ValueError(f"{name} must not contain an empty path")
        if item.startswith("/") or item.startswith("\\"):
            raise ValueError(
                f"{name} entries must be relative to the scan root; got {item!r}"
            )
        if PurePosixPath(item.replace("\\", "/")).is_absolute():
            raise ValueError(
                f"{name} entries must be relative to the scan root; got {item!r}"
            )

        parts = [part for part in item.replace("\\", "/").split("/") if part and part != "."]
        if ".." in parts:
            raise ValueError(
                f"{name} entries must not escape the scan root with '..'; got {item!r}"
            )
        if not parts:
            raise ValueError(f"{name} must not contain an empty path")
        normalized.append("/".join(parts))

    # Sorted and de-duplicated so that two logically identical configurations
    # compare equal and hash equal, which keeps results reproducible and makes
    # "the same configuration" a checkable statement rather than a hope.
    return tuple(sorted(set(normalized)))


@dataclass(frozen=True, slots=True)
class PathFilterConfig:
    """Which paths a directory scan may look at.

    Attributes:
        ignored_directories: Directory *names*, matched exactly, at any depth.
            A directory called ``.git`` anywhere in the tree is skipped.
        ignored_filenames: File names, matched exactly, at any depth.
        ignored_extensions: File extensions including the leading dot, matched
            case-insensitively against the final suffix of the name.
        ignored_paths: Relative POSIX paths, matched exactly or as a directory
            prefix. ``"build"`` skips ``build/`` and everything under it;
            ``"docs/generated"`` skips that directory and its contents.
        follow_symlinks: Whether a symlink may be followed at all. Off by
            default. Even when on, a symlink whose target resolves outside the
            scan root is skipped with
            :attr:`SkipReason.SYMLINK_OUTSIDE_ROOT`.
        max_depth: Deepest file to include, counted from the scan root. Files
            directly in the root are depth ``0`` and files one directory down are
            depth ``1``, so ``max_depth=0`` scans only the root's own files and
            ``max_depth=1`` also scans one level of subdirectory. ``None`` means
            no limit.

    Raises:
        TypeError: If a collection is not an iterable of strings, or a limit is
            the wrong type.
        ValueError: If an extension lacks its dot, an ignore path is absolute
            or escapes the root with ``..``, or a limit is out of range.
    """

    ignored_directories: frozenset[str] = DEFAULT_IGNORED_DIRECTORIES
    ignored_filenames: frozenset[str] = DEFAULT_IGNORED_FILENAMES
    ignored_extensions: frozenset[str] = DEFAULT_IGNORED_EXTENSIONS
    ignored_paths: tuple[str, ...] = ()
    follow_symlinks: bool = False
    max_depth: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "ignored_directories", _validate_names(self.ignored_directories, "ignored_directories")
        )
        object.__setattr__(
            self, "ignored_filenames", _validate_names(self.ignored_filenames, "ignored_filenames")
        )
        object.__setattr__(
            self,
            "ignored_extensions",
            _validate_extensions(self.ignored_extensions, "ignored_extensions"),
        )
        object.__setattr__(
            self, "ignored_paths", _validate_paths(self.ignored_paths, "ignored_paths")
        )

        if not isinstance(self.follow_symlinks, bool):
            raise TypeError(
                f"follow_symlinks must be a bool, got {type(self.follow_symlinks).__name__}"
            )
        if self.max_depth is not None:
            if isinstance(self.max_depth, bool) or not isinstance(self.max_depth, int):
                raise TypeError(
                    f"max_depth must be an int or None, got {type(self.max_depth).__name__}"
                )
            if self.max_depth < 0:
                raise ValueError("max_depth must be non-negative")

    # -- Individual rules ---------------------------------------------------
    #
    # Public so that a caller filtering its own list, or writing tests, can ask
    # one question at a time instead of constructing a Decision by hand.

    def ignores_directory_name(self, name: str) -> bool:
        """Return whether ``name`` is an ignored directory name.

        An exact match, never a substring. ``envs``, ``environment`` and
        ``env.py`` are all scanned; only ``env`` is skipped.
        """

        return name in self.ignored_directories

    def ignores_filename(self, name: str) -> bool:
        """Return whether ``name`` is an ignored exact filename."""

        return name in self.ignored_filenames

    def ignores_extension(self, name: str) -> bool:
        """Return whether ``name``'s extension is ignored.

        The final suffix only, lowercased, so ``config.ENV`` is skipped on a
        case-sensitive filesystem for the same reason ``.env`` is. A name with
        no extension is never skipped here.
        """

        return _extension_of(name) in self.ignored_extensions

    def ignores_path(self, relative: str) -> bool:
        """Return whether the relative path ``relative`` is ignored.

        ``relative`` is POSIX-style and relative to the scan root. Each
        configured entry matches either the whole path or one of its ancestor
        directories, so ``"vendor"`` covers ``vendor/a/b/c.py``.
        """

        return matches_ignored_path(relative, self.ignored_paths)

    def decide(self, name: str, relative: str, *, is_directory: bool) -> Decision:
        """Return the decision for one entry found at ``relative``.

        Args:
            name: The entry's own basename.
            relative: Its POSIX path relative to the scan root.
            is_directory: Whether the entry is a directory.

        Returns:
            A :class:`Decision`. Rules are applied most specific first --
            configured path, then name, then extension -- so the reported
            reason is the one the caller most likely meant.

        Note:
            This is a *name* judgement only. It does not follow symlinks, stat
            anything or check file types; :func:`is_regular_file` and
            :func:`resolve_within` do that, and
            :func:`secret_shield.sources.filesystem.walk` composes the three.
        """

        normalized = normalize_relative_path(relative, fallback=name)

        if self.ignores_path(normalized):
            return Decision.reject(SkipReason.IGNORED_PATH)

        if is_directory:
            if self.ignores_directory_name(name):
                return Decision.reject(SkipReason.IGNORED_DIRECTORY)
            return ACCEPT

        if self.ignores_filename(name):
            return Decision.reject(SkipReason.IGNORED_FILENAME)

        if self.ignores_extension(name):
            return Decision.reject(SkipReason.IGNORED_EXTENSION)

        return ACCEPT


DEFAULT_PATH_FILTER_CONFIG: Final[PathFilterConfig] = PathFilterConfig()
"""The shipped defaults: conservative skips and no symlink following."""


def default_path_filter_config() -> PathFilterConfig:
    """Return a fresh copy of the default path filter configuration."""

    return PathFilterConfig(
        ignored_directories=DEFAULT_IGNORED_DIRECTORIES,
        ignored_filenames=DEFAULT_IGNORED_FILENAMES,
        ignored_extensions=DEFAULT_IGNORED_EXTENSIONS,
    )


def _extension_of(name: str) -> str:
    """Return the final suffix of ``name``, lowercased, dot included.

    ``PurePosixPath.suffix`` returns ``""`` for a dotfile like ``.env``, which
    is exactly right: ``.env`` has no extension and must never be filtered by
    one.
    """

    return PurePosixPath(name).suffix.lower()


def normalize_relative_path(relative: str, *, fallback: str = "") -> str:
    """Return ``relative`` as a clean POSIX path with no leading or trailing ``/``.

    Backslashes become forward slashes so a caller passing a Windows-style
    ignore list gets the same behaviour on every platform. ``.`` and ``..``
    segments are *removed* rather than resolved, because the result is a
    reporting key and a lookup key, never a filesystem path: it must not be able
    to name a location outside the root.

    Args:
        relative: The path to normalise. Any value is accepted; non-strings are
            stringified, since this is fed from ``os.scandir`` names that are
            already text.
        fallback: Used when ``relative`` normalises to nothing, which happens
            for ``""``, ``"."``, ``"/"`` or ``".."``. A root-relative path is
            never empty in practice, so an empty result means the caller passed
            a bad key; substituting the entry's own basename keeps the result
            usable instead of producing a path that matches everything.

    Returns:
        A slash-joined path with no empty, ``.`` or ``..`` segments. May be the
        empty string if both arguments normalise to nothing.
    """

    return _normalize(relative) or _normalize(fallback)


def _normalize(value: str) -> str:
    """Strip empty, ``.`` and ``..`` segments and join the rest with ``/``."""

    parts = [
        part
        for part in str(value).replace("\\", "/").split("/")
        if part and part not in {".", ".."}
    ]
    return "/".join(parts)


def matches_ignored_path(relative: str, ignored_paths: tuple[str, ...]) -> bool:
    """Return whether ``relative`` is covered by any entry in ``ignored_paths``.

    An entry matches the whole path or any of its ancestors. ``"build"``
    therefore covers ``build/x.py`` and ``build/deep/y.py``, while
    ``"build/deep"`` covers only the latter. Comparison is on whole path
    segments, so ``"build"`` never matches ``"buildings/x.py"``.

    Globs are deliberately not supported. A glob would make the ignore list a
    regular-expression surface over attacker-influenced filenames, for a
    feature a caller can build out of explicit entries; the simpler matching is
    the safer one and it is what ``.gitignore``-shaped callers already produce.
    """

    if not ignored_paths:
        return False

    parts = normalize_relative_path(relative).split("/")
    if not parts or parts == [""]:
        return False

    prefixes = {""}
    for index in range(1, len(parts) + 1):
        prefixes.add("/".join(parts[:index]))

    return any(entry in prefixes for entry in ignored_paths)


def is_regular_file(path: Path, *, follow_symlinks: bool = False) -> bool:
    """Return whether ``path`` is a regular file.

    Args:
        path: The path to test.
        follow_symlinks: Whether to resolve a symlink first. With the default
            ``False``, a symlink to a regular file is **not** a regular file,
            which is what stops the walk from stepping outside the root.

    Note:
        Deliberately excludes FIFOs, sockets, block and character devices,
        doors and anything else that is not ``S_ISREG``. Opening a FIFO blocks
        until a writer appears, and a device node offers no bound on how much a
        read would return, so both are skipped rather than scanned.
    """

    try:
        info = os.stat(path, follow_symlinks=follow_symlinks)
    except (OSError, ValueError):
        # A vanished path, a broken symlink, or a name the OS rejects. All of
        # them mean "not a regular file we can read", which is the answer the
        # caller needs; none of them is worth failing a scan over.
        return False
    return stat.S_ISREG(info.st_mode)


def is_within(path: Path, root: Path) -> bool:
    """Return whether ``path`` is ``root`` or lies inside it.

    Both arguments must already be resolved. This is a lexical containment test,
    not a filesystem one, so it cannot be defeated by a symlink that appears
    between the check and the read; see the module docstring for how far that
    residual risk is reduced.
    """

    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def resolve_within(path: Path, root: Path) -> Path | None:
    """Resolve ``path`` and return the target, or ``None`` if it escapes ``root``.

    This is the gate that makes "never follow a symlink outside the scan root"
    true rather than aspirational. It resolves the whole chain -- a link that
    points at another link that points at ``/etc`` resolves to ``/etc`` -- and
    returns ``None`` unless the final target is ``root`` or inside it.

    Args:
        path: The symlink to resolve.
        root: The already-resolved scan root.

    Returns:
        The resolved target, or ``None`` when the link is broken, loops, or
        points outside the root.
    """

    try:
        target = path.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        # OSError: broken link, permission denied, or a name too long to
        # resolve. RuntimeError: a symlink loop. ValueError: a path the OS
        # refuses outright. None of them can be resolved, so none is followed.
        return None

    return target if is_within(target, root) else None
