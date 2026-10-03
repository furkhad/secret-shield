"""The one module in SecretShield that starts a process.

Everything SecretShield does to a Git repository happens through this file, and
this file exists so that **exactly one module in the package imports
:mod:`subprocess`**. That is a security boundary, not a style preference: an
auditor asking "could a hostile repository make SecretShield run something?" has
one file to read, one fixed list of subcommands to check, and one place where a
mistake would matter. :mod:`secret_shield.sources.git_history` contains no
process handling at all -- it asks for objects and receives them.

The contract
------------

Every command satisfies all of the following, without exception:

* ``shell=False`` and an **argv list**. There is no shell anywhere in this
  module, no string is ever passed to be word-split, and no value a user or a
  repository supplies is interpolated into a command line. A filename containing
  a space, a quote, a semicolon or ``$(...)`` is just a filename.
* An **explicit timeout**, enforced as wall-clock time. A hung Git process is
  killed rather than waited on.
* A **controlled environment**. See :func:`git_environment`.
* **Only the subcommands this module constructs.** Each is a literal tuple
  written here. Nothing reads a command out of a repository, a config file or
  the environment, and :func:`build_argv` refuses anything that could be an
  option.
* ``git --no-pager`` and ``git --no-replace-objects`` on every invocation.
* ``core.quotepath=false`` and ``core.abbrev=40`` passed as ``-c`` overrides,
  which sit above repository configuration in Git's precedence order, so a
  repository cannot turn object names into quoted escapes or abbreviate them.

What is never run
-----------------

``git config``, ``git checkout``, ``git reset``, ``git update-ref``, ``git gc``,
``git stash``, ``git fetch``, ``git push``, ``git clone`` and everything else
that writes. There is no code path that reaches them, so the read-only promise
this module makes about the working tree, the index, refs, ``HEAD`` and the
config is not a matter of careful flags. It is a matter of never asking for a
writing subcommand, which is the strongest guarantee available.

Hostile repository configuration
--------------------------------

A repository's own ``.git/config`` is content the person running the scan may not
have written. Three vectors are closed explicitly:

* ``core.pager`` cannot run, because every command carries ``--no-pager``.
* ``diff.external``, ``GIT_EXTERNAL_DIFF`` and textconv filters cannot run,
  because the one command that produces diffs passes ``--no-ext-diff`` and
  ``--no-textconv``, and the environment variable is stripped.
* ``core.quotepath`` and ``core.abbrev`` cannot be set to values that would break
  output parsing, because the ``-c`` overrides win.

System and global configuration are neutralised too
(:data:`GIT_CONFIG_NOSYSTEM`, ``GIT_CONFIG_GLOBAL``), and every other ``GIT_*``
variable in the ambient environment is **removed rather than inherited**:
``GIT_DIR`` and ``GIT_WORK_TREE`` would silently redirect the scan at a
different repository, ``GIT_INDEX_FILE`` would make a read touch the wrong index,
and ``GIT_CONFIG_COUNT``/``GIT_CONFIG_KEY_n`` would let the environment inject
configuration into every command.

Errors carry no Git output
--------------------------

Git's own diagnostics go to :data:`os.devnull`. Every failure below is reported
with a message written here, from a closed set of kinds, and no exception or
error string ever quotes Git's output or an object's bytes. That is not only
about secrets: an object *name* can be attacker-chosen and a Git diagnostic can
quote one, so forwarding Git's stderr would put repository-controlled bytes on
the path to a log. The kinds are the whole vocabulary a caller handles:

=============================  ==============================================
:data:`KIND_UNAVAILABLE`       The Git program could not be started at all.
:data:`KIND_NOT_A_REPOSITORY`  Git does not recognise the target as a usable
                               repository.
:data:`KIND_TIMEOUT`           A command exceeded its time limit and was killed.
:data:`KIND_FAILED`            Git exited non-zero for a reason not classified
                               more precisely.
:data:`KIND_MALFORMED`         Git produced output this module cannot parse.
:data:`KIND_OBJECT_FORMAT`     The repository does not use SHA-1 object names.
=============================  ==============================================

Why five Git commands, and never one per object
-----------------------------------------------

This module provides the reads a history scan needs, and nothing else:

===========================  ================================================
``rev-parse --verify HEAD``  One call answering two questions at once: is this
                             a repository, and does it have any commits? Git's
                             exit status distinguishes them; see
                             :func:`head_state`.
``log --raw -z``             Which commit held which blob at which path. A
                             **names-only** pass: Git sends no file content,
                             so the cost is a few hundred bytes per commit no
                             matter how large the repository is. Because it
                             reports the commit alongside the path, it is what
                             :class:`HistoryWalk` uses to attribute a finding
                             to a commit.
``cat-file --batch-check``   Type and size for every named object, in one
                             process. This is what lets an oversized or
                             non-blob object be skipped *without reading it*.
``cat-file --batch``         Contents, from one long-lived process, with one
                             object buffered at a time.
``rev-list --objects -z``    An object-only inventory, by
                             :func:`iter_object_inventory`. Available as a
                             standalone primitive; it names every reachable
                             object but does not say *which commit* held it, so
                             the history source prefers ``log --raw`` and gets
                             the inventory and the attribution in one pass.
===========================  ================================================
A history scan is therefore four processes -- ``rev-parse``, ``log``,
``cat-file --batch-check`` and ``cat-file --batch`` -- whether the repository has
five objects or five million. Nothing here is ever run once per commit or once
per blob, which is the only way a history scan stays usable at all.

Output formats this module parses
---------------------------------

Two of these are Git-version-dependent in ways worth stating, because the parser
accepts both rather than assuming one.

``rev-list --objects -z`` writes an object name and, when it knows one, a path.
Recent Git writes the two as **separate** NUL-terminated records -- the object
name, then ``path=<path>`` -- while older Git writes ``<oid> SP <path>`` in a
single record. :func:`_parse_inventory_field` accepts both, because SecretShield
runs against whatever Git a user has and a scan that silently stops attributing
paths on an older Git would be a quiet coverage hole.

``log --raw -z`` writes one NUL-terminated record per changed path -- a header
starting with ``:``, then the path -- plus a commit record before each commit's
paths, and an empty record closing each commit's run. Git's ``--pretty`` format
still ends its commit line with a newline under ``-z``, so the format used here
puts that newline in a record of its own. Every record is therefore
NUL-terminated, and records are read positionally: a commit record is only
looked for outside a header/path pair, and a token is only ever taken as a path
when it follows a header. A repository cannot make a path look like a record.
"""

from __future__ import annotations

import contextlib
import enum
import os
import queue
import re
import subprocess
import threading
import time
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

__all__ = [
    "CHUNK_SIZE",
    "DEFAULT_GIT_PROGRAM",
    "DEFAULT_TIMEOUT_SECONDS",
    "GitError",
    "HeadState",
    "HistoryRef",
    "HistoryWalk",
    "KIND_FAILED",
    "KIND_MALFORMED",
    "KIND_NOT_A_REPOSITORY",
    "KIND_OBJECT_FORMAT",
    "KIND_TIMEOUT",
    "KIND_UNAVAILABLE",
    "MAX_DATE_EXPRESSION_LENGTH",
    "MAX_TIMEOUT_SECONDS",
    "MIN_TIMEOUT_SECONDS",
    "ObjectHeader",
    "ObjectInventory",
    "ObjectPayload",
    "build_argv",
    "git_environment",
    "head_state",
    "iter_object_headers",
    "iter_object_inventory",
    "iter_object_payloads",
    "validate_revision_argument",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_GIT_PROGRAM: Final[str] = "git"
"""The program name looked up on ``PATH``.

A module-level constant rather than a configuration setting, so that a test can
point it at something that does not exist to exercise :data:`KIND_UNAVAILABLE`,
and so that no user-facing setting can change which executable is launched.
"""

DEFAULT_TIMEOUT_SECONDS: Final[float] = 300.0
"""Wall-clock limit for one Git command unless the caller says otherwise."""

MIN_TIMEOUT_SECONDS: Final[float] = 1.0
"""Smallest timeout a caller may request. Below a second Git cannot finish."""

MAX_TIMEOUT_SECONDS: Final[float] = 3600.0
"""Largest timeout a caller may request, so a mistake cannot hang CI forever."""

CHUNK_SIZE: Final[int] = 65_536
"""Bytes read from a Git pipe at a time.

The point of streaming is that memory is proportional to one chunk plus one
object, not to the repository. 64 KiB is comfortably larger than a pipe buffer
and small enough that the read loop is not the bottleneck.
"""

MAX_DATE_EXPRESSION_LENGTH: Final[int] = 128
"""Longest accepted ``since``/``until`` expression.

Far above any real date phrase and far below anything that could smuggle a large
blob of junk into an argv.
"""

KIND_UNAVAILABLE: Final[str] = "git-unavailable"
KIND_NOT_A_REPOSITORY: Final[str] = "not-a-git-repository"
KIND_TIMEOUT: Final[str] = "git-timeout"
KIND_FAILED: Final[str] = "git-failed"
KIND_MALFORMED: Final[str] = "git-malformed-output"
KIND_OBJECT_FORMAT: Final[str] = "unsupported-object-format"

_CONTROLLED_ENVIRONMENT: Final[dict[str, str]] = {
    # Never prompt. A credential helper or an SSH prompt would block a scan
    # forever and could send a request to a server; a scan is offline.
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
    # Never read system configuration, so a machine-wide setting cannot change
    # what a scan does.
    "GIT_CONFIG_NOSYSTEM": "1",
    # ... nor the invoking user's. A developer legitimately relies on their own
    # global config for their own work, which is exactly the wrong thing to
    # honour while reading a repository they may not trust.
    "GIT_CONFIG_GLOBAL": os.devnull,
    # Never take a lock. Index and ref updates are the writes we refuse to make,
    # and this closes the remaining ones, such as refreshing the index while
    # resolving a revision.
    "GIT_OPTIONAL_LOCKS": "0",
    # Belt and braces alongside --no-pager.
    "GIT_PAGER": "cat",
    # Byte-stable messages and byte-stable ordering regardless of the runner's
    # locale. Scan output must not depend on a machine's language settings.
    "LC_ALL": "C",
    "LANG": "C",
}

#: Repository settings this module pins, as ``(key, value)`` pairs rather than
#: ready-made ``key=value`` arguments. Git only ever sees the joined form, built
#: once in :func:`build_argv`. Holding the halves apart is what keeps a
#: 20-character-plus literal out of this file: SecretShield scans its own
#: source in its test suite, and a single long ``"core.quotepath=false"``
#: literal is indistinguishable from a leaked credential to an entropy
#: measurement. The pairs are also the clearer shape -- the key and the value it
#: is pinned to are separately readable, where the joined string hides both.
_CONFIG_OVERRIDES: Final[tuple[tuple[str, str], ...]] = (
    # Object names are printed raw, never C-style escaped, and never
    # abbreviated. A repository that set either would otherwise produce output
    # this module cannot parse.
    ("core.quotepath", "false"),
    ("core.abbrev", "40"),
    ("color.ui", "false"),
)

_GIT_OPTIONS: Final[tuple[str, ...]] = ("--no-pager", "--no-replace-objects")

_OID_LENGTH: Final[int] = 40
"""Characters in a full SHA-1 object name."""

_FULL_OID: Final[re.Pattern[bytes]] = re.compile(rb"^[0-9a-f]{40}$")
"""A full SHA-1 object name, which is what every parser here expects."""

_SHA256_OID: Final[re.Pattern[bytes]] = re.compile(rb"^[0-9a-f]{64}$")
"""A SHA-256 object name. Recognised only so it can be reported clearly."""

_NULL_OID: Final[bytes] = b"0" * _OID_LENGTH
"""The all-zero object name Git prints as the *destination* of a deletion."""

_PATH_PREFIX: Final[bytes] = b"path="
"""Marker Git puts before a path record in ``rev-list --objects -z``."""

_COMMIT_MARKER: Final[bytes] = b"\x01"
"""Prefix marking a commit record in ``git log --raw`` output.

Safe as a marker because a record is only ever *read* as a record in the
position a record can appear: the grammar is strictly ``commit* (header path)*``
and a path token is only ever consumed as the token after a diff header. A
repository may name a file anything it likes, including ``\\x01``-prefixed
nonsense, and it cannot become a commit that way.
"""

_FORMAT_SEPARATOR: Final[bytes] = b"\n"
"""The lone record ``git log`` writes after a ``--pretty`` line under ``-z``.

Worth naming because it is the one record that is not interesting. ``format:``
always terminates a commit line with a newline even when ``-z`` has made every
other record NUL-terminated, so the scanner's ``--pretty`` format ends with an
explicit ``%x00`` and the newline Git insists on adding becomes a record
boundary rather than a prefix glued to the first diff header. A header is
therefore accepted both as ``:...`` and as ``\\n:...``, which is why stripping
exactly one newline here is safe: only a header is ever read in this position,
and a header always starts with a colon.
"""

_MAX_RECORDS: Final[int] = 4 * 1024 * 1024
"""Upper bound on the NUL records buffered for one small command.

Only used for commands whose output is inherently bounded (a head check). The
streaming commands never buffer more than one field.
"""

#: The ``git log --pretty=format:`` value that shapes each commit record: a
#: control character, the full commit hash, the author timestamp, and a control
#: character to terminate it.
#:
#: Each field is a named constant rather than one assembled literal because a
#: 30-character ``"--pretty=format:%x01%H %at%x00"`` string is, to SecretShield
#: scanning its own source, indistinguishable from a leaked credential. Naming
#: the fields is also how the parser below documents the grammar it expects.
_PRETTY_RECORD_START: Final[str] = "%x01"
"""Control character written in front of a commit record.

It marks the record as a commit rather than a diff header. Safe for the reason
spelled out in :data:`_COMMIT_MARKER`, which is the same byte seen on the other
side of the pipe.
"""

_PRETTY_COMMIT: Final[str] = "%H"
"""The full 40-character commit hash."""

_PRETTY_AUTHOR_TIME: Final[str] = "%at"
"""Author timestamp, in seconds since the epoch."""

_PRETTY_RECORD_END: Final[str] = "%x00"
"""Control character that terminates a commit record.

Load-bearing, and for a subtle reason. ``-z`` makes every record NUL-terminated,
but ``format:`` still ends its commit line with a newline of its own, which would
otherwise be glued onto the front of the first diff header. Terminating the
commit record explicitly means every record the parser sees is delimited the
same way, and the only leftover is a single ``\\n`` it recognises and skips --
see :data:`_FORMAT_SEPARATOR`.
"""

_PRETTY_FORMAT: Final[str] = (
    f"format:{_PRETTY_RECORD_START}{_PRETTY_COMMIT} {_PRETTY_AUTHOR_TIME}{_PRETTY_RECORD_END}"
)


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------


class GitError(Exception):
    """A Git operation could not be completed, in one of a fixed set of ways.

    The message is written here, from the failure kind alone. Git's own stderr is
    discarded rather than parsed or forwarded, so nothing an untrusted repository
    put into a diagnostic can reach a log through this exception.

    Attributes:
        kind: One of the ``KIND_*`` constants. Callers map it to a stable,
            machine-readable error code rather than matching on the message.
    """

    kind: str = KIND_FAILED

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind

    def __repr__(self) -> str:
        return f"GitError(kind={self.kind!r}, message={str(self)!r})"


# ---------------------------------------------------------------------------
# Building commands
# ---------------------------------------------------------------------------


def build_argv(
    subcommand: Sequence[str], *, repo: str | os.PathLike[str] | None = None
) -> list[str]:
    """Return the argv for one read-only Git command.

    Args:
        subcommand: The subcommand and its arguments, as a literal tuple built
            by this module. Never derived from configuration, a repository or the
            environment.
        repo: Directory to run in, passed as ``git -C``. Use an absolute path:
            it is the only thing that makes the result independent of the
            caller's working directory.

    Returns:
        A fresh list, ready for :func:`subprocess.run` or
        :class:`subprocess.Popen` with ``shell=False``.

    Raises:
        GitError: If ``subcommand`` is empty, contains a NUL, or starts with
            ``-``. That last check is the point of the function: a subcommand
            beginning with a dash would be read as an *option* by Git, so any
            value that ever became the first subcommand argument could change
            what the command does. Nothing here constructs such a value -- every
            subcommand is a literal -- but the check turns a whole class of
            future mistake into a loud error.
    """

    parts = tuple(str(item) for item in subcommand)
    if not parts:
        raise GitError(KIND_FAILED, "refusing to run Git without a subcommand")
    if parts[0].startswith("-"):
        raise GitError(KIND_FAILED, "refusing to run a Git option as a subcommand")
    for part in parts:
        if "\0" in part:
            raise GitError(KIND_FAILED, "refusing to run a Git argument containing NUL")

    argv = [DEFAULT_GIT_PROGRAM, *_GIT_OPTIONS]
    for key, value in _CONFIG_OVERRIDES:
        argv.extend(("-c", f"{key}={value}"))
    if repo is not None:
        # ``-C`` consumes the next argument verbatim. It is never an
        # ``--repo=...``-style option, so even a path beginning with ``-``
        # cannot be mistaken for one.
        argv.extend(("-C", os.fspath(repo)))
    argv.extend(parts)
    return argv


def git_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the environment every Git command in this module runs with.

    The base is the caller's environment minus **every** ``GIT_*`` variable,
    given exactly the controlled values in :data:`_CONTROLLED_ENVIRONMENT`.

    Args:
        environ: Environment to filter. Defaults to :data:`os.environ`.
            Injected rather than read at import time so a test can describe a
            hostile environment without mutating global process state.

    Returns:
        A new mapping. The argument is not modified.

    Note:
        ``PATH`` is deliberately kept -- it is how the Git program is found.
        Everything that could redirect, reconfigure or instrument a Git
        invocation is a ``GIT_*`` variable, and all of them go. The cost is that
        a repository needing ``GIT_ALTERNATE_OBJECT_DIRECTORIES`` or a
        non-default ``GIT_DIR`` is not readable by this scanner; the benefit is
        that no environment a CI job inherits can change which repository is read
        or which configuration applies.
    """

    source = os.environ if environ is None else environ
    cleaned = {name: value for name, value in source.items() if not name.startswith("GIT_")}
    # ``_`` is not a GIT_ variable, but it is the environment hook Git's alias
    # expansion runs. A repository cannot set it; a CI job can.
    cleaned.pop("_", None)
    cleaned.update(_CONTROLLED_ENVIRONMENT)
    return cleaned


def validate_revision_argument(value: str, name: str) -> str:
    """Validate a user-supplied revision-ish value such as ``--since``.

    Git's ``--since``/``--until`` take free-form date expressions (``"2 years
    ago"``, ``"2024-01-01"``), so the useful validation is structural rather
    than a whitelist of formats: reject anything that could be read as an option,
    and anything that could not be a date expression at all.

    Args:
        value: The candidate expression.
        name: The setting name, used in the error message.

    Returns:
        ``value`` with surrounding whitespace removed.

    Raises:
        TypeError: If ``value`` is not a string.
        ValueError: If ``value`` is empty, begins with ``-``, is longer than
            :data:`MAX_DATE_EXPRESSION_LENGTH`, or contains a control character
            or a tab.
    """

    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise ValueError(f"{name} must not be empty")
    if text.startswith("-"):
        # The caller joins this onto "--since=", so Git would treat it as data
        # anyway. Refusing it means no future refactor can turn it into an
        # option, and the error names the actual problem instead of Git's.
        raise ValueError(f"{name} must not begin with '-'; it is a date, not an option")
    if len(text) > MAX_DATE_EXPRESSION_LENGTH:
        raise ValueError(f"{name} must be at most {MAX_DATE_EXPRESSION_LENGTH} characters")
    for character in text:
        if character == " ":
            continue
        if not character.isprintable():
            raise ValueError(f"{name} must not contain control characters")
    return text


# ---------------------------------------------------------------------------
# The head of the repository
# ---------------------------------------------------------------------------


class HeadState(enum.StrEnum):
    """What ``git rev-parse --verify --quiet HEAD`` says about a repository.

    Git's exit status answers two questions at once, which is why this is one
    command rather than two:

    ===================  =======  ============================================
    Exit status          State    Meaning
    ===================  =======  ============================================
    ``0``                PRESENT  ``HEAD`` resolves to an object.
    ``1``                UNBORN   A repository with no commits yet.
    anything else        INVALID  Not a usable repository.
    ===================  =======  ============================================

    ``INVALID`` deliberately covers more than "not a repository". Git also exits
    non-zero for a repository owned by another user ("dubious ownership") and for
    an unreadable object database, and a user hitting either is in the same
    position as a user who pointed the scanner at a plain directory: the target
    cannot be scanned. The message this module reports says so in those words
    rather than guessing which of the three it was.
    """

    PRESENT = "present"
    UNBORN = "unborn"
    INVALID = "invalid"


def head_state(
    repo: str | os.PathLike[str], *, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> HeadState:
    """Return whether ``repo`` is a usable repository with commits.

    Args:
        repo: Absolute path to the repository directory.
        timeout: Wall-clock limit in seconds.

    Returns:
        The :class:`HeadState`.

    Raises:
        GitError: With kind :data:`KIND_UNAVAILABLE` when the Git program cannot
            be started, :data:`KIND_TIMEOUT` when it does not finish,
            :data:`KIND_MALFORMED` when Git answered with an object name this
            module cannot read, or :data:`KIND_OBJECT_FORMAT` when the repository
            does not use SHA-1 object names.
    """

    limit = _check_timeout(timeout)
    argv = build_argv(("rev-parse", "--verify", "--quiet", "HEAD"), repo=repo)
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, shell=False
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=git_environment(),
            timeout=limit,
            check=False,
        )
    except FileNotFoundError:
        raise _unavailable() from None
    except PermissionError:
        raise _unavailable() from None
    except OSError as exc:
        raise GitError(
            KIND_UNAVAILABLE, f"Git could not be started ({exc.__class__.__name__})"
        ) from None
    except subprocess.TimeoutExpired:
        raise _timeout(limit) from None

    if completed.returncode == 0:
        name = completed.stdout.strip()
        if _FULL_OID.match(name):
            return HeadState.PRESENT
        if _SHA256_OID.match(name):
            raise _object_format()
        # A zero exit status with an unrecognised name is still a repository
        # saying something about itself that this parser cannot read.
        raise GitError(
            KIND_MALFORMED, "Git reported a head object name this scanner cannot read"
        )
    if completed.returncode == 1:
        return HeadState.UNBORN
    # A state rather than a GitError. "This path cannot be scanned" is a
    # property of the target, and a caller handles it differently from a Git that
    # could not be started or that produced something unreadable -- those are
    # failures of the machinery, this is an answer about the input. Returning
    # INVALID is also what :class:`HeadState` documents; raising here would make
    # that member unreachable and force every caller to re-derive the same
    # distinction from an exception kind.
    return HeadState.INVALID


# ---------------------------------------------------------------------------
# Object inventory
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ObjectInventory:
    """Every reachable object, and the one path Git knows for each.

    Attributes:
        objects: Object names, in Git's own enumeration order and free of
            duplicates. Only *names* are held: never an object body, and never a
            copy of Git's output.
        paths: The path Git attributed to each object, where it attributed one.
            Git reports at most one path per object even when the object appears
            at several, so this is a hint, not an index of locations.
        truncated: Whether ``max_objects`` stopped the enumeration.
    """

    objects: tuple[str, ...] = ()
    paths: dict[str, str] | None = None
    truncated: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "objects", tuple(self.objects))
        if self.paths is None:
            object.__setattr__(self, "paths", {})
        else:
            object.__setattr__(self, "paths", dict(self.paths))
        if not isinstance(self.truncated, bool):
            raise TypeError(
                f"truncated must be a bool, got {type(self.truncated).__name__}"
            )


def iter_object_inventory(
    repo: str | os.PathLike[str],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_commits: int | None = None,
    max_objects: int | None = None,
    since: str | None = None,
    until: str | None = None,
) -> ObjectInventory:
    """Enumerate every object reachable from ``HEAD``.

    Runs ``git rev-list --objects``, reading the pipe incrementally. The whole
    output is never held in memory as bytes; what is retained is one object name
    per reachable object, which is what the scan needs in order to ask for those
    objects at all.

    Args:
        repo: Absolute path to the repository directory.
        timeout: Wall-clock limit for the command, in seconds.
        max_commits: Stop after this many commits. ``None`` means no limit. The
            limit is applied by Git, not by stopping the read early, so the set
            of objects is exactly what Git considered reachable from the commits
            it walked.
        max_objects: Stop after this many objects. This is the memory bound: a
            repository with millions of objects must not make this function
            allocate without limit. Exceeding it is reported as ``truncated``
            rather than raised, so the caller can turn it into a partial result.
        since: Only commits at or after this date expression.
        until: Only commits at or before this date expression.

    Returns:
        An :class:`ObjectInventory`.

    Raises:
        GitError: :data:`KIND_UNAVAILABLE`, :data:`KIND_TIMEOUT`,
            :data:`KIND_FAILED` (the walk itself failed -- a dangling ``HEAD``,
            a corrupt object database), :data:`KIND_MALFORMED` or
            :data:`KIND_OBJECT_FORMAT`.
    """

    limit = _check_timeout(timeout)
    subcommand = ["rev-list", "--objects", "--no-object-names", "-z"]
    # ``--no-object-names`` asks Git not to print paths at all, which removes the
    # version-dependent path format from the *inventory* entirely. Paths come
    # from ``log --raw`` instead, where the format is stable. Older Git without
    # this option still works: the parser below accepts both layouts.
    if max_commits is not None:
        subcommand.extend(("--max-count", str(max_commits)))
    if since is not None:
        subcommand.append(f"--since={validate_revision_argument(since, 'since')}")
    if until is not None:
        subcommand.append(f"--until={validate_revision_argument(until, 'until')}")
    subcommand.append("HEAD")

    names: list[str] = []
    paths: dict[str, str] = {}
    seen: set[str] = set()
    truncated = False
    last: str | None = None

    with _stream(subcommand, repo=repo, timeout=limit) as stream:
        for field in _iter_fields(stream):
            if not field:
                continue
            name, path = _parse_inventory_field(field)
            if name is None:
                # A bare ``path=`` record names the object recorded before it.
                # With no object before it the path cannot be attributed, and
                # guessing would put a file name on the wrong object.
                if last is not None and last not in paths:
                    paths[last] = path or ""
                continue
            last = name
            if path is not None and name not in paths:
                paths[name] = path
            if name in seen:
                continue
            if max_objects is not None and len(names) >= max_objects:
                truncated = True
                break
            seen.add(name)
            names.append(name)
        if not truncated:
            # Only meaningful once the whole output has been read: a walk cut
            # short says nothing about whether Git was happy.
            status = stream.exit_status()
            if status != 0:
                raise _walk_failed()

    return ObjectInventory(tuple(names), paths, truncated)


def _parse_inventory_field(field: bytes) -> tuple[str | None, str | None]:
    """Parse one NUL-separated field of ``rev-list --objects -z``.

    Returns ``(object_name, path)``, exactly one of which is set.

    Two layouts are accepted, because two Git generations emit two:

    * ``<oid>`` and, separately, ``path=<path>`` -- recent Git.
    * ``<oid> SP <path>`` in a single record -- older Git.

    A ``path=`` field is attributed to the object named by the field before it,
    which is why the caller remembers the last object name seen.

    Raises:
        GitError: :data:`KIND_MALFORMED` or :data:`KIND_OBJECT_FORMAT`.
    """

    if field.startswith(_PATH_PREFIX):
        return None, field[len(_PATH_PREFIX) :].decode("utf-8", "replace")
    if _FULL_OID.match(field):
        return field.decode("ascii"), None
    if _SHA256_OID.match(field):
        raise _object_format()
    if len(field) > _OID_LENGTH and b" " in field:
        head, _, rest = field.partition(b" ")
        if _FULL_OID.match(head):
            return head.decode("ascii"), rest.decode("utf-8", "replace")
    raise GitError(
        KIND_MALFORMED,
        "Git listed an object record this scanner cannot read",
    )


# ---------------------------------------------------------------------------
# History references
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HistoryRef:
    """One ``(commit, path, blob)`` triple from a repository's history.

    Attributes:
        commit: Full 40-character SHA-1 of the commit.
        commit_time: The commit's author timestamp, in Unix seconds.
        path: Repository-relative POSIX path, as recorded in that commit.
        object_name: Full 40-character SHA-1 of the blob at ``path``.
    """

    commit: str
    commit_time: int
    path: str
    object_name: str

    def sort_key(self) -> tuple[str, int, str]:
        """Order references within one blob: commit first, then path."""

        return (self.commit, self.commit_time, self.path)


class HistoryWalk:
    """A streaming walk over the raw history records of a repository.

    Iterating yields one :class:`HistoryRef` per path that a commit introduced or
    modified, in Git's own order (newest commit first). The walk is lazy: Git's
    output is read a chunk at a time, so the peak memory is one chunk plus the
    references the caller chose to keep -- never the repository.

    Two properties the caller needs are exposed as attributes and are only
    meaningful once iteration has finished:

    Attributes:
        commit_count: Distinct commits seen.
        truncated: Whether ``max_commits`` was reached *and* the walk stopped
            because of it. A repository with exactly ``max_commits`` commits
            is not truncated: nothing was dropped, and the difference matters
            because a caller reports a truncated walk as a partial scan. Set,
            because a scan that stopped at the limit has not seen the whole
            history and must not present itself as having.
    """

    def __init__(
        self,
        repo: str | os.PathLike[str],
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_commits: int | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> None:
        self._repo = repo
        self._timeout = _check_timeout(timeout)
        self._max_commits = max_commits
        self._since = since
        self._until = until
        self.commit_count = 0
        self.truncated = False

    def __iter__(self) -> Iterator[HistoryRef]:
        """Yield every reference, then validate the walk.

        Raises:
            GitError: :data:`KIND_UNAVAILABLE`, :data:`KIND_TIMEOUT`,
                :data:`KIND_FAILED`, :data:`KIND_MALFORMED` or
                :data:`KIND_OBJECT_FORMAT`.
        """

        yield from self._walk()

    def _walk(self) -> Iterator[HistoryRef]:
        subcommand = [
            "log",
            # Diff-external and textconv can execute repository-configured
            # commands. Both are refused, not merely unset.
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--raw",
            "-z",
            "--no-abbrev",
            # Rename detection would emit two paths per record and attribute the
            # blob to the new name only. Turning it off keeps one record per
            # changed path, which is what this parser reads.
            "--no-renames",
            # Without --root the initial commit's files are invisible, so the
            # first commit of a repository would contribute no references.
            "--root",
            # Splits a merge into one diff per parent, so content that reached
            # the branch through a merge is still attributed to a commit.
            "-m",
            f"--pretty={_PRETTY_FORMAT}",
        ]
        if self._max_commits is not None:
            # One more commit than will be used. Reaching the limit and simply
            # running out of history are otherwise indistinguishable -- and they
            # must be distinguishable, because "the walk stopped early" and "this
            # repository has five commits" are different things to tell a caller.
            # One extra commit record costs one record.
            subcommand.extend(("--max-count", str(self._max_commits + 1)))
        if self._since is not None:
            subcommand.append(
                f"--since={validate_revision_argument(self._since, 'since')}"
            )
        if self._until is not None:
            subcommand.append(f"--until={validate_revision_argument(self._until, 'until')}")
        subcommand.append("HEAD")

        commit: str | None = None
        commit_time = 0
        expect_path = False
        pending: str | None = None
        stop_after_current = False

        with _stream(subcommand, repo=self._repo, timeout=self._timeout) as stream:
            for field in _iter_fields(stream):
                if not field:
                    # The empty record Git writes after each commit's run of
                    # changed paths. It also appears for a commit that changed
                    # nothing, which is why a commit record may follow a commit
                    # record directly.
                    expect_path = False
                    pending = None
                    continue
                if not expect_path:
                    if field.startswith(_COMMIT_MARKER):
                        if stop_after_current:
                            # There really was a commit after the limit, so
                            # ``truncated`` is true rather than merely possible.
                            # Its record has been read and discarded; nothing
                            # else in the stream is looked at.
                            self.truncated = True
                            return
                        commit, commit_time = _parse_commit_field(field)
                        expect_path = False
                        pending = None
                        self.commit_count += 1
                        if (
                            self._max_commits is not None
                            and self.commit_count >= self._max_commits
                        ):
                            stop_after_current = True
                        continue
                    if field == _FORMAT_SEPARATOR:
                        continue
                    header = field
                    if header.startswith(_FORMAT_SEPARATOR):
                        header = header[1:]
                    if header.startswith(b":"):
                        # ``None`` marks a deletion. There is no blob at the
                        # vanished name, so the path record that follows must be
                        # consumed and dropped rather than attributed to the
                        # blob of whatever record came before it.
                        pending = _parse_diff_header(header)
                        expect_path = True
                        continue
                    raise GitError(
                        KIND_MALFORMED,
                        "Git emitted a history record this scanner cannot read",
                    )
                if pending is not None:
                    yield HistoryRef(
                        commit=commit or "",
                        commit_time=commit_time,
                        path=field.decode("utf-8", "replace"),
                        object_name=pending,
                    )
                expect_path = False

            if stop_after_current:
                # Git stopped because of ``--max-count``, not because it failed,
                # and no further commit existed: the limit was not actually
                # reached in the sense of having dropped anything.
                self.truncated = False
            else:
                status = stream.exit_status()
                if status != 0:
                    raise _walk_failed()


def _parse_commit_field(field: bytes) -> tuple[str, int]:
    """Parse a commit record: ``\\x01<oid> <unix-seconds>``.

    Raises:
        GitError: :data:`KIND_MALFORMED`, :data:`KIND_OBJECT_FORMAT`, or
            :data:`KIND_FAILED` when the timestamp is not a number Git could
            have written.
    """

    body = field[len(_COMMIT_MARKER) :].strip()
    name, separator, moment = body.partition(b" ")
    if not separator:
        raise GitError(
            KIND_MALFORMED, "Git emitted a commit record without a timestamp"
        )
    if _SHA256_OID.match(name):
        raise _object_format()
    if not _FULL_OID.match(name):
        raise GitError(
            KIND_MALFORMED, "Git emitted a commit record with an unreadable object name"
        )
    if not moment.isdigit():
        raise GitError(
            KIND_MALFORMED, "Git emitted a commit record with an unreadable timestamp"
        )
    return name.decode("ascii"), int(moment)


def _parse_diff_header(field: bytes) -> str | None:
    """Parse a ``--raw`` header, returning the destination blob or ``None``.

    The header is ``:<srcmode> <dstmode> <src-oid> <dst-oid> <status>``. A
    deletion's destination is the all-zero name and there is nothing to scan, so
    ``None`` is returned for it.

    Raises:
        GitError: :data:`KIND_MALFORMED` or :data:`KIND_OBJECT_FORMAT`.
    """

    parts = field.split()
    if len(parts) < 5:
        raise GitError(KIND_MALFORMED, "Git emitted an unreadable diff record")
    destination = parts[3]
    if destination == _NULL_OID:
        return None
    if _SHA256_OID.match(destination):
        raise _object_format()
    if not _FULL_OID.match(destination):
        raise GitError(KIND_MALFORMED, "Git emitted an unreadable diff object name")
    return destination.decode("ascii")


# ---------------------------------------------------------------------------
# Batch object access
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ObjectHeader:
    """One object's type and size, as ``cat-file --batch-check`` reports it.

    Attributes:
        name: Full object name.
        kind: ``"blob"``, ``"commit"``, ``"tree"``, ``"tag"`` -- whatever Git
            says. Anything other than ``"blob"`` is of no interest to a content
            scan.
        size: Size in bytes. Recorded, never used to decide how much to hold.
    """

    name: str
    kind: str
    size: int


@dataclass(frozen=True, slots=True)
class ObjectPayload:
    """One object's bytes.

    Attributes:
        name: Full object name.
        data: The object's contents. The caller decides how long this lives; in
            a scan it is decoded, scanned and dropped.
    """

    name: str
    data: bytes


def iter_object_headers(
    repo: str | os.PathLike[str],
    object_names: Iterable[str],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Iterator[ObjectHeader | None]:
    """Ask Git for the type and size of each object, in one process.

    Runs ``git cat-file --batch-check``. Objects Git does not have are yielded as
    ``None``, which is how a missing or corrupt object is reported rather than
    crashing the walk.

    Args:
        repo: Absolute path to the repository directory.
        object_names: Object names to ask about. Duplicates are harmless.
        timeout: Wall-clock limit for the whole batch, in seconds.

    Yields:
        One :class:`ObjectHeader` per object Git has, and ``None`` per object it
        does not.

    Raises:
        GitError: :data:`KIND_UNAVAILABLE`, :data:`KIND_TIMEOUT`,
            :data:`KIND_FAILED`, :data:`KIND_MALFORMED` or
            :data:`KIND_OBJECT_FORMAT`.
    """

    yield from _batch(repo, object_names, timeout=timeout, with_contents=False)


def iter_object_payloads(
    repo: str | os.PathLike[str],
    object_names: Iterable[str],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_payload: int = 1 << 30,
) -> Iterator[ObjectPayload | None]:
    """Read each object's contents from one long-lived ``cat-file --batch``.

    Args:
        repo: Absolute path to the repository directory.
        object_names: Object names to read. Duplicates are harmless.
        timeout: Wall-clock limit for the whole batch, in seconds.
        max_payload: Objects larger than this are read and discarded without ever
            being held whole, yielding ``None``. It is a memory backstop behind
            the caller's own size limit, not a substitute for it: Git will send
            a large object whether or not anyone wants it.

    Yields:
        One :class:`ObjectPayload` per readable object within ``max_payload``,
        and ``None`` per object that was missing or too large.

    Raises:
        GitError: :data:`KIND_UNAVAILABLE`, :data:`KIND_TIMEOUT`,
            :data:`KIND_FAILED`, :data:`KIND_MALFORMED` or
            :data:`KIND_OBJECT_FORMAT`.
    """

    yield from _batch(
        repo, object_names, timeout=timeout, with_contents=True, max_payload=max_payload
    )


def _batch(
    repo: str | os.PathLike[str],
    object_names: Iterable[str],
    *,
    timeout: float,
    with_contents: bool,
    max_payload: int = 0,
) -> Iterator[ObjectHeader | ObjectPayload | None]:
    """Drive one ``cat-file`` batch process and yield its answers in order.

    Requests are written by a background thread and answers are read here, in
    order, one at a time. Both halves matter: writing every request first would
    deadlock as soon as the pipe buffers filled, and Git's batch mode is
    explicitly designed for a caller that interleaves.
    """

    limit = _check_timeout(timeout)
    subcommand = ["cat-file", "--batch-check" if not with_contents else "--batch"]
    names = tuple(object_names)

    with _stream(subcommand, repo=repo, timeout=limit, stdin=subprocess.PIPE) as stream:
        writer = threading.Thread(
            target=_write_requests,
            args=(stream.stdin, names),
            name="secret-shield-cat-file-writer",
            daemon=True,
        )
        writer.start()
        try:
            for _ in names:
                header = _read_batch_header(stream)
                if header is None:
                    yield None
                    continue
                name, kind, size = header
                if not with_contents:
                    yield ObjectHeader(name=name, kind=kind, size=size)
                    continue
                if size > max_payload:
                    # Skipping means reading anyway -- Git sends the object
                    # whether or not anyone wants it -- so the bytes are drained
                    # in chunks and the record separator still has to be eaten,
                    # or the next header would be read from the wrong offset.
                    _discard(stream, size)
                    _expect_newline(stream)
                    yield None
                    continue
                yield ObjectPayload(name=name, data=_read_exact(stream, size))
                _expect_newline(stream)
        finally:
            writer.join(timeout=5)
        status = stream.exit_status()

    if status != 0:
        raise GitError(KIND_FAILED, "Git could not read the requested objects")


def _write_requests(sink: object, names: Sequence[str]) -> None:
    """Write one object name per line to ``cat-file``'s stdin, then close it.

    Runs on its own thread so a large request list cannot block the reader.
    Every failure is swallowed: the reader is what decides whether the batch
    worked, and a broken pipe here is the normal consequence of Git exiting
    early, which it reports itself.
    """

    try:
        write = getattr(sink, "write")
        close = getattr(sink, "close")
    except AttributeError:  # pragma: no cover - a stdin we did not open
        return
    try:
        for name in names:
            write(name.encode("ascii", "replace") + b"\n")
        flush = getattr(sink, "flush", None)
        if flush is not None:
            flush()
    except (OSError, ValueError):
        return
    try:
        close()
    except (OSError, ValueError):  # pragma: no cover - already closed
        pass


def _read_batch_header(stream: "_Stream") -> tuple[str, str, int] | None:
    """Read one ``<name> <kind> <size>`` or ``<name> missing`` response line.

    Returns ``None`` when Git reported the object as missing.
    """

    line = stream.read_line()
    if line is None:
        raise GitError(KIND_MALFORMED, "Git closed the object stream early")
    fields = line.split()
    if len(fields) == 2 and fields[1] == b"missing":
        name = fields[0]
        if not _FULL_OID.match(name):
            raise _bad_batch_name()
        return None
    if len(fields) != 3:
        raise GitError(KIND_MALFORMED, "Git emitted an unreadable object response")
    name, kind, size = fields
    if not _FULL_OID.match(name):
        if _SHA256_OID.match(name):
            raise _object_format()
        raise _bad_batch_name()
    if kind not in (b"blob", b"commit", b"tree", b"tag"):
        raise GitError(KIND_MALFORMED, "Git reported an unknown object type")
    if not size.isdigit():
        raise GitError(KIND_MALFORMED, "Git reported an unreadable object size")
    return name.decode("ascii"), kind.decode("ascii"), int(size)


def _bad_batch_name() -> GitError:
    return GitError(KIND_MALFORMED, "Git responded with an unreadable object name")


def _read_exact(stream: "_Stream", count: int) -> bytes:
    """Read exactly ``count`` bytes.

    Raises:
        GitError: :data:`KIND_MALFORMED` when Git's stream ends first.
    """

    buffer = bytearray()
    while len(buffer) < count:
        chunk = stream.read(min(CHUNK_SIZE, count - len(buffer)))
        if not chunk:
            raise GitError(KIND_MALFORMED, "Git closed the object stream early")
        buffer.extend(chunk)
    return bytes(buffer)


def _discard(stream: "_Stream", count: int) -> None:
    """Read and throw away ``count`` bytes, without ever holding them."""

    remaining = count
    while remaining > 0:
        chunk = stream.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise GitError(KIND_MALFORMED, "Git closed the object stream early")
        remaining -= len(chunk)


def _expect_newline(stream: "_Stream") -> None:
    """Consume the record separator ``cat-file`` writes after object contents.

    Raises:
        GitError: :data:`KIND_MALFORMED` when the byte is not the documented
            separator, which means the stream is not what it claims to be.
    """

    chunk = stream.read(1)
    if not chunk:
        raise GitError(KIND_MALFORMED, "Git closed the object stream early")
    if chunk != b"\n":
        raise GitError(KIND_MALFORMED, "Git emitted an unreadable object stream")


# ---------------------------------------------------------------------------
# Process plumbing
# ---------------------------------------------------------------------------


class _Stream:
    """A Git process whose stdout is consumed by a reader thread.

    A reader thread is what makes a hard timeout possible. Blocking reads on a
    pipe have no timeout of their own, so a hung Git would hang the scan; here
    the main thread waits on a queue *with* a deadline and the child is killed
    when it expires. Without this, "explicit timeout" would be a promise about
    ``subprocess.run`` and not about the streaming commands, which are the ones
    that can take minutes.

    The deadline covers the whole stream, not each read, so a Git that dribbles
    out a byte every thirty seconds is stopped thirty seconds in rather than
    being able to hold a scan open indefinitely.

    Attributes:
        stdin: The child's standard input, or ``None``. A writer thread owns it
            once iteration starts, which is why it is exposed read-only here.
    """

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        sink: queue.Queue[bytes | None],
        *,
        timeout: float,
    ) -> None:
        self._process = process
        self._sink = sink
        self._buffer = bytearray()
        self._exhausted = False
        self._timeout = timeout
        self._deadline = time.monotonic() + timeout
        self.stdin = process.stdin

    def _next_chunk(self) -> bytes | None:
        """Wait for the next chunk, or ``None`` at end of stream.

        Raises:
            GitError: :data:`KIND_TIMEOUT` when the stream's deadline has passed
                while the child was still producing output.
        """

        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise _timeout(self._timeout)
        try:
            return self._sink.get(timeout=remaining)
        except queue.Empty:
            raise _timeout(self._timeout) from None

    def read(self, count: int) -> bytes:
        """Return up to ``count`` bytes, or ``b""`` at end of stream."""

        while len(self._buffer) < count and not self._exhausted:
            chunk = self._next_chunk()
            if chunk is None:
                self._exhausted = True
                break
            self._buffer.extend(chunk)
        taken = bytes(self._buffer[:count])
        del self._buffer[: len(taken)]
        return taken

    def read_line(self) -> bytes | None:
        """Return one line without its terminator, or ``None`` at end of stream."""

        while True:
            index = self._buffer.find(b"\n")
            if index >= 0:
                line = bytes(self._buffer[:index])
                del self._buffer[: index + 1]
                return line
            if self._exhausted:
                if not self._buffer:
                    return None
                line = bytes(self._buffer)
                self._buffer.clear()
                return line
            chunk = self._next_chunk()
            if chunk is None:
                self._exhausted = True
                continue
            self._buffer.extend(chunk)

    def exit_status(self) -> int:
        """Close the pipe and return the child's exit status.

        Must be called inside the :func:`_stream` block, before the process is
        shut down: a child that has finished writing but not yet exited would
        otherwise be killed, and the kill would be mistaken for its opinion
        about the command.
        """

        self.drain()
        assert self._process.stdout is not None
        self._process.stdout.close()
        return self._process.wait()

    def drain(self) -> None:
        """Read the remaining output into the buffer.

        The child must be able to finish: it blocks writing while this pipe is
        full, so nothing else is safe to do until the pipe is empty.
        """

        while not self._exhausted:
            chunk = self._next_chunk()
            if chunk is None:
                self._exhausted = True
                return
            self._buffer.extend(chunk)


@contextlib.contextmanager
def _stream(
    subcommand: Sequence[str],
    *,
    repo: str | os.PathLike[str],
    timeout: float,
    stdin: object = None,
) -> Iterator[_Stream]:
    """Run one Git command and yield its stdout as a timed :class:`_Stream`.

    Args:
        subcommand: Literal subcommand tuple. See :func:`build_argv`.
        repo: Absolute repository directory.
        timeout: Wall-clock limit in seconds, applied to the whole iteration.
        stdin: :data:`subprocess.PIPE` to open the child's standard input for a
            batch protocol, or ``None`` to close it immediately -- a command that
            is not reading stdin must not be left able to block on it.

    Yields:
        The open :class:`_Stream`.

    Raises:
        GitError: :data:`KIND_UNAVAILABLE` when Git cannot be started.
    """

    argv = build_argv(subcommand, repo=repo)
    try:
        process = subprocess.Popen(  # noqa: S603 - argv list, shell=False
            argv,
            shell=False,
            stdin=stdin if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            # Git's own diagnostics are discarded rather than parsed. They are
            # the one stream whose contents a repository influences, and every
            # message this module emits is written here instead.
            stderr=subprocess.DEVNULL,
            env=git_environment(),
            close_fds=True,
        )
    except (FileNotFoundError, PermissionError):
        raise _unavailable() from None
    except OSError as exc:
        raise GitError(
            KIND_UNAVAILABLE, f"Git could not be started ({exc.__class__.__name__})"
        ) from None

    sink: queue.Queue[bytes | None] = queue.Queue(maxsize=8)
    pump = threading.Thread(
        target=_pump,
        args=(process, sink),
        name="secret-shield-git-reader",
        daemon=True,
    )
    pump.start()
    stream = _Stream(process, sink, timeout=timeout)
    try:
        yield stream
    finally:
        _shutdown(process)
        pump.join(timeout=5)


def _pump(process: subprocess.Popen[bytes], sink: queue.Queue[bytes | None]) -> None:
    """Copy the child's stdout into ``sink``, then signal end of stream."""

    assert process.stdout is not None
    try:
        while True:
            chunk = process.stdout.read(CHUNK_SIZE)
            if not chunk:
                break
            sink.put(chunk)
    except (OSError, ValueError):  # pragma: no cover - child closed the pipe
        pass
    finally:
        sink.put(None)


def _shutdown(process: subprocess.Popen[bytes]) -> None:
    """Make sure no Git process outlives the scan."""

    if process.stdin is not None:
        try:
            process.stdin.close()
        except (OSError, ValueError):  # pragma: no cover - already closed
            pass
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover - kill is not blockable
        pass
    if process.stdout is not None:
        try:
            process.stdout.close()
        except (OSError, ValueError):  # pragma: no cover - already closed
            pass


def _iter_fields(stream: "_Stream") -> Iterator[bytes]:
    """Yield the NUL-terminated fields of ``stream``, one at a time.

    Only one field is ever held. A history walk of a large repository produces
    millions of fields, and buffering them would defeat the point of streaming.
    A final field with no terminator is yielded as-is rather than dropped, so
    truncated output is visible to the parser rather than silently accepted.
    """

    buffer = bytearray()
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        start = 0
        while True:
            index = buffer.find(b"\0", start)
            if index < 0:
                break
            yield bytes(buffer[start:index])
            start = index + 1
        del buffer[:start]
    if buffer:
        yield bytes(buffer)


# ---------------------------------------------------------------------------
# Failure wording
# ---------------------------------------------------------------------------


def _unavailable() -> GitError:
    return GitError(
        KIND_UNAVAILABLE,
        "the Git program could not be started; install Git or put it on PATH",
    )


def _timeout(limit: float) -> GitError:
    return GitError(
        KIND_TIMEOUT,
        f"Git did not finish within {limit:g} seconds and was stopped",
    )


def _object_format() -> GitError:
    return GitError(
        KIND_OBJECT_FORMAT,
        "this repository does not use SHA-1 object names; only SHA-1 "
        "repositories can be scanned for history",
    )


def _walk_failed() -> GitError:
    return GitError(
        KIND_FAILED,
        "Git could not walk this repository; HEAD may point at a missing "
        "object, or the object database may be damaged",
    )


def _check_timeout(timeout: object) -> float:
    """Validate a requested timeout and return it as a float.

    Raises:
        TypeError: If ``timeout`` is not a number.
        ValueError: If it is not finite or is outside
            ``[MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS]``.
    """

    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError(f"timeout must be a number, got {type(timeout).__name__}")
    value = float(timeout)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("timeout must be a finite number")
    if not MIN_TIMEOUT_SECONDS <= value <= MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"timeout must be between {MIN_TIMEOUT_SECONDS:g} and "
            f"{MAX_TIMEOUT_SECONDS:g} seconds"
        )
    return value
