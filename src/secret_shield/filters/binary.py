"""Deciding whether a file's bytes are text.

A secret scanner has to make one judgement call before it can do any work: is
this file text? Text files are decoded and searched. Everything else is
skipped, because the alternative -- feeding megabytes of JPEG data to a regular
expression engine -- is slow, and because a match inside a compressed stream is
meaningless.

The decision is made on a bounded prefix of the file, never the whole thing, so
classifying a ten-gigabyte file costs the same as classifying a ten-byte one.

Three signals, in this order:

1. **A NUL byte.** Text files essentially never contain one, and binary formats
   essentially always do. This is the primary signal and it is exact.
2. **Undecodable UTF-8.** A file that is not valid UTF-8 is not source code
   this scanner can search. The check is on decoded *characters*, not raw
   bytes, so a file full of accented text is not mistaken for binary.
3. **A high proportion of non-printable characters.** The last resort, for text
   that is valid UTF-8 but is mostly control characters -- a corrupted dump, or
   a text format with an unusual encoding.

Why characters and not bytes
----------------------------

The obvious implementation counts bytes outside ``0x20``-``0x7e`` and gets it
badly wrong: in UTF-8 every character above ASCII is two or more bytes with the
high bit set, so a file of ordinary accented text looks binary. Decoding first
and measuring characters is what keeps normal Unicode source scannable, which
is a requirement rather than a nicety: a scanner that skips its own test suite
because it contains non-ASCII docstrings is useless.

Known limits
------------

Base64, hex and other *printable* encodings of binary data have no NUL bytes
and no control characters, so this classifier calls them text. That is a
deliberate trade: the alternative would be guessing from character statistics
and would misclassify ordinary prose. The extension filter in
:mod:`secret_shield.filters.paths` is what covers encoded blobs cheaply, and
this module is the backstop for everything it misses.

Invalid UTF-8 is treated as binary rather than decoded with replacement
characters. A source file with one bad byte in it is rare, and a secret scanner
that searches a mangled rendering of a file is reporting on something the author
never wrote. The cost is stated rather than hidden: such a file is skipped and
the skip is recorded.
"""

from __future__ import annotations

import enum
import math
from dataclasses import dataclass
from typing import Final

__all__ = [
    "ALLOWED_CONTROL_CHARACTERS",
    "ALLOWED_SEPARATORS",
    "DEFAULT_MAX_CONTROL_RATIO",
    "DEFAULT_SNIFF_BYTES",
    "BinaryConfig",
    "BinaryVerdict",
    "classify_bytes",
    "default_binary_config",
    "has_nul_byte",
]

DEFAULT_SNIFF_BYTES: Final[int] = 8192
"""How much of a file is classified, in bytes (8 KiB).

Text files essentially never contain NUL, so its presence in the first block is
a reliable signal. Sniffing a prefix rather than the whole file keeps the check
cheap on large inputs: a 10 MiB file costs the same 8 KiB of inspection as a
10 byte one.
"""

DEFAULT_MAX_CONTROL_RATIO: Final[float] = 0.30
"""Share of non-printable characters above which UTF-8 text is called binary.

A quarter of the sample is a deliberately high bar. Ordinary source code has
control characters only as line endings and tabs, so a real text file lands at
roughly zero. Setting this low would start rejecting real source code, and a
false "binary" verdict is silent data loss, which is the worst failure this
module has.
"""

ALLOWED_CONTROL_CHARACTERS: Final[frozenset[str]] = frozenset("\t\n\v\f\r")
"""Whitespace that text files legitimately contain.

Tab, newline, vertical tab, form feed and carriage return. Note that space is
*not* here: ``str.isprintable`` already accepts it, and putting it in both
places would make the two rules disagree about what a space is.
"""

ALLOWED_SEPARATORS: Final[frozenset[str]] = frozenset(
    " "
    "\u00a0"  # no-break space
    "\u1680"  # ogham space mark
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028"  # line separator
    "\u2029"  # paragraph separator
    "\u202f"  # narrow no-break space
    "\u205f"  # medium mathematical space
    "\u3000"  # ideographic space
)
"""Separators that Python calls non-printable but text files legitimately use.

``str.isprintable()`` returns ``False`` for every Unicode ``Separator``
character other than the ASCII space, which includes the ideographic space used
for indentation in CJK text. Counting those as binary would quietly skip exactly
the non-ASCII source this module exists to keep scannable, so they are allowed
explicitly.

Zero-width characters (``Cf``, such as U+200B and the zero-width joiner) are
deliberately *not* in this set. They are invisible in an editor, they are a
known trick for hiding data in a file that still looks like text, and no
hand-written source contains a meaningful number of them.
"""

#: The longest UTF-8 encoding of a single character, in bytes. A sniff window
#: can leave at most three of them dangling at its end, which is what
#: :func:`_is_unfinished_sequence` exists to recognise.
_MAX_UTF8_SEQUENCE_BYTES: Final[int] = 4


class BinaryVerdict(enum.StrEnum):
    """The outcome of classifying a byte string.

    A ``StrEnum`` so a verdict can go straight into a report or an error code
    without a lookup table. ``TEXT`` is the only value for which the caller
    should decode and search; every other value carries a fixed explanation
    that names the signal, never the bytes.
    """

    TEXT = "text"
    """Usable text. Decode it and search it."""

    NUL_BYTE = "nul-byte"
    """A NUL byte was found. The strongest binary signal there is."""

    UNDECODABLE = "undecodable"
    """The bytes are not valid UTF-8, so they are not searchable source."""

    CONTROL_HEAVY = "control-heavy"
    """Valid UTF-8, but mostly characters that do not appear in text."""

    @property
    def is_binary(self) -> bool:
        """Whether the caller should skip this file."""

        return self is not BinaryVerdict.TEXT

    @property
    def description(self) -> str:
        """A fixed explanation, safe to put in a report.

        Contains no part of the classified bytes. That is a hard rule rather
        than a convention: an error message built from file content is a way to
        leak the very thing being scanned for.
        """

        return _DESCRIPTIONS[self]


_DESCRIPTIONS: Final[dict[BinaryVerdict, str]] = {
    BinaryVerdict.TEXT: "text",
    BinaryVerdict.NUL_BYTE: "contains a NUL byte",
    BinaryVerdict.UNDECODABLE: "is not valid UTF-8 text",
    BinaryVerdict.CONTROL_HEAVY: "is mostly non-printable characters",
}


@dataclass(frozen=True, slots=True)
class BinaryConfig:
    """Thresholds for :func:`classify_bytes`.

    Attributes:
        max_sniff_bytes: How many bytes to inspect. The rest of the file is not
            read to make this decision.
        max_control_ratio: Share of non-printable characters, from ``0.0`` to
            ``1.0`` inclusive, above which text is called binary. A ratio
            exactly equal to the limit is **not** binary, so the comparison is
            strict and the boundary is testable.
    """

    max_sniff_bytes: int = DEFAULT_SNIFF_BYTES
    max_control_ratio: float = DEFAULT_MAX_CONTROL_RATIO

    def __post_init__(self) -> None:
        if isinstance(self.max_sniff_bytes, bool) or not isinstance(
            self.max_sniff_bytes, int
        ):
            raise TypeError(
                "max_sniff_bytes must be an int, got "
                f"{type(self.max_sniff_bytes).__name__}"
            )
        if self.max_sniff_bytes < 1:
            raise ValueError("max_sniff_bytes must be at least 1")

        ratio = self.max_control_ratio
        if isinstance(ratio, bool) or not isinstance(ratio, (int, float)):
            raise TypeError(
                f"max_control_ratio must be a number, got {type(ratio).__name__}"
            )
        if math.isnan(ratio) or math.isinf(ratio):
            raise ValueError("max_control_ratio must be finite")
        if not 0.0 <= ratio <= 1.0:
            raise ValueError("max_control_ratio must be between 0.0 and 1.0 inclusive")


DEFAULT_BINARY_CONFIG: Final[BinaryConfig] = BinaryConfig()
"""The shipped defaults: an 8 KiB sniff window and a 30% control-character bar."""


def default_binary_config() -> BinaryConfig:
    """Return a fresh copy of the default binary-detection configuration."""

    return BinaryConfig(
        max_sniff_bytes=DEFAULT_SNIFF_BYTES,
        max_control_ratio=DEFAULT_MAX_CONTROL_RATIO,
    )


def has_nul_byte(data: bytes) -> bool:
    """Return whether ``data`` contains a NUL byte.

    The single primitive behind the primary binary signal, shared with
    :func:`secret_shield.scanner.scan_file` so that the two paths cannot drift
    into disagreeing about what a NUL byte means.

    Args:
        data: Bytes to inspect. Pass an already-truncated prefix to keep the
            check bounded.
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"has_nul_byte() expects bytes, got {type(data).__name__}")
    return b"\x00" in bytes(data)


def classify_bytes(data: bytes, config: BinaryConfig | None = None) -> BinaryVerdict:
    """Decide whether ``data`` is text, looking at a bounded prefix only.

    Args:
        data: The bytes to classify. Usually the start of a file, but the
            function is correct for any byte string and never reads past
            ``config.max_sniff_bytes``.
        config: Thresholds to apply. Defaults to
            :data:`DEFAULT_BINARY_CONFIG`.

    Returns:
        A :class:`BinaryVerdict`. Never raises for undecodable input: invalid
        UTF-8 is a verdict, not an error, because a scanner that crashed on the
        first odd file would never finish a scan.

    Note:
        An empty input is :attr:`BinaryVerdict.TEXT`. There is nothing in it to
        be a secret, and calling it binary would make every empty file in a
        repository look like something was skipped.
    """

    settings = config if config is not None else DEFAULT_BINARY_CONFIG

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"classify_bytes() expects bytes, got {type(data).__name__}")

    raw = bytes(data)
    window = raw[: settings.max_sniff_bytes]
    truncated = len(raw) > settings.max_sniff_bytes

    if has_nul_byte(window):
        return BinaryVerdict.NUL_BYTE

    if not window:
        return BinaryVerdict.TEXT

    text = _decode_window(window, repair_truncated_tail=truncated)
    if text is None:
        return BinaryVerdict.UNDECODABLE

    if _control_ratio(text) > settings.max_control_ratio:
        return BinaryVerdict.CONTROL_HEAVY

    return BinaryVerdict.TEXT


def _decode_window(window: bytes, *, repair_truncated_tail: bool) -> str | None:
    """Decode a sniffed prefix, tolerating a split multi-byte character.

    UTF-8 encodes one character in at most four bytes, so cutting a file at an
    arbitrary byte offset can slice a character in half. That is an artefact of
    sniffing, not evidence that the file is binary, and without this repair a
    perfectly ordinary UTF-8 file is skipped whenever its character boundary
    does not land on the window boundary -- which, for a window of 8192 bytes,
    is most files containing non-ASCII text.

    The repair is applied only when the window really was cut. A decode failure
    in a file that was read in full is genuine, and is reported as such.

    The decision is structural -- *is the tail a valid but unfinished UTF-8
    sequence?* -- rather than a match on ``UnicodeDecodeError.reason``. Matching
    the message would work today and would silently break if CPython ever
    reworded it; the structural test states what it means and cannot drift.

    Note:
        This decides only whether the file is worth decoding. A file that is
        misjudged as text here is still decoded strictly in full by the caller,
        which raises on genuinely invalid bytes. So an over-eager repair costs a
        wasted decode attempt, never a binary file being searched.
    """

    try:
        return window.decode("utf-8")
    except UnicodeDecodeError as exc:
        if not repair_truncated_tail or not _is_unfinished_sequence(window, exc.start):
            return None
        # Everything before the reported offset decoded successfully, so this
        # prefix is safe to return once the partial character is dropped.
        return window[: exc.start].decode("utf-8")


def _is_unfinished_sequence(data: bytes, index: int) -> bool:
    """Return whether ``data[index:]`` is a valid but incomplete UTF-8 character.

    Three conditions, all necessary:

    * ``index`` is inside ``data``.
    * The lead byte starts a sequence that *can* exist. ``0x80``-``0xC1`` cannot:
      they are continuation bytes and the overlong two-byte leads.
    * Fewer bytes are present than the lead byte requires, **and** every byte
      that is present is a continuation byte. That last clause is what
      distinguishes ``E6 97`` (a Japanese character cut short) from ``E6 28``
      (``(``, which is simply not valid UTF-8 at all).
    """

    if index < 0 or index >= len(data):
        return False

    lead = data[index]
    if lead < 0xC2:
        return False
    if lead < 0xE0:
        expected = 2
    elif lead < 0xF0:
        expected = 3
    elif lead < 0xF5:
        expected = 4
    else:
        return False

    tail = data[index + 1 :]
    if any(not 0x80 <= byte <= 0xBF for byte in tail):
        return False

    return len(tail) < expected - 1


def _control_ratio(text: str) -> float:
    """Return the share of ``text`` that cannot appear in a text file.

    Measured in characters, not bytes, and using ``str.isprintable`` so that
    every Unicode script is judged by the Unicode database rather than by an
    ASCII range. See :data:`ALLOWED_SEPARATORS` for the characters that method
    rejects but source code legitimately contains.
    """

    if not text:
        return 0.0

    control = 0
    for character in text:
        if character in ALLOWED_CONTROL_CHARACTERS or character in ALLOWED_SEPARATORS:
            continue
        if character.isprintable():
            continue
        control += 1

    return control / len(text)
