"""Module entry point: ``python -m secret_shield``.

The CLI is not implemented yet. Scanning works -- ``scan_file`` and
``render_text`` are the supported interface for now -- but there is no
directory traversal, no argument parsing and no output format selection, so
this module exists to give an honest, non-zero exit code instead of an
``AttributeError`` traceback, and to reserve the entry point that later stages
will fill in.

That is deliberate. A ``python -m secret_shield <path>`` that silently scanned
nothing would be worse than one that refuses to start.

When ``cli.py`` lands, ``main`` here will simply delegate to it.
"""

from __future__ import annotations

import sys

from .exit_codes import EXIT_NOT_IMPLEMENTED

_NOT_IMPLEMENTED_MESSAGE = (
    "SecretShield CLI is not implemented yet. The library can scan a single "
    "file:\n"
    "  python -c \"import secret_shield as s; "
    "print(s.render_text(s.scan_file('path/to/file')))\"\n"
    "See README.md for the current status."
)


def main(argv: list[str] | None = None) -> int:
    """Report that the CLI is unavailable.

    Args:
        argv: Accepted for signature compatibility with the future CLI and
            deliberately unused.

    Returns:
        :data:`~secret_shield.exit_codes.EXIT_NOT_IMPLEMENTED`.
    """

    del argv  # Unused until the real CLI exists; keeps the signature stable.
    print(_NOT_IMPLEMENTED_MESSAGE, file=sys.stderr)
    return EXIT_NOT_IMPLEMENTED


if __name__ == "__main__":
    raise SystemExit(main())