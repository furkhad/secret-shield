"""Module entry point: ``python -m secret_shield``.

The CLI is not implemented yet. Stage 0 provides only the foundations, so this
module exists to give an honest, non-zero exit code instead of an
``AttributeError`` traceback, and to reserve the entry point that later stages
will fill in.

When ``cli.py`` lands, ``main`` here will simply delegate to it.
"""

from __future__ import annotations

import sys

from .exit_codes import EXIT_NOT_IMPLEMENTED

_NOT_IMPLEMENTED_MESSAGE = (
    "SecretShield CLI is not implemented yet. Stage 0 provides the core "
    "library only (masking, data model, exit codes).\n"
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