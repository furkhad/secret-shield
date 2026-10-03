"""Module entry point: ``python -m secret_shield``.

This module exists so that the package is runnable without installation, and it
holds no logic of its own. It delegates to :func:`secret_shield.cli.main` and
turns the returned exit code into the process's exit status.

The two invocations are deliberately equivalent rather than merely similar::

    python -m secret_shield --help
    secret-shield --help

produce byte-identical output, because the program name argparse reports is
fixed to ``TOOL_NAME`` instead of being read from ``sys.argv[0]`` -- which under
``-m`` would otherwise be ``__main__.py``.

Note:
    Earlier stages shipped an ``EXIT_NOT_IMPLEMENTED`` stub here. The exit code
    it used still exists in :mod:`secret_shield.exit_codes` for capabilities that
    genuinely are absent, but nothing in this release returns it: there is no
    flag for an unimplemented feature, so the honest answer to "scan Git
    history" is a usage error, not a stub.
"""

from __future__ import annotations

from collections.abc import Sequence

from .cli import main as _cli_main

__all__ = ["main"]


def main(argv: Sequence[str] | None = None) -> int:
    """Run the SecretShield CLI and return its exit code.

    Args:
        argv: Arguments without the program name. ``None`` means ``sys.argv[1:]``.

    Returns:
        One of the values in :mod:`secret_shield.exit_codes`. Never raises, so a
        bad command line, a failed scan or an interrupt is reported as a number
        rather than a traceback.
    """

    return _cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())