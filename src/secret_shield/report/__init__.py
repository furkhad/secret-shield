"""Report rendering.

A reporter is a pure function from a result to a string. It performs no file
I/O, no terminal control and no network access, which is what makes reports
testable by comparing strings.

Stage 1 ships a human-readable text report only. JSON and Markdown arrive in a
later stage, and will follow the same rule: ``ScanResult`` in, ``str`` out.
"""

from __future__ import annotations

from .text import render_text

__all__ = ["render_text"]