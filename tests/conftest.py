"""Shared pytest configuration for the SecretShield test suite.

Two jobs:

1. Make the suite runnable straight from a checkout. The package uses a
   ``src/`` layout, so if it has not been installed the tests would not be
   able to import it. When it *is* installed (the normal case, via
   ``pip install -e ".[dev]"``) the installed package wins, which keeps the
   tests honest about what users actually run.

2. Provide synthetic fixtures. Every value defined here is fabricated. None of
   it is a real credential, and none of it is copied from a production system.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SRC_DIR = Path(__file__).resolve().parent.parent / "src"

if (
    importlib.util.find_spec("secret_shield") is None
):  # pragma: no cover - env dependent
    sys.path.insert(0, str(_SRC_DIR))

# Make ``vendor_fixtures`` importable from anywhere in the suite. pytest puts a
# test file's own directory on ``sys.path``, which for ``tests/unit/test_x.py``
# is ``tests/unit`` and not ``tests``; without this the shared synthetic
# credentials would have to be duplicated per test module.
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))


#: Obviously fake material used across the suite. Built from repeated blocks so
#: that it can never be mistaken for a live credential.
SYNTHETIC_SECRET = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"

#: The placeholder key published in AWS's own documentation. It is a documented
#: example, not a credential, and it is what our tests assert against for AWS.
EXAMPLE_AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

#: A documentation-style token: a real vendor prefix followed only by zeros.
EXAMPLE_GITHUB_TOKEN = "ghp_" + ("0" * 36)


@pytest.fixture
def synthetic_secret() -> str:
    """A clearly fabricated 40-character secret."""

    return SYNTHETIC_SECRET


@pytest.fixture
def example_aws_key() -> str:
    """The documented AWS example key ID."""

    return EXAMPLE_AWS_ACCESS_KEY_ID


@pytest.fixture
def example_github_token() -> str:
    """A documentation-style GitHub token."""

    return EXAMPLE_GITHUB_TOKEN
