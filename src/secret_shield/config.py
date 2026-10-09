"""Layered configuration: one schema, six sources, no surprises.

SecretShield is configured the way most serious tools are: built-in defaults
first, then whatever the project says, then whatever the environment says, then
whatever the caller says. Nothing else. There is exactly one schema and every
source speaks it.

The layers, lowest precedence first::

    defaults                            default_path_scan_config()
    < pyproject.toml [tool.secretshield]
    < .secretshield.toml
    < .secretshield.json
    < SECRETSHIELD_* environment variables
    < explicit overrides                load_config(overrides={...})

A later layer always wins. There is no layer that partially wins.

Why only these four files
-------------------------

Three of them are enough. ``pyproject.toml`` is where a Python project's
settings already live, so a repository that has one should not need a second
file to explain itself. ``.secretshield.toml`` is the human-facing file. JSON
exists because some CI systems can only emit JSON. No other format is accepted,
because every additional format is a second schema to keep in sync and a second
parser to keep secure.

Why no list extension
---------------------

**Every list replaces. Nothing ever extends.** If a layer sets
``paths.ignored_directories``, the shipped defaults are gone rather than merged
with.

That is the one place where a scanner could quietly lose coverage, so the rule
was chosen for auditability over convenience:

* **Replacement is associative.** "The highest layer that mentions a key wins"
  composes. A mixed policy -- this list extends, that one replaces -- does not:
  ``(A extend B) extend C`` and ``A extend (B extend C)`` disagree about order
  and duplicates, and which one a caller gets would depend on how the layers
  happen to be grouped. With replacement there is exactly one answer, and
  :meth:`Config.source_of` reports it.
* **Replacement is visible.** After replacement, the effective ignore list can
  be read off the configuration. With extension, the effective list can only be
  obtained by running the code, so "what does this configuration actually skip?"
  stops being a question a config review can answer.
* **A committed file is the whole truth.** A repository saying
  ``ignored_directories = ["fixtures"]`` states its policy completely.
  Restating the defaults in order to keep them is verbose; discovering that
  ``node_modules`` is no longer skipped because a later file replaced the list
  is not.

The cost is real and worth naming: adding one entry to the shipped defaults
means restating the rest. The README prints them verbatim for that case.

Why a deny list for rules
-------------------------

Only ``rules.disabled`` exists; there is no allow list. An allow list in a file
committed eighteen months ago must go on silently disabling rules added to the
catalog since, which is the worst available failure mode for a tool whose job is
to notice new credential formats. A deny list has the opposite property: a
catalog release shows up as new findings, which a human triages, rather than as
silence.

Configuration is untrusted input
--------------------------------

A ``.secretshield.toml`` in a cloned repository is content the person running
the scan may not have written, reviewed, or even looked at. It is therefore
parsed as data and never as code:

* TOML is read with :mod:`tomllib` and JSON with :func:`json.loads`. Neither
  can call anything. There is no ``eval``, no ``exec``, no ``pickle``, no
  dynamic ``import``, and no ``subprocess`` anywhere in this module.
* No setting value is ever compiled into a pattern. There is deliberately no
  setting that accepts a regular expression; custom user-supplied rules are
  deferred, and the schema has no placeholder for them.
* Every value is type-checked and range-checked before it can reach a scanner
  setting. Unknown keys are hard errors, never ignored, because a silently
  dropped key is a setting the author believed they had tightened.
* Files are size-capped before parsing, so a hostile checkout cannot turn a scan
  into an out-of-memory run by shipping a huge ``.secretshield.json``.
* Duplicate keys are rejected. ``tomllib`` rejects them for TOML; JSON needs
  ``json.loads``'s ``object_pairs_hook`` to do the same, and it is wired up
  because "last one wins" makes a file's meaning depend on how a reader happened
  to be written.
* Error messages are built from the schema plus the offending key, never echoed
  from a file body, and every value that does reach a message has its control
  characters stripped so a crafted filename cannot repaint a terminal.

Importing this module reads nothing, touches nothing and prints nothing. All
filesystem and environment access happens inside :func:`load_config`, which
takes both as injectable parameters, so a test can describe a hostile
configuration without creating one.
"""

from __future__ import annotations

import dataclasses
import difflib
import enum
import json
import math
import os
import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypeVar

from .detectors import EntropyRuleConfig
from .detectors.base import DetectorRegistry
from .detectors.catalog import default_registry
from .detectors.entropy_rule import default_entropy_config
from .filters.binary import BinaryConfig
from .filters.paths import PathFilterConfig
from .masking import strip_control_characters
from .models import Severity
from .scanner import ScanConfig
from .sources.filesystem import PathScanConfig, default_path_scan_config

__all__ = [
    "CONFIG_FILENAMES",
    "ENV_PREFIX",
    "MAX_CONFIG_BYTES",
    "PYPROJECT_SECTION",
    "SETTINGS",
    "Config",
    "ConfigError",
    "ConfigLayer",
    "ConfigOrigin",
    "Setting",
    "SettingKind",
    "load_config",
    "setting_for",
    "setting_for_env",
]


ENV_PREFIX: Final[str] = "SECRETSHIELD_"
"""Prefix that marks an environment variable as ours, and only ours."""

CONFIG_FILENAMES: Final[tuple[str, ...]] = (".secretshield.toml", ".secretshield.json")
"""Project-root config filenames, in increasing order of precedence."""

PYPROJECT_SECTION: Final[tuple[str, ...]] = ("tool", "secretshield")
"""Where in ``pyproject.toml`` the settings live."""

MAX_CONFIG_BYTES: Final[int] = 1_048_576
"""Largest configuration file read, in bytes (1 MiB).

The shipped schema configures about twenty settings. A megabyte is three orders
of magnitude more than that needs and far less than a scanner should allocate
because a repository told it to. The cap exists so that scanning a hostile
checkout cannot be turned into an out-of-memory run by adding a large file named
``.secretshield.json``.
"""


class ConfigLayer(enum.StrEnum):
    """Where a setting came from, ordered by increasing precedence.

    ``DEFAULTS`` is deliberately absent. It is not a layer that can be read or
    written; it is the value of every unset setting, and it already has one
    home -- the ``default_*`` factories in the modules that own those settings.
    Listing it here would invite a second copy of every number.
    """

    PYPROJECT = "pyproject.toml"
    TOML = ".secretshield.toml"
    JSON = ".secretshield.json"
    ENVIRONMENT = "environment"
    OVERRIDES = "overrides"

    @property
    def precedence(self) -> int:
        """Rank in the merge; higher wins. Stable for sorting and reporting."""

        return _LAYER_PRECEDENCE[self]


_LAYER_PRECEDENCE: Final[dict[ConfigLayer, int]] = {
    ConfigLayer.PYPROJECT: 10,
    ConfigLayer.TOML: 20,
    ConfigLayer.JSON: 30,
    ConfigLayer.ENVIRONMENT: 40,
    ConfigLayer.OVERRIDES: 50,
}


class ConfigError(Exception):
    """A configuration could not be read, understood or applied.

    Configuration problems are raised, never repaired. A scanner that guessed
    what an unrecognised key meant, or carried on with a value of the wrong
    type, would report a scan nobody asked for using settings nobody chose.

    Attributes:
        layer: Which layer produced the problem, when known.
        key: The dotted setting name, when attributable to one.
        location: The file, or the environment variable, being read.
    """

    def __init__(
        self,
        message: str,
        *,
        layer: ConfigLayer | None = None,
        key: str | None = None,
        location: str | None = None,
    ) -> None:
        # Everything reaching a message is either written here from the schema
        # or is a value a user typed. A typed value may carry ANSI escapes or
        # bidirectional overrides, so it is stripped like any other untrusted
        # display input.
        super().__init__(strip_control_characters(message))
        self.layer = layer
        self.key = key
        self.location = (
            strip_control_characters(location) if location is not None else None
        )

    def __repr__(self) -> str:
        return f"ConfigError({str(self)!r}, layer={self.layer!r}, key={self.key!r})"


@dataclass(frozen=True, slots=True)
class ConfigOrigin:
    """One layer, and the settings it actually contributed.

    Attributes:
        layer: Which layer this is.
        location: The file, or the environment variable, it was read from.
        keys: Dotted setting names it set, sorted. Empty for a layer that was
            consulted but set nothing.
    """

    layer: ConfigLayer
    location: str
    keys: tuple[str, ...] = ()


class SettingKind(enum.StrEnum):
    """How one setting's value is parsed and validated.

    The kind decides which parser runs, and therefore which mistakes are
    possible. An integer setting cannot receive ``"abc"``; a boolean setting
    cannot receive ``"maybe"``. The environment parser is a separate code path
    from the file parser precisely because only one of them starts from a string,
    and both must accept exactly the same set of written values.
    """

    INTEGER = "integer"
    OPTIONAL_INTEGER = "optional integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    STRING_LIST = "string list"
    SEVERITY = "severity"


# Grammar for the numeric forms accepted from the environment. Hand-rolled
# rather than delegated to int()/float() so that "1_0", "0x10", "inf" and "nan"
# are rejected instead of being silently reinterpreted by Python.
_INTEGER_PATTERN: Final[re.Pattern[str]] = re.compile(r"[+-]?[0-9]+")
_NUMBER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?"
)

_TRUE_WORDS: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
_FALSE_WORDS: Final[frozenset[str]] = frozenset({"0", "false", "no", "off"})
"""The complete set of accepted boolean spellings, compared case-insensitively.

``1``/``0`` exist because shell scripts and CI matrices emit them, and
``yes``/``no``/``on``/``off`` because humans write them. Nothing else is
accepted, so ``t``, ``y``, ``enabled`` and ``"TRUE-ish"`` are errors rather than
surprises.
"""

_NULL_WORDS: Final[frozenset[str]] = frozenset({"none", "null", "unlimited", "unset"})
"""Spellings that mean "no limit" for an optional-integer setting.

An *empty* environment variable is deliberately not one of them. ``MAX_DEPTH=``
is far more likely to be an unset variable that slipped into a CI template than
a deliberate request to scan the whole tree without limit, and treating it as
"unlimited" would silently widen coverage. Removing the limit is spelled.
"""


@dataclass(frozen=True, slots=True)
class Setting:
    """One configurable setting, and everything needed to validate it.

    The schema is data so that validation, documentation, the environment
    mapping and the "did you mean" suggestions all derive from a single list.
    Adding a setting in two places is how a tool ends up accepting a value from
    the environment that it rejects in a file.

    Attributes:
        section: Grouping used in file syntax, e.g. ``"entropy"``.
        name: Leaf name, unique across the whole schema. That uniqueness is what
            lets the environment variable be ``SECRETSHIELD_<NAME>`` without
            carrying its section, and it is enforced when the indexes are built.
        kind: Which parser validates this setting's values.
        help: One line, used in documentation and in error messages.
        minimum: Inclusive lower bound for numeric kinds.
        maximum: Inclusive upper bound for numeric kinds.
    """

    section: str
    name: str
    kind: SettingKind
    help: str
    minimum: float | None = None
    maximum: float | None = None

    def __post_init__(self) -> None:
        # Deliberately self-contained. SETTINGS below instantiates every Setting
        # at import time, so a __post_init__ calling a helper defined further
        # down the file would raise NameError on import. That has bitten this
        # codebase before.
        if not isinstance(self.section, str) or not self.section.isidentifier():
            raise ValueError(
                f"setting section must be an identifier, got {self.section!r}"
            )
        if not isinstance(self.name, str) or not self.name.isidentifier():
            raise ValueError(f"setting name must be an identifier, got {self.name!r}")
        if not isinstance(self.kind, SettingKind):
            raise TypeError(
                f"setting kind must be a SettingKind, got {type(self.kind).__name__}"
            )
        if not isinstance(self.help, str) or not self.help.strip():
            raise ValueError(f"setting {self.name} needs a help string")
        if self.minimum is not None and self.maximum is not None:
            if self.minimum > self.maximum:
                raise ValueError(f"setting {self.name} has minimum above maximum")

    @property
    def key(self) -> str:
        """The dotted name this setting is written as, e.g. ``entropy.min_length``."""

        return f"{self.section}.{self.name}"

    @property
    def env_var(self) -> str:
        """The environment variable that sets this, e.g. ``SECRETSHIELD_MIN_LENGTH``."""

        return ENV_PREFIX + self.name.upper()

    def describe(self) -> str:
        """Return a one-line description with its accepted type and bounds."""

        if self.minimum is None and self.maximum is None:
            bounds = ""
        else:
            low = "-inf" if self.minimum is None else _format_number(self.minimum)
            high = "+inf" if self.maximum is None else _format_number(self.maximum)
            bounds = f" {low}..{high}"
        return f"{self.key} ({self.kind}{bounds}): {self.help}"


SETTINGS: Final[tuple[Setting, ...]] = (
    # -- scan --------------------------------------------------------------
    Setting(
        "scan",
        "max_file_size",
        SettingKind.INTEGER,
        "Largest file read, in bytes.",
        minimum=1,
    ),
    Setting(
        "scan",
        "max_files",
        SettingKind.INTEGER,
        "Largest number of files one scan will read before it stops.",
        minimum=1,
    ),
    Setting(
        "scan",
        "max_line_length",
        SettingKind.INTEGER,
        "Longest line handed to the candidate extractor, in characters.",
        minimum=1,
    ),
    # -- paths -------------------------------------------------------------
    Setting(
        "paths",
        "max_depth",
        SettingKind.OPTIONAL_INTEGER,
        "Deepest file to scan, counted from the root. Unset means no limit.",
        minimum=0,
    ),
    Setting(
        "paths",
        "follow_symlinks",
        SettingKind.BOOLEAN,
        "Whether a symlink inside the root may be followed. Even when true, a "
        "symlink whose target resolves outside the root is still skipped.",
    ),
    Setting(
        "paths",
        "ignored_directories",
        SettingKind.STRING_LIST,
        "Directory names skipped anywhere in the tree. Replaces the defaults.",
    ),
    Setting(
        "paths",
        "ignored_filenames",
        SettingKind.STRING_LIST,
        "Exact file names skipped anywhere in the tree. Replaces the defaults.",
    ),
    Setting(
        "paths",
        "ignored_extensions",
        SettingKind.STRING_LIST,
        "Extensions skipped, with or without the leading dot. Replaces the defaults.",
    ),
    Setting(
        "paths",
        "ignored_paths",
        SettingKind.STRING_LIST,
        "Relative POSIX paths skipped together with everything under them. "
        "Replaces the default, which is empty.",
    ),
    # -- binary ------------------------------------------------------------
    Setting(
        "binary",
        "max_sniff_bytes",
        SettingKind.INTEGER,
        "How many leading bytes are inspected to classify a file as text.",
        minimum=1,
    ),
    Setting(
        "binary",
        "max_control_ratio",
        SettingKind.NUMBER,
        "Control-character ratio above which a file is treated as binary.",
        minimum=0.0,
        maximum=1.0,
    ),
    # -- entropy -----------------------------------------------------------
    Setting(
        "entropy",
        "min_length",
        SettingKind.INTEGER,
        "Shortest high-entropy candidate considered, in characters.",
        minimum=1,
    ),
    Setting(
        "entropy",
        "min_raw_entropy",
        SettingKind.NUMBER,
        "Minimum Shannon entropy of a candidate, in bits per character.",
        minimum=0.0,
    ),
    Setting(
        "entropy",
        "max_raw_entropy",
        SettingKind.NUMBER,
        "Candidates above this are ignored as non-credential text.",
        minimum=0.0,
    ),
    Setting(
        "entropy",
        "min_normalized_entropy",
        SettingKind.NUMBER,
        "Minimum evenness ratio of a candidate, from 0.0 to 1.0.",
        minimum=0.0,
        maximum=1.0,
    ),
    Setting(
        "entropy",
        "max_prose_words",
        SettingKind.INTEGER,
        "Candidates with at least this many multi-character words are ignored.",
        minimum=0,
    ),
    Setting(
        "entropy",
        "max_severity",
        SettingKind.SEVERITY,
        "Severity ceiling for entropy-only findings. Cannot exceed MEDIUM, "
        "because entropy carries no information about impact.",
    ),
    # -- rules -------------------------------------------------------------
    Setting(
        "rules",
        "disabled",
        SettingKind.STRING_LIST,
        "Ids of vendor rules to switch off. There is no allow list; see the "
        "module docstring for why.",
    ),
    # -- scan behavior ------------------------------------------------------
    Setting(
        "scan",
        "jobs",
        SettingKind.INTEGER,
        "Number of worker threads to use for scanning files. 1 means serial.",
        minimum=1,
    ),
)
"""The whole configuration schema, in one place."""

_ALL_KEYS: Final[tuple[str, ...]] = tuple(setting.key for setting in SETTINGS)


def _build_indexes(
    settings: Iterable[Setting],
) -> tuple[dict[str, Setting], dict[str, Setting]]:
    """Return the by-key and by-environment-variable indexes for ``settings``.

    A repeated leaf name is a programming error in this module rather than a
    user error, so it is raised immediately instead of being papered over: two
    settings sharing a leaf name would make ``SECRETSHIELD_MAX_FILES``
    ambiguous, and silently keeping only one of them would hide the collision
    until the day somebody relied on the wrong default.
    """

    items = tuple(settings)
    by_key: dict[str, Setting] = {}
    by_env: dict[str, Setting] = {}
    for setting in items:
        if setting.key in by_key:
            raise RuntimeError(f"duplicate setting key {setting.key!r}")
        owner = by_env.get(setting.env_var)
        if owner is not None:
            raise RuntimeError(
                f"settings {owner.key!r} and {setting.key!r} share the environment "
                f"variable {setting.env_var}; leaf names must be unique"
            )
        by_key[setting.key] = setting
        by_env[setting.env_var] = setting
    return by_key, by_env


_SETTINGS_BY_KEY, _SETTINGS_BY_ENV = _build_indexes(SETTINGS)


def setting_for(key: str) -> Setting | None:
    """Return the setting named by the dotted ``key``, or ``None`` if unknown."""

    return _SETTINGS_BY_KEY.get(key) if isinstance(key, str) else None


def setting_for_env(variable: str) -> Setting | None:
    """Return the setting driven by the environment ``variable``, if any."""

    return _SETTINGS_BY_ENV.get(variable) if isinstance(variable, str) else None


# ---------------------------------------------------------------------------
# Reading raw values out of a mapping-shaped layer
# ---------------------------------------------------------------------------


def _unknown_key_error(key: str, *, layer: ConfigLayer, location: str) -> ConfigError:
    """Build the error for an unrecognised setting, with a suggestion if close."""

    close = difflib.get_close_matches(key, _ALL_KEYS, n=2, cutoff=0.72)
    if close:
        hint = f"; did you mean {close[0]!r}?"
    else:
        hint = f"; known settings are {', '.join(_ALL_KEYS)}"
    return ConfigError(
        f"{location}: unknown setting {key!r}{hint}",
        layer=layer,
        key=key,
        location=location,
    )


def _flatten(
    mapping: Mapping[str, object],
    *,
    layer: ConfigLayer,
    location: str,
) -> dict[str, object]:
    """Return ``mapping`` as ``{"section.name": raw_value}``.

    Accepts both spellings real files use: a nested table (``[entropy]`` /
    ``{"entropy": {...}}``) and a flat dotted key (``"entropy.min_length"`` /
    ``{"entropy.min_length": ...}``). They describe the same schema, so both
    produce the same flat mapping.

    Raises:
        ConfigError: If ``mapping`` is not a mapping, if a key is not a string,
            if the same setting is given twice in two different spellings, or
            if a setting is unknown. Unknown keys are never ignored.
    """

    flat: dict[str, object] = {}
    spelling_of: dict[str, str] = {}

    def record(key: str, value: object, spelling: str) -> None:
        if key not in _SETTINGS_BY_KEY:
            raise _unknown_key_error(key, layer=layer, location=location)
        if key in flat:
            raise ConfigError(
                f"{location}: {key!r} is set twice, as {spelling_of[key]} and as "
                f"{spelling}; one setting must have exactly one value",
                layer=layer,
                key=key,
                location=location,
            )
        flat[key] = value
        spelling_of[key] = spelling

    for raw_key, value in mapping.items():
        if not isinstance(raw_key, str):
            raise ConfigError(
                f"{location}: setting names must be strings, got {type(raw_key).__name__}",
                layer=layer,
                location=location,
            )
        if isinstance(value, Mapping):
            for sub_key, sub_value in value.items():
                if not isinstance(sub_key, str):
                    raise ConfigError(
                        f"{location}: setting names under {raw_key!r} must be strings, "
                        f"got {type(sub_key).__name__}",
                        layer=layer,
                        location=location,
                    )
                record(f"{raw_key}.{sub_key}", sub_value, f"{raw_key}.{sub_key}")
        else:
            record(raw_key, value, repr(raw_key))

    return flat


# ---------------------------------------------------------------------------
# Coercion to validated, typed values
# ---------------------------------------------------------------------------


def _type_name(value: object) -> str:
    """Return a user-facing description of ``value``'s type."""

    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, int):
        return "an integer"
    if isinstance(value, float):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, (bytes, bytearray)):
        return "raw bytes"
    if isinstance(value, Mapping):
        return "a table"
    if isinstance(value, (list, tuple)):
        return "a list"
    return f"a {type(value).__name__}"


def _format_number(value: float) -> str:
    """Render ``value`` for a message, without a pointless ``.0`` on integers."""

    if isinstance(value, float) and value.is_integer() and abs(value) < 1e16:
        return str(int(value))
    return str(value)


def _check_range(
    setting: Setting,
    number: float,
    *,
    layer: ConfigLayer,
    location: str,
) -> None:
    """Raise :class:`ConfigError` if ``number`` is outside the setting's bounds."""

    if setting.minimum is not None and number < setting.minimum:
        raise ConfigError(
            f"{location}: {setting.key} must be at least {_format_number(setting.minimum)}, "
            f"got {_format_number(number)}",
            layer=layer,
            key=setting.key,
            location=location,
        )
    if setting.maximum is not None and number > setting.maximum:
        raise ConfigError(
            f"{location}: {setting.key} must be at most {_format_number(setting.maximum)}, "
            f"got {_format_number(number)}",
            layer=layer,
            key=setting.key,
            location=location,
        )


def _parse_severity(
    text: str, *, setting: Setting, layer: ConfigLayer, location: str
) -> Severity:
    """Parse a severity label, reporting any failure as a :class:`ConfigError`."""

    try:
        return Severity.from_label(text)
    except (TypeError, ValueError):
        labels = ", ".join(member.label for member in Severity)
        raise ConfigError(
            f"{location}: {setting.key} must be one of [{labels}]; got {text!r}",
            layer=layer,
            key=setting.key,
            location=location,
        ) from None


def _coerce_mapping_value(
    setting: Setting,
    raw: object,
    *,
    layer: ConfigLayer,
    location: str,
) -> object:
    """Validate a value that arrived as a Python object.

    File layers and ``overrides`` both produce objects rather than text, so
    validation is a type check rather than a parse.

    A string is never accepted where a list is expected, even when it looks like
    a comma-separated list: a bare string is the shape a mistyped ``["build"]``
    takes, and accepting both spellings would make ``paths.ignored_paths =
    "build"`` mean something different depending on which layer delivered it.
    """

    def fail(want: str, got: object) -> ConfigError:
        return ConfigError(
            f"{location}: {setting.key} must be {want}, got {_type_name(got)}",
            layer=layer,
            key=setting.key,
            location=location,
        )

    kind = setting.kind

    if kind is SettingKind.SEVERITY:
        if isinstance(raw, Severity):
            return raw
        if not isinstance(raw, str):
            raise fail("a severity label", raw)
        return _parse_severity(raw, setting=setting, layer=layer, location=location)

    if kind is SettingKind.BOOLEAN:
        # isinstance rather than a truthiness test: 0, "" and [] are not
        # booleans, and accepting them would let max_files=0 mean "off".
        if not isinstance(raw, bool):
            raise fail("a boolean", raw)
        return raw

    if kind in (SettingKind.INTEGER, SettingKind.OPTIONAL_INTEGER):
        if kind is SettingKind.OPTIONAL_INTEGER and raw is None:
            return None
        # bool before int: bool is a subclass of int, and True is not a size.
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise fail(
                "an integer" if kind is SettingKind.INTEGER else "an integer or null",
                raw,
            )
        _check_range(setting, float(raw), layer=layer, location=location)
        # Extra validation for jobs
        if setting.key == "scan.jobs" and raw > 64:
            raise ConfigError(
                f"{location}: jobs must be at most 64",
                layer=layer,
                key=setting.key,
                location=location,
            )
        return raw

    if kind is SettingKind.NUMBER:
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise fail("a number", raw)
        number = float(raw)
        if not math.isfinite(number):
            raise ConfigError(
                f"{location}: {setting.key} must be a finite number",
                layer=layer,
                key=setting.key,
                location=location,
            )
        _check_range(setting, number, layer=layer, location=location)
        return number

    # STRING_LIST
    if isinstance(raw, (str, bytes, bytearray, Mapping)) or not isinstance(
        raw, Sequence
    ):
        raise fail("a list of strings", raw)
    items: list[str] = []
    for entry in raw:
        if not isinstance(entry, str):
            raise ConfigError(
                f"{location}: {setting.key} must contain only strings, "
                f"got {_type_name(entry)}",
                layer=layer,
                key=setting.key,
                location=location,
            )
        items.append(entry)
    return tuple(items)


def _coerce_env_value(
    setting: Setting,
    raw: str,
    *,
    layer: ConfigLayer,
    location: str,
) -> object:
    """Parse and validate one environment variable's value.

    Every failure is an error. Nothing is skipped, nothing is defaulted: an
    unrecognised ``SECRETSHIELD_*`` variable is as much a mistake as a
    malformed one, and silently ignoring it is how a CI job ends up scanning with
    settings its author did not choose.
    """

    text = raw.strip()
    kind = setting.kind

    if kind is SettingKind.BOOLEAN:
        lowered = text.lower()
        if lowered in _TRUE_WORDS:
            return True
        if lowered in _FALSE_WORDS:
            return False
        accepted = ", ".join(sorted(_TRUE_WORDS | _FALSE_WORDS))
        raise ConfigError(
            f"{location}: {setting.key} must be a boolean; accepted values are "
            f"[{accepted}]; got {raw!r}",
            layer=layer,
            key=setting.key,
            location=location,
        )

    if kind in (SettingKind.INTEGER, SettingKind.OPTIONAL_INTEGER):
        if kind is SettingKind.OPTIONAL_INTEGER and text.lower() in _NULL_WORDS:
            return None
        if not _INTEGER_PATTERN.fullmatch(text):
            raise ConfigError(
                f"{location}: {setting.key} must be a base-10 integer "
                f"such as '4096'; got {raw!r}",
                layer=layer,
                key=setting.key,
                location=location,
            )
        number = int(text)
        _check_range(setting, float(number), layer=layer, location=location)
        # Extra validation for jobs to match PathScanConfig
        if setting.key == "scan.jobs" and number > 64:
            raise ConfigError(
                f"{location}: jobs must be at most 64",
                layer=layer,
                key=setting.key,
                location=location,
            )
        return number

    if kind is SettingKind.NUMBER:
        if not _NUMBER_PATTERN.fullmatch(text):
            raise ConfigError(
                f"{location}: {setting.key} must be a finite decimal number "
                f"such as '4.0'; got {raw!r}",
                layer=layer,
                key=setting.key,
                location=location,
            )
        float_val = float(text)
        if not math.isfinite(
            float_val
        ):  # pragma: no cover - unreachable via the pattern
            raise ConfigError(
                f"{location}: {setting.key} must be a finite number",
                layer=layer,
                key=setting.key,
                location=location,
            )
        _check_range(setting, float_val, layer=layer, location=location)
        return float_val

    if kind is SettingKind.SEVERITY:
        return _parse_severity(text, setting=setting, layer=layer, location=location)

    # STRING_LIST: comma separated, whitespace trimmed per entry.
    if not text:
        return ()
    items: list[str] = []
    for piece in text.split(","):
        entry = piece.strip()
        if not entry:
            raise ConfigError(
                f"{location}: {setting.key} must be a comma-separated list of names; "
                f"got an empty entry in {raw!r}",
                layer=layer,
                key=setting.key,
                location=location,
            )
        items.append(entry)
    return tuple(items)


# ---------------------------------------------------------------------------
# File layers
# ---------------------------------------------------------------------------


class _DuplicateKey(ValueError):
    """Internal signal: a JSON object repeated a key."""


def _reject_duplicate_keys(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    """``object_pairs_hook`` that refuses to silently keep the last of two keys."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _read_text(path: Path, *, layer: ConfigLayer) -> str | None:
    """Return the file's UTF-8 text, or ``None`` if it does not exist.

    A missing optional configuration file is the normal case and is not an
    error. Every other filesystem failure is: a directory named
    ``.secretshield.toml`` or a file nobody can read is a mistake in the project,
    and silently scanning with the wrong settings because of it is worse than
    stopping.
    """

    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return None
    except IsADirectoryError:
        raise ConfigError(
            f"{path}: is a directory, not a configuration file",
            layer=layer,
            location=str(path),
        ) from None
    except OSError as exc:
        raise ConfigError(
            f"{path}: cannot be read ({type(exc).__name__}); refusing to guess "
            "the project's settings",
            layer=layer,
            location=str(path),
        ) from None

    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(
            f"{path}: larger than the {MAX_CONFIG_BYTES}-byte configuration limit; "
            "this is not a settings file",
            layer=layer,
            location=str(path),
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(
            f"{path}: is not valid UTF-8; configuration files must be UTF-8 text",
            layer=layer,
            location=str(path),
        ) from None
    # A leading BOM is a Windows habit, not an intent. It is stripped rather
    # than rejected because it changes nothing about what the file means.
    return text.removeprefix("﻿")


def _toml_table(
    text: str, *, path: Path, layer: ConfigLayer, section: tuple[str, ...]
) -> object:
    """Parse TOML and return the sub-table at ``section``.

    ``section`` is empty for a standalone file. A missing intermediate table is
    ``None`` -- a ``pyproject.toml`` with no ``[tool]`` is ordinary.
    """

    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        # tomllib reports line and column, never the content of the offending
        # line, so its message is safe to surface verbatim.
        raise ConfigError(
            f"{path}: malformed TOML: {exc}",
            layer=layer,
            location=str(path),
        ) from None

    node: object = document
    for part in section:
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def _json_table(text: str, *, path: Path, layer: ConfigLayer) -> object:
    """Parse JSON and return the top-level object."""

    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey as exc:
        raise ConfigError(
            f"{path}: key {str(exc)!r} appears more than once; JSON would keep "
            "whichever came last, which makes the file ambiguous",
            layer=layer,
            location=str(path),
        ) from None
    except json.JSONDecodeError as exc:
        # json.JSONDecodeError carries the offending line, so only the position
        # and its own words are used here.
        raise ConfigError(
            f"{path}: malformed JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})",
            layer=layer,
            location=str(path),
        ) from None


def _require_table(
    value: object, *, path: Path, layer: ConfigLayer
) -> Mapping[str, object]:
    """Return ``value`` if it is a mapping, else raise."""

    if isinstance(value, Mapping):
        return value
    raise ConfigError(
        f"{path}: the configuration must be a table/object, got {value!r}",
        layer=layer,
        location=str(path),
    )


# ---------------------------------------------------------------------------
# The result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Config:
    """A resolved configuration: the settings one scan will actually use.

    The object is a thin, immutable description of *where* to scan and *how*,
    holding no copies of the shipped defaults. It carries provenance so that
    "why is this setting what it is?" is answerable without re-running the
    merge, which is what makes precedence testable and supportable.

    Attributes:
        root: The directory configuration was resolved against, resolved to an
            absolute path so that the result does not depend on the caller's
            current directory.
        path_scan: The scan settings, ready for
            :func:`~secret_shield.sources.filesystem.scan_path`.
        origins: The layers that contributed at least one setting, lowest
            precedence first. Empty when no layer set anything, which is the
            signal that the shipped defaults are in force unchanged.
    """

    root: Path
    path_scan: PathScanConfig
    origins: tuple[ConfigOrigin, ...] = ()

    @property
    def scan_config(self) -> ScanConfig:
        """The single-file settings, for :func:`~secret_shield.scanner.scan_file`."""

        return self.path_scan.scan

    def path_scan_config(self) -> PathScanConfig:
        """Return the directory-scan settings.

        A method as well as the :attr:`path_scan` field, so that call sites read
        symmetrically with the other ``*_config()`` factories in this package.
        """

        return self.path_scan

    def source_of(self, key: str) -> ConfigOrigin | None:
        """Return the layer that set ``key``, or ``None`` if the default stands."""

        for origin in reversed(self.origins):
            if key in origin.keys:
                return origin
        return None

    def is_default(self, key: str) -> bool:
        """Return whether ``key`` still holds its shipped default."""

        return self.source_of(key) is None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _resolve_root(project_root: Path) -> Path:
    """Validate and absolutise the project root."""

    if not isinstance(project_root, Path):
        raise TypeError(
            f"project_root must be a pathlib.Path, got {type(project_root).__name__}"
        )
    resolved = project_root.resolve()
    if not resolved.is_dir():
        raise ConfigError(
            f"{project_root}: is not a directory, so there is no project to "
            "configure",
            location=str(project_root),
        )
    return resolved


def _read_mapping_layer(
    path: Path,
    *,
    layer: ConfigLayer,
    section: tuple[str, ...],
) -> tuple[dict[str, object], ConfigOrigin] | None:
    """Read one file layer, or return ``None`` if it contributed nothing."""

    text = _read_text(path, layer=layer)
    if text is None:
        return None

    if layer is ConfigLayer.PYPROJECT:
        found = _toml_table(text, path=path, layer=layer, section=section)
        if found is None:
            # pyproject.toml exists but says nothing about us. Completely normal.
            return None
        table = _require_table(found, path=path, layer=layer)
    elif layer is ConfigLayer.JSON:
        table = _require_table(
            _json_table(text, path=path, layer=layer), path=path, layer=layer
        )
    else:
        table = _require_table(
            _toml_table(text, path=path, layer=layer, section=()),
            path=path,
            layer=layer,
        )

    flat = _flatten(table, layer=layer, location=path.name)
    validated = {
        key: _coerce_mapping_value(
            _SETTINGS_BY_KEY[key], value, layer=layer, location=path.name
        )
        for key, value in flat.items()
    }
    return validated, ConfigOrigin(
        layer=layer, location=path.name, keys=tuple(sorted(validated))
    )


def _read_environment_layer(
    environ: Mapping[str, str],
) -> tuple[dict[str, object], ConfigOrigin] | None:
    """Read every ``SECRETSHIELD_*`` variable in ``environ``."""

    validated: dict[str, object] = {}
    for variable in sorted(environ):
        if not variable.startswith(ENV_PREFIX):
            continue
        if variable == ENV_PREFIX or not variable[len(ENV_PREFIX) :]:
            raise ConfigError(
                f"{variable}: is an incomplete environment variable name; "
                f"expected {ENV_PREFIX}<SETTING>",
                layer=ConfigLayer.ENVIRONMENT,
                location=variable,
            )
        setting = _SETTINGS_BY_ENV.get(variable)
        if setting is None:
            raise ConfigError(
                f"{variable}: unknown setting; valid names are "
                f"{', '.join(sorted(_SETTINGS_BY_ENV))}",
                layer=ConfigLayer.ENVIRONMENT,
                location=variable,
            )
        raw = environ[variable]
        if not isinstance(raw, str):  # pragma: no cover - Mapping[str, str] by contract
            raise ConfigError(
                f"{variable}: environment values must be strings, got "
                f"{type(raw).__name__}",
                layer=ConfigLayer.ENVIRONMENT,
                location=variable,
            )
        validated[setting.key] = _coerce_env_value(
            setting, raw, layer=ConfigLayer.ENVIRONMENT, location=variable
        )
    if not validated:
        return None
    return validated, ConfigOrigin(
        layer=ConfigLayer.ENVIRONMENT,
        location="environment",
        keys=tuple(sorted(validated)),
    )


def _read_overrides_layer(
    overrides: Mapping[str, object],
) -> tuple[dict[str, object], ConfigOrigin] | None:
    """Read the caller's explicit overrides."""

    if not isinstance(overrides, Mapping):
        raise TypeError(f"overrides must be a Mapping, got {type(overrides).__name__}")
    flat = _flatten(overrides, layer=ConfigLayer.OVERRIDES, location="overrides")
    validated = {
        key: _coerce_mapping_value(
            _SETTINGS_BY_KEY[key],
            value,
            layer=ConfigLayer.OVERRIDES,
            location="overrides",
        )
        for key, value in flat.items()
    }
    if not validated:
        return None
    return validated, ConfigOrigin(
        layer=ConfigLayer.OVERRIDES, location="overrides", keys=tuple(sorted(validated))
    )


# ---------------------------------------------------------------------------
# Applying the merged values
# ---------------------------------------------------------------------------
#
# Which setting lands in which object is written out by hand below rather than
# derived from the section name. Deriving it looks tidier and is wrong: the
# "scan" section spans two different objects, because the per-file size cap
# belongs to ScanConfig while the file count and line length belong to
# PathScanConfig. A mis-routed setting does not raise -- it quietly scans with a
# limit nobody set, which is the one class of bug this whole stage exists to
# make impossible.


_SCAN_CONFIG_KEYS: Final[tuple[str, ...]] = ("scan.max_file_size",)
"""Settings that become fields of ScanConfig."""

_PATH_SCAN_KEYS: Final[tuple[str, ...]] = (
    "scan.max_files",
    "scan.max_line_length",
    "scan.jobs",
)
"""Settings that become fields of PathScanConfig."""

_ENTROPY_KEYS: Final[tuple[str, ...]] = (
    "entropy.min_length",
    "entropy.min_raw_entropy",
    "entropy.max_raw_entropy",
    "entropy.min_normalized_entropy",
    "entropy.max_prose_words",
    "entropy.max_severity",
)
"""Settings that become fields of EntropyRuleConfig."""

_PATH_FILTER_KEYS: Final[tuple[str, ...]] = (
    "paths.max_depth",
    "paths.follow_symlinks",
    "paths.ignored_directories",
    "paths.ignored_filenames",
    "paths.ignored_extensions",
    "paths.ignored_paths",
)
"""Settings that become fields of PathFilterConfig."""

_BINARY_KEYS: Final[tuple[str, ...]] = (
    "binary.max_sniff_bytes",
    "binary.max_control_ratio",
)
"""Settings that become fields of BinaryConfig."""


_DataclassT = TypeVar("_DataclassT")


def _apply(
    base: _DataclassT,
    keys: Sequence[str],
    values: Mapping[str, object],
    provenance: Mapping[str, ConfigOrigin],
) -> _DataclassT:
    """Return ``base`` with the given settings' merged values applied.

    Only keys the merge actually produced are touched, so a target with nothing
    configured comes back as the same object it went in as -- which is what
    keeps an unconfigured scan byte-identical to the pre-configuration one.

    Where there is something to apply, ``dataclasses.replace`` re-runs the
    target's own ``__post_init__``. That is the point: every setting ends up
    validated by the class that owns it, so this module never restates -- and can
    never drift from -- a rule the scanner already enforces. That is why there
    is no "extension must start with a dot" check here; the path filter already
    has one, and a second copy would be one more thing to forget to update.
    """

    updates = {_SETTINGS_BY_KEY[key].name: values[key] for key in keys if key in values}
    if not updates:
        return base
    try:
        return dataclasses.replace(base, **updates)  # type: ignore[type-var]
    except (TypeError, ValueError) as exc:
        # Cross-field rules live in __post_init__, so the wording comes from the
        # class that knows the rule. ConfigError strips control characters from
        # it, because these messages quote the offending value back.
        origin = _highest_origin(provenance, keys)
        where = origin.location if origin is not None else "configuration"
        raise ConfigError(
            f"{where}: {exc}",
            layer=origin.layer if origin is not None else None,
            location=where,
        ) from None


def _highest_origin(
    provenance: Mapping[str, ConfigOrigin], keys: Sequence[str]
) -> ConfigOrigin | None:
    """Return the highest-precedence origin among ``keys``, or ``None``.

    Used to attribute a cross-field failure -- one that no single value is
    responsible for, such as an entropy floor set above its own ceiling -- to the
    place a reader will actually go looking.
    """

    best: ConfigOrigin | None = None
    for key in keys:
        origin = provenance.get(key)
        if origin is not None and (
            best is None or origin.layer.precedence > best.layer.precedence
        ):
            best = origin
    return best


def _build_registry(
    disabled: Sequence[str], provenance: Mapping[str, ConfigOrigin]
) -> DetectorRegistry | None:
    """Return a registry with ``disabled`` removed, or ``None`` if none are.

    Returning ``None`` matters: it leaves :meth:`PathScanConfig.rules` on its own
    default path, so a configuration that disables nothing yields a config object
    equal to the shipped one rather than an equivalent copy. An explicitly empty
    deny list is therefore a no-op rather than a way to accidentally pin the
    catalog at today's contents.
    """

    if not disabled:
        return None

    catalog = default_registry()
    known = set(catalog.ids())
    unknown = sorted({rule_id for rule_id in disabled if rule_id not in known})
    if unknown:
        origin = provenance.get("rules.disabled")
        where = origin.location if origin is not None else "configuration"
        raise ConfigError(
            f"{where}: rules.disabled names unknown rule id(s) "
            f"{', '.join(repr(rule_id) for rule_id in unknown)}; known ids are "
            f"{', '.join(sorted(known))}",
            layer=origin.layer if origin is not None else None,
            key="rules.disabled",
            location=where,
        )

    removed = frozenset(disabled)
    return DetectorRegistry(rule for rule in catalog if rule.id not in removed)


def _build_path_scan(
    values: Mapping[str, object], provenance: Mapping[str, ConfigOrigin]
) -> PathScanConfig:
    """Assemble the effective scan settings from the merged values."""

    base = default_path_scan_config()
    entropy: EntropyRuleConfig = _apply(
        default_entropy_config(), _ENTROPY_KEYS, values, provenance
    )
    directory: PathScanConfig = _apply(base, _PATH_SCAN_KEYS, values, provenance)
    scan: ScanConfig = _apply(base.scan, _SCAN_CONFIG_KEYS, values, provenance)
    filters: PathFilterConfig = _apply(
        base.filters, _PATH_FILTER_KEYS, values, provenance
    )
    binary: BinaryConfig = _apply(base.binary, _BINARY_KEYS, values, provenance)
    # values is Mapping[str, object], but "rules.disabled" is always a sequence of strings
    disabled: Sequence[str] = values.get("rules.disabled", ()) or ()  # type: ignore[assignment]
    registry = _build_registry(disabled, provenance)

    try:
        return dataclasses.replace(
            base,
            scan=dataclasses.replace(scan, entropy=entropy),
            filters=filters,
            binary=binary,
            registry=registry,
            max_line_length=directory.max_line_length,
            max_files=directory.max_files,
            jobs=directory.jobs,
        )
    except (TypeError, ValueError) as exc:
        # PathScanConfig checks only types and two positive integers, so this is
        # unreachable from the schema today. It is wrapped anyway: the day a
        # cross-field rule lands there, it must surface as a ConfigError like
        # everything else rather than as a bare ValueError from dataclasses.
        raise ConfigError(f"invalid scan settings: {exc}") from None


# ---------------------------------------------------------------------------
# The entry point
# ---------------------------------------------------------------------------


def load_config(
    *,
    project_root: Path,
    overrides: Mapping[str, object] | None = None,
    environ: Mapping[str, str] | None = None,
) -> Config:
    """Resolve the configuration for a project.

    Reads every layer in precedence order, validates each one independently,
    then merges. With nothing to read, the result is equal to
    :func:`~secret_shield.sources.filesystem.default_path_scan_config`, so the
    behaviour of a scan with configuration support and the behaviour without it
    are the same thing.

    Every layer is validated even when a later layer would have overwritten it.
    That is deliberate: a typo committed to ``pyproject.toml`` must fail on a
    developer laptop with no environment variables set, or it will sit there
    until the day the variable stops being set and the wrong setting silently
    takes effect.

    Args:
        project_root: Directory holding ``pyproject.toml`` and the optional
            config files. Must exist. Resolved to an absolute path, so the
            result does not depend on the caller's working directory.
        overrides: Settings supplied programmatically, as the highest-precedence
            layer. Both spellings are accepted: ``{"scan.max_files": 10}`` and
            ``{"scan": {"max_files": 10}}``. Values must already be typed; no
            string parsing happens here, so an ``int`` stays an ``int``.
        environ: Environment variables to read. Defaults to :data:`os.environ`
            when omitted. Injected rather than read at module scope so that
            tests never have to mutate global process state.

    Returns:
        An immutable :class:`Config`.

    Raises:
        TypeError: If ``project_root`` is not a :class:`~pathlib.Path`,
            ``overrides`` is not a mapping, or ``environ`` is not a mapping.
        ConfigError: If ``project_root`` is not a directory, or if any layer is
            unreadable, names an unknown setting, or holds a value of the wrong
            type or outside its range.
    """

    if environ is None:
        environ = os.environ
    if not isinstance(environ, Mapping):
        raise TypeError(f"environ must be a Mapping, got {type(environ).__name__}")
    if overrides is not None and not isinstance(overrides, Mapping):
        raise TypeError(f"overrides must be a Mapping, got {type(overrides).__name__}")

    root = _resolve_root(project_root)
    layers: list[tuple[dict[str, object], ConfigOrigin]] = []

    from_pyproject = _read_mapping_layer(
        root / "pyproject.toml",
        layer=ConfigLayer.PYPROJECT,
        section=PYPROJECT_SECTION,
    )
    if from_pyproject is not None:
        layers.append(from_pyproject)

    for filename in CONFIG_FILENAMES:
        found = _read_mapping_layer(
            root / filename, layer=ConfigLayer(filename), section=()
        )
        if found is not None:
            layers.append(found)

    from_env = _read_environment_layer(environ)
    if from_env is not None:
        layers.append(from_env)

    if overrides:
        from_overrides = _read_overrides_layer(overrides)
        if from_overrides is not None:
            layers.append(from_overrides)

    # Later layers overwrite earlier ones. Replacement alone is what makes this
    # associative; see the module docstring for why no layer extends another.
    merged: dict[str, object] = {}
    provenance: dict[str, ConfigOrigin] = {}
    for values, origin in layers:
        for key, value in values.items():
            merged[key] = value
            provenance[key] = origin

    return Config(
        root=root,
        path_scan=_build_path_scan(merged, provenance),
        origins=tuple(origin for _, origin in layers),
    )
