# Contributing to SecretShield

Thank you for considering a contribution. This document describes how to propose changes, run tests, and keep the codebase consistent with its design goals.

## Quick Start

```bash
# Requires Python 3.11+
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Development Principles

These are not guidelines — they are enforced by tests and review.

1. **Zero runtime dependencies.** Adding a dependency to `dependencies` in `pyproject.toml` requires a security review and a compelling reason. `pytest` is a dev dependency only.
2. **No shell, no eval, no exec.** Scanned content is untrusted input. It is never executed, evaluated, or interpolated into a command.
3. **Findings never hold raw secrets.** `Finding.from_match()` is the only way to create a finding from detected material. The raw value is masked, fingerprinted, and dropped inside that call.
4. **Severity and confidence are separate.** Severity = impact if real (from the rule). Confidence = evidence for this match (from the match).
5. **Configuration is untrusted.** Unknown keys are errors. Values are type-checked and range-checked. Files are size-capped.
5. **stdout is a data channel.** The report is the only thing written to stdout. Diagnostics go to stderr. `--output` leaves stdout empty.
6. **Exit codes are the interface.** The contract in `exit_codes.py` is the single source of truth. Partial results (exit 3) outrank findings (exit 1).
7. **Determinism.** Two runs over an unchanged tree produce byte-identical output. `--jobs 1` and `--jobs 8` agree. No report field depends on wall-clock time.
8. **Tests are the specification.** If a behavior matters, it has a test. If a test exists, the behavior is intentional.

## Project Structure

```
src/secret_shield/          # src layout — tests cannot import repo files by accident
├── __init__.py             # public API, __version__
├── __main__.py             # `python -m secret_shield`; delegates to cli.main
├── cli.py                  # argparse front end; no detection logic
├── models.py               # Finding, Location, ScanError, ScanResult, enums
├── masking.py              # mask(), fingerprint(), sanitize_excerpt()
├── exit_codes.py           # the CI exit-code contract
├── entropy.py              # Shannon entropy, evenness, charset families
├── tokenizer.py            # candidate extraction and structural filters
├── config.py               # layered settings: defaults, file, environ, overrides
├── pipeline.py             # match fusion, context scoring, dedup
├── scanner.py              # per-file read + analyse
├── detectors/
│   ├── catalog.py          # the vendor rules
│   ├── base.py             # Rule, RawMatch
│   ├── entropy_rule.py     # the entropy screen
│   └── context.py          # context keywords and scoring
├── filters/                # binary sniffing, path exclusion
├── sources/
│   ├── filesystem.py       # scan_path(): directory traversal
│   ├── git_cmd.py          # the only module that runs Git; no shell, always argv
│   └── git_history.py      # scan_history(): blobs reachable from HEAD
└── report/                 # ScanResult -> str; no I/O, no colours
    ├── text.py
    ├── json_report.py
    ├── markdown.py
    └── security.py         # security.txt generation
tests/
├── conftest.py             # synthetic fixtures; src/ bootstrap
├── vendor_fixtures.py      # obviously fake credentials, marker-checked
├── unit/                   # one module per unit
├── integration/            # layers composed
└── functional/             # the CLI, run as a subprocess
```

## Adding a Vendor Rule

1. Open `src/secret_shield/detectors/catalog.py`
2. Add a new `Rule` to the `RULES` tuple
3. Follow the existing pattern:
   - Use a synthetic fixture or published format description — **never a real credential**
   - Set `severity` = impact if real (LOW/MEDIUM/HIGH/CRITICAL)
   - Set `specificity` = EXACT (known prefix/length) or HEURISTIC (shape only)
   - Set `base_confidence` appropriately (CANDIDATE/PROBABLE/HIGH_CONFIDENCE)
   - Add `keywords` for context scoring
   - Write `false_positive_notes` explaining what this rule might match incorrectly
   - Write actionable `remediation`
   - Assign a `priority` that orders it sensibly among siblings
4. Add tests in `tests/unit/test_vendor_rules.py` and `tests/vendor_fixtures.py`
5. Run `pytest -q` — all tests must pass

**Rules in this catalog are data.** No code in `detectors/base.py` names a vendor. Adding a rule is appending to `RULES`; no engine change is needed.

## Adding a Configuration Setting

1. Add a `Setting` to `SETTINGS` in `config.py`
2. Choose the correct `SettingKind` (INTEGER, OPTIONAL_INTEGER, NUMBER, BOOLEAN, STRING_LIST, SEVERITY)
3. Set `minimum`/`maximum` for numeric kinds
4. Write a one-line `help` string — it appears in error messages and documentation
5. Add the key to the appropriate `_*_KEYS` tuple (`_SCAN_CONFIG_KEYS`, `_PATH_SCAN_KEYS`, etc.)
6. The setting is now available in all five layers (pyproject.toml, .secretshield.toml, .secretshield.json, env, overrides)
7. Add tests in `tests/unit/test_config.py`

## Running Tests

```bash
# All tests
pytest -q

# One module
pytest tests/unit/test_masking.py -q

# Keyword filter
pytest -k fingerprint -q

# Verbose
pytest -v

# With coverage (if installed)
pytest --cov=secret_shield --cov-report=term-missing
```

**Functional tests** run the CLI as a real subprocess. This is the only way to observe the exit status a parent process sees and whether stdout stays pure through a pipe.

```bash
pytest tests/functional/ -v
```

## Code Style

- **Type hints:** All public functions and dataclasses are typed. `mypy --strict` passes on `src/`.
- **Docstrings:** Google-style for modules, classes, and public functions. Private functions may omit.
- **Line length:** 100 characters.
- **Imports:** Stdlib first, then local. No wildcard imports.
- **Dataclasses:** Use `frozen=True, slots=True` for immutability and memory.
- **Enums:** Use `StrEnum`/`IntEnum` with a shared `_LabelledEnum` base for report-facing enums.
- **Errors:** Raise specific exceptions (`ConfigError`, `ValueError`, `TypeError`). Never silently ignore or repair invalid input.

Run static checks:

```bash
# Type checking (if mypy installed)
mypy --strict src/secret_shield

# Linting (if ruff installed)
ruff check src/ tests/

# Formatting (if ruff installed)
ruff format src/ tests/
```

## Pre-commit Hooks

A lightweight pre-commit configuration is provided (`.pre-commit-config.yaml`). Install it:

```bash
pip install pre-commit
pre-commit install
```

Hooks run on every commit:
- `ruff` — lint and format
- `mypy` — type check (if available)
- `pytest -q` — fast test subset (unit tests only, < 30s)
- `check-yaml`, `check-toml`, `check-json` — config file syntax
- `end-of-file-fixer`, `trailing-whitespace` — whitespace hygiene

To run manually:

```bash
pre-commit run --all-files
```

## Pull Request Checklist

Before submitting:

- [ ] `pytest -q` passes (2046+ tests)
- [ ] `python -m compileall -q src` produces no output
- [ ] `git diff --check` produces no output
- [ ] `secret-shield scan .` reports only test fixtures (no findings in `src/`)
- [ ] New code has tests
- [ ] New settings are documented in `docs/configuration.md`
- [ ] New rules are documented in `docs/rules.md`
- [ ] No runtime dependencies added
- [ ] No shell commands added
- [ ] No raw secrets in fixtures (all `tests/` values contain `SYNTH`)

## Release Process

Maintainers only:

1. Update version in `pyproject.toml` and `src/secret_shield/__init__.py`
2. Update `CHANGELOG.md` (if it exists)
3. Tag: `git tag -a v0.x.y -m "Release 0.x.y"`
4. Push tag: `git push origin v0.x.y`
5. GitHub Actions builds and publishes to PyPI

## Code of Conduct

Be respectful. Assume good faith. Focus on the code, not the person. Harassment, discrimination, and disruptive behavior are not tolerated.

## License

By contributing, you agree that your contributions will be licensed under the MIT License (the project's license).