# SecretShield

SecretShield is a Python security scanner for detecting accidentally exposed secrets and credentials in source code, configuration files, and Git repositories.

## Status

**Stage 0 — foundations. Not yet a scanner.**

The detection engine, the CLI, and the reports do not exist yet. What is
implemented today is the layer everything else is built on, and the one that is
hardest to retrofit safely: redaction and the data model.

| Component | State |
| --- | --- |
| `masking` — redaction, fingerprints, sanitized excerpts | Done, tested |
| `models` — `Finding`, `Location`, `ScanResult`, enums | Done, tested |
| `exit_codes` — the CI exit-code contract | Done |
| Detection rules, entropy analysis | Not started |
| Filesystem and Git history scanning | Not started |
| CLI, reports | Not started |

`python -m secret_shield` exits with code `5` and says so plainly, rather than
pretending to be a working scanner.

## Goals

- Detect common API keys, tokens, passwords, private keys, and database credentials
- Detect high-entropy suspicious strings
- Safely mask detected secrets
- Scan repositories efficiently
- Produce JSON and Markdown audit reports

## Design commitments

These are properties the code is written to keep, not aspirations. They are
enforced by tests, because each one is expensive to add late.

1. **A finding cannot hold a raw secret.** `Finding` has no field that can
   store secret material. The value is masked and fingerprinted inside
   `Finding.from_match()` and then dropped, so a stray `print()`, `repr()`,
   debugger session or traceback has nothing to leak.

2. **Severity and confidence are separate.** Severity answers "if this is real,
   how bad is it?" and comes from the rule. Confidence answers "how sure are
   we this is real?" and comes from the evidence for that particular match. A
   generic `password = "..."` line is CRITICAL severity but only MEDIUM
   confidence.

3. **Findings are candidates, not verdicts.** A regular-expression match is
   evidence that something secret-shaped exists, nothing more. `Confidence.
   VERIFIED` exists for a future out-of-band verification step; the initial
   release never produces it.

4. **Redaction never encodes length.** Every secret shorter than the reveal
   threshold collapses to the same fixed-width marker, so the mask cannot be
   used as an oracle for how long a secret is.

5. **Zero runtime dependencies.** A secret scanner is a high-value supply-chain
   target, so it depends only on the standard library. `pytest` is a
   development dependency and is never imported at runtime.

6. **Scanned content is untrusted input.** It is never executed, evaluated or
   interpolated into a shell. Control characters, bidirectional overrides and
   ANSI escapes are stripped before anything is displayed, so a hostile
   repository cannot reshape a report or repaint a terminal.

## Project structure

```
src/secret_shield/          # src layout: tests cannot import repo files by accident
├── __init__.py             # public API, __version__
├── __main__.py             # `python -m secret_shield` (placeholder until the CLI lands)
├── models.py               # Finding, Location, ScanError, ScanResult, enums
├── masking.py              # mask(), fingerprint(), sanitize_excerpt()
└── exit_codes.py           # the CI exit-code contract
tests/
├── conftest.py             # synthetic fixtures; src/ bootstrap
└── unit/
    ├── test_masking.py
    └── test_models.py
```

Modules still to come: `config.py`, `pipeline.py`, `detectors/`, `filters/`,
`sources/` (filesystem and Git history), `report/`, `cli.py`.

## Development

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Run a single file, or a single test:

```bash
pytest tests/unit/test_masking.py
pytest -k fingerprint
```

## Security

Never place real credentials in this repository. Use synthetic test secrets only.

Test values follow placeholders published in vendor documentation, such as
`AKIAIOSFODNN7EXAMPLE`, which is AWS's own documented example key. Any secret
added later must be obviously fabricated and must live under `tests/`.

If you believe you have found a real credential in this repository, please
report it privately rather than opening a public issue.

## License

MIT