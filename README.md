# SecretShield

SecretShield is a Python security scanner for detecting accidentally exposed secrets and credentials in source code, configuration files, and Git repositories.

## Status

**Stage 1 — a working single-file scanner. No vendor rules, no CLI yet.**

You can now scan one text file and read a human-readable report:

```python
import secret_shield

result = secret_shield.scan_file("config/settings.py")
print(secret_shield.render_text(result))
```

Detection today is **entropy screening only**. It finds values that look like
machine-generated key material regardless of vendor, and it deliberately cannot
tell you whether any of them is a real credential. A SHA-1 commit hash, a UUID
and a leaked API key are the same shape to an entropy measurement, so all three
are reported, at MEDIUM severity and PROBABLE confidence, for a human to
dismiss.

| Component | State |
| --- | --- |
| `masking` — redaction, fingerprints, sanitized excerpts | Done, tested |
| `models` — `Finding`, `Location`, `ScanResult`, enums | Done, tested |
| `exit_codes` — the CI exit-code contract | Done |
| `entropy` — Shannon entropy, evenness ratio, charset families | Done, tested |
| `tokenizer` — conservative candidate extraction | Done, tested |
| `detectors` — high-entropy rule (one rule, MEDIUM ceiling) | Done, tested |
| `scanner` — `scan_file`, safe text reading, statistics | Done, tested |
| `report` — `render_text`, pure and deterministic | Done, tested |
| Vendor rules (AWS, GitHub, Stripe, ...) | Not started |
| Directory traversal, allowlists, context scoring | Not started |
| Filesystem and Git history scanning | Not started |
| CLI, JSON and Markdown reports | Not started |

`python -m secret_shield` still exits with code `5`. There is no CLI until
directory traversal exists; scanning one file at a time by hand is not the
intended interface.

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

7. **The scanner stays quiet on ordinary source code.** Entropy alone flags
   every long mixed-character string, which in a Python repository means every
   constant, f-string fragment and docstring cross-reference. The tokenizer
   discards six shapes that are syntax rather than data — interpolation braces,
   qualified references, named constants, documentation roles, regular
   expression syntax, and call parentheses — plus anything spanning a line, on
   the grounds that key material is single-line. Each filter states what it
   suppresses in its docstring, and each accepted cost has a test pinning it.
   Scanning this repository's own source produces zero findings.

## Project structure

```
src/secret_shield/          # src layout: tests cannot import repo files by accident
├── __init__.py             # public API, __version__
├── __main__.py             # `python -m secret_shield` (placeholder until the CLI lands)
├── models.py               # Finding, Location, ScanError, ScanResult, enums
├── masking.py              # mask(), fingerprint(), sanitize_excerpt()
├── exit_codes.py           # the CI exit-code contract
├── entropy.py              # Shannon entropy, evenness, charset families
├── tokenizer.py            # candidate extraction and structural filters
├── detectors/              # detection rules; currently one entropy rule
│   └── entropy_rule.py
├── scanner.py              # scan_file(): read one text file, return a result
└── report/                 # ScanResult -> str; no I/O, no colours
    └── text.py
tests/
├── conftest.py             # synthetic fixtures; src/ bootstrap
├── unit/
│   ├── test_masking.py
│   ├── test_models.py
│   ├── test_entropy.py
│   ├── test_tokenizer.py
│   ├── test_entropy_rule.py
│   ├── test_scanner.py
│   └── test_text_report.py
└── integration/
    └── test_single_file_scan.py
```

Modules still to come: `config.py`, `pipeline.py`, `filters/`, `sources/`
(filesystem and Git history), `cli.py`, and JSON and Markdown reporters.

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

Scan a file the way the tests do:

```bash
python -c "import secret_shield as s; print(s.render_text(s.scan_file('README.md')))"
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