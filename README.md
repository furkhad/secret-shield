# SecretShield

SecretShield is a Python security scanner for detecting accidentally exposed secrets and credentials in source code and configuration files.

## Status

**Stage 8 — a working CLI over vendor rules, directory traversal and layered
configuration. No Git history scanning.**

```bash
secret-shield scan .
secret-shield scan src --format json --output report.json
secret-shield rules list
```

Detection combines a **vendor pattern catalog** with an **entropy screen**. A
pattern match knows what it matched; the entropy screen catches values no vendor
claims. Both report *candidates*, never verdicts: nothing is verified against an
issuing service, so every finding is something a human should look at.

| Component | State |
| --- | --- |
| `masking` — redaction, fingerprints, sanitized excerpts | Done, tested |
| `models` — `Finding`, `Location`, `ScanResult`, enums | Done, tested |
| `exit_codes` — the CI exit-code contract | Done, tested |
| `entropy` — Shannon entropy, evenness ratio, charset families | Done, tested |
| `tokenizer` — conservative candidate extraction and structural filters | Done, tested |
| `detectors` — 14 vendor rules + the entropy rule | Done, tested |
| `filters` — binary sniffing, path exclusion, symlink safety | Done, tested |
| `pipeline` — match fusion, context scoring, dedup | Done, tested |
| `config` — layered settings: defaults, file, environment, overrides | Done, tested |
| `sources/` — filesystem traversal | Done, tested |
| `report` — `render_text`, `render_json`, `render_markdown` | Done, tested |
| `cli` — argparse front end, exit codes, atomic `--output` | Done, tested |
| Git history scanning | Not started |
| SARIF, baselines, allowlists | Not started |

## Command line

Two invocations, identical output:

```bash
secret-shield scan TARGET          # installed console script
python -m secret_shield scan TARGET   # no installation needed
```

`TARGET` is a file or a directory. A directory is walked subject to the
configured limits.

```bash
secret-shield scan config/settings.py
secret-shield scan . --format json | jq '.summary'
secret-shield scan . --jobs 8 --max-depth 3 --fail-on high
secret-shield scan src --min-confidence probable --fingerprint none
secret-shield scan . --format markdown --output report.md
secret-shield rules list
secret-shield rules list --format json
```

`--help`, `scan --help` and `rules --help` document every option. Each flag maps
onto an existing configuration setting, so a limit set on the command line and
the same limit set in a file are validated identically.

### Exit codes

CI branches on these, so they are part of the contract:

| Code | Meaning |
| --- | --- |
| `0` | Nothing met the failure threshold |
| `1` | Findings reached the threshold (`--fail-on`) |
| `2` | Usage error: bad arguments, an invalid target, or bad configuration |
| `3` | The scan finished with errors, so the result is **partial** |
| `4` | Internal error |
| `5` | Not implemented — unreachable in this release |
| `130` | Interrupted |

**Partial results beat findings.** `3` wins over `1`, so a scan that could not
read every input can never pass a pipeline that only distinguishes `0` from `1`.
A truncated scan must not be able to look like a clean one.

### Streams

**stdout carries the report and nothing else.** Diagnostics, per-file failures
and the `--output` confirmation go to stderr, so `--format json` is always
pipeable. With `--output`, stdout stays completely empty.

No raw secret, and no source line, reaches either stream.

### Determinism

Two runs of the same command over an unchanged tree produce byte-identical
output, and `--jobs 1` and `--jobs 8` agree. Nothing in a report depends on wall
clock time. Fingerprints are stable across runs under `--fingerprint sha256`, or
`hmac` with a fixed key:

```bash
SECRETSHIELD_FINGERPRINT_KEY="$(openssl rand -hex 32)" \
    secret-shield scan . --format json --output report.json
```

`--fingerprint hmac` requires that key rather than inventing a random one per
run, because a per-run key would make two runs of the same command disagree.
`--fingerprint none` omits the digest entirely, for a report bound for a public
URL — an unkeyed digest of a low-entropy value can be brute-forced.

### Configuration

Settings are layered. Later layers win:

1. built-in defaults
2. `pyproject.toml` `[tool.secretshield]`
3. `.secretshield.toml`, then `.secretshield.json`
4. `SECRETSHIELD_*` environment variables
5. command line options

```toml
# .secretshield.toml
[scan]
jobs = 4
max_file_size = 1048576

[paths]
max_depth = 3
ignored_directories = ["vendor"]

[rules]
disabled = ["stripe-test-key"]
```

Rules are disabled through configuration, not through a flag. An unknown
setting, an out-of-range value or an unknown rule id is an error rather than
being silently ignored — a misspelled limit that is quietly dropped applies a
limit nobody set.

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
   Scanning this repository's own `src/` produces zero findings.

8. **The exit code is the interface.** A tool that reports a problem and exits
   `0` is a tool CI learns to ignore, and one that maps every failure to `1`
   cannot tell a clean run from a broken one. `exit_codes.py` is the single
   source of truth, partial results outrank findings, and no flag exists for a
   capability the release does not have.

9. **stdout is a data channel.** The report is the only thing written there, so
   `--format json` is pipeable. Diagnostics are separate, and `--output` leaves
   stdout empty. A report can be captured by a CI job without anything else
   corrupting it.

10. **Argument values are configuration, not a back door.** Command line
    options are passed into `load_config()` as the highest-precedence
    `overrides` layer rather than assigned onto a config object afterwards, so
    `--jobs 0` fails with the same message and the same exit code as
    `jobs = 0` in a file. There is no way for a flag to carry a value the
    configuration schema would have rejected.

## Project structure

```
src/secret_shield/          # src layout: tests cannot import repo files by accident
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
│   └── entropy_rule.py     # the entropy screen
├── filters/                # binary sniffing, path exclusion
├── sources/
│   └── filesystem.py       # scan_path(): directory traversal
└── report/                 # ScanResult -> str; no I/O, no colours
    ├── text.py
    ├── json_report.py
    └── markdown.py
tests/
├── conftest.py             # synthetic fixtures; src/ bootstrap
├── vendor_fixtures.py      # obviously fake credentials, marker-checked
├── unit/                   # one module per unit
├── integration/            # layers composed
└── functional/             # the CLI, run as a subprocess
```

Modules still to come: `sources/git.py` (history scanning), SARIF output,
baselines, and allowlists.

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

Check the CLI the way a user would:

```bash
python -m secret_shield --help
python -m secret_shield scan . --format json | jq '.summary'
python -m secret_shield rules list
```

`tests/functional/test_cli.py` runs the CLI as a real subprocess, which is the
only way to observe the exit status a parent sees and whether stdout stays pure
through a pipe.

## Security

Never place real credentials in this repository. Use synthetic test secrets only.

Test values must be obviously fabricated and must live under `tests/`.
`tests/vendor_fixtures.py` enforces this: every fixture carries the substring
`SYNTH`, and a module-level check raises if one does not, so a failure message
naming a fixture cannot read like a live credential.

Scanning this repository reports findings only inside `tests/`, and only the
entropy rule plus the vendor rules matching those synthetic values. `src/` is
clean.

One known false positive is worth naming, because it is the kind of thing a
user will hit in their first minute: `--fingerprint` entry points and other
dotted configuration strings are reported by the entropy rule. In this
repository, `pyproject.toml`'s own `secret-shield = "secret_shield.cli:main"`
line is such a finding. The entropy screen cannot tell a dotted module path from
a token — that is the cost of a rule that works on values no vendor claims.

If you believe you have found a real credential in this repository, please
report it privately rather than opening a public issue.

## License

MIT