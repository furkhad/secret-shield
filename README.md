# SecretShield

SecretShield is a Python security scanner for detecting accidentally exposed secrets and credentials in source code and configuration files.

## Status

**Stage 9 — a working CLI over vendor rules, directory traversal, layered
configuration and Git history.**

```bash
secret-shield scan .
secret-shield scan src --format json --output report.json
secret-shield git .                     # also finds what was deleted
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
| `sources/` — Git history scanning | Done, tested |
| `report` — `render_text`, `render_json`, `render_markdown` | Done, tested |
| `cli` — argparse front end, exit codes, atomic `--output` | Done, tested |
| SARIF, baselines | Done, tested |

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

### Git history

`scan` reads what is on disk. A credential that was committed and then deleted
is not on disk, so `scan` cannot see it — which is the usual way a real leak
survives a cleanup commit. `git` reads the history instead:

```bash
secret-shield git .
secret-shield git . --format json --output history.json
secret-shield git ~/work/repo --since "2 years ago" --fail-on high
```

It is a separate subcommand rather than a `scan` flag, because it answers a
different question about a different object. Both share the reporters, the
detectors and the exit-code contract, so a finding reads the same either way.

**What it does.** Git names every blob reachable from `HEAD` and the paths it
was committed at (`git log --raw`, a names-only pass that moves no file content),
the references are reduced to the *distinct* blobs, and the survivors' contents
are streamed back once each (`git cat-file`). Every blob is analysed by the same
pipeline that `scan` uses, labelled `source_kind = "git"`. Each finding names
the newest commit in which that content was present at that path, and reads
`path:line:column@commit` — the reference an editor or `git blame` understands.

**Each blob is read once.** A repository that moves a large vendored file
across a thousand commits stores one object, not a thousand. Blobs are keyed by
object id, so history is scanned once per *distinct* object no matter how many
commits or paths reference it; the remaining references are counted rather than
re-analysed. This is what makes the scan of a large repository finish at all.
A blob that was current at one path and historical at another yields one finding
per path, each attributed to the newest commit at that path.

**It reads; it does not touch.** Nothing is checked out, written, fetched or
referenced, and no ref, index or working-tree file is modified — `git status`
afterwards is identical to `git status` before. The only Git subcommands invoked
are the read-only `rev-parse`, `log` and `cat-file`. No command is built as a
string, so there is no shell to inject into; every invocation is an argv list
with `shell=False` and an explicit timeout. A revision beginning with `-` is
rejected rather than passed on, so it cannot become an option.

**Today's ignore rules do not apply.** A path ignored now may not have been
ignored when the secret was committed, and skipping it would be exactly the
wrong answer. `--respect-path-filters` opts into the same default filtering
that `scan` uses — `node_modules`, `.venv`, `__pycache__` and the rest — and
to nothing beyond it.

**Coverage is reported, not assumed.** When part of the history is not examined,
a stderr line says how many commits were walked, how many distinct objects were
actually searched, and what was skipped — binary blobs, oversized blobs, paths
over the length limit — or that history was truncated by `--max-commits`. The
line is silent when nothing was skipped, so its absence means everything
reachable from `HEAD` was searched. Anything genuinely unreadable is an error,
not a silent skip, so a partial result always says so.

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
│   ├── filesystem.py       # scan_path(): directory traversal
│   ├── git_cmd.py          # the only module that runs Git; no shell, always argv
│   └── git_history.py      # scan_history(): blobs reachable from HEAD
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

Modules still to come: allowlists.

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

## Known limits

Stated plainly, because a limit you know about is a decision you can make and a
limit you discover in CI is a surprise.

- **Git history scanning reads SHA-1 repositories only.** A repository created
  with `--object-format=sha256` is detected and refused with
  `unsupported-object-format`, not mis-scanned. Git's SHA-256 support is not
  yet universal, and a scan that silently walked nothing would look identical to
  a clean repository.
- **Only `HEAD` is scanned.** Branches, tags, reflog entries, stashes and
  dangling objects that are not reachable from `HEAD` are not visited. A secret
  on an abandoned branch is a real leak this will not find.
- **No object is written, so nothing is cleaned.** This tool reports; it does
  not rewrite history. Removing a leaked credential from Git requires rewriting
  history and rotating the credential, and rotating the credential is the part
  that actually matters — a leaked key that was never used is still leaked once
  it was pushed.
- **History is unbounded by default.** `git` reads every commit reachable from
  `HEAD` with no commit limit, which on a multi-gigabyte repository is a long
  scan. `--max-commits`, `--max-blobs` and `--max-refs` bound it, and the
  coverage line reports when a bound was hit.
- **Blobs over `--max-blob-size` (10 MiB) are not read.** They are counted and
  named in the coverage line rather than read into memory.
- **Binary blobs are not searched.** There is no text to scan, and forcing
  bytes through the tokenizer produces noise, not findings.
- **Config-file limits do not apply to `git`.** `secret-shield git` takes its
  limits on the command line and does not read `.secretshield.toml`, so a
  history scan cannot be silently reshaped by a repository-local file that the
  scanner is about to audit.

## License

MIT
