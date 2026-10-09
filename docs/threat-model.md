# Threat Model

This document describes the assets SecretShield protects, the threat actors and their capabilities, the trust boundaries, and the mitigations implemented in the code. It is written for maintainers, security reviewers, and users who need to understand the security posture of the tool.

## Assets

| Asset | Description | Sensitivity |
| --- | --- | --- |
| **Scanned source code** | Files and Git blobs read during a scan. May contain real secrets. | High — contains the very secrets we're trying to find |
| **Secrets detected** | API keys, tokens, passwords, private keys, database URIs found during scan | Critical — the primary output of the tool |
| **Scan reports** | JSON, Markdown, or text output containing findings (masked values, locations, fingerprints) | Medium — redacted, but fingerprints and locations are metadata |
| **Configuration** | `.secretshield.toml`, `.secretshield.json`, `pyproject.toml`, env vars | Low — but untrusted input; can shape scan behavior |
| **Tool integrity** | The scanner binary/package itself, its dependencies, its supply chain | Critical — a compromised scanner is a supply-chain attack vector |

## Threat Actors

| Actor | Motivation | Capabilities |
| --- | --- | --- |
| **Malicious repository author** | Exfiltrate secrets from the scanner's environment, corrupt scan results, escape the scan sandbox | Controls all files in the scanned repo, including filenames, content, symlinks, Git history, config files |
| **Malicious package maintainer / supply chain** | Inject backdoor into SecretShield package | Controls PyPI release, GitHub Actions, dependencies |
| **CI/CD system compromise** | Steal secrets found during scan, modify scan results | Controls CI environment, environment variables, artifacts, logs |
| **Local developer (accidental)** | Leak secrets via misconfiguration, tool misuse | Runs scanner locally, commits config, views reports |
| **Report consumer** | Extract secrets from report artifacts | Reads JSON/Markdown reports, CI logs, PR comments |

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                        SCANNER PROCESS                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Config     │  │  Scanner    │  │  Reporter   │             │
│  │  Loader     │──▶│  Pipeline   │──▶│  (stdout)   │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                      │
│         ▼                ▼                ▼                      │
│  ┌─────────────────────────────────────────────┐               │
│  │           PYTHON STDLIB ONLY                │               │
│  │  (no runtime deps, no shell, no eval)       │               │
│  └─────────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
         │                │                │
         ▼                ▼                ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────┐
│  Filesystem     │ │  Git CLI    │ │  Stdout/    │
│  (untrusted)    │ │  (argv only)│ │  Stderr     │
└─────────────────┘ └─────────────┘ └─────────────┘
```

**Inside the boundary:** Python stdlib, scanner logic, configuration schema validation.
**Outside the boundary:** Scanned files, Git repository, configuration files, environment variables, stdout/stderr, CI system.

## Threats and Mitigations

### T1: Path Traversal / Symlink Escape

**Threat:** A scanned repository contains a symlink pointing outside the scan root (`../../../etc/passwd`). The scanner follows it and reads sensitive files.

**Mitigation:**
- `PathFilterConfig.follow_symlinks` defaults to `false`
- Even when `true`, `resolve_within()` (in `filters/paths.py`) resolves the whole
  symlink chain and returns `None` unless the final target is the scan root or
  inside it, so the walk never reads through an escaping link
- `scan_path()` in `filesystem.py` validates every resolved path before reading
- Tests: `tests/unit/test_path_filter.py` includes symlink escape attempts

**Residual Risk:** None if `follow_symlinks=false` (default). If user enables it, the root check is enforced.

### T2: Command Injection via Git

**Threat:** A malicious repository crafts a Git revision, branch name, or config that injects shell commands when the scanner invokes `git`.

**Mitigation:**
- **Only** `git_cmd.py` invokes `subprocess`
- **All** invocations use `argv` lists: `["git", "rev-parse", ...]`
- **Never** `shell=True`
- **Explicit timeout** on every call (default 300s)
- Revision arguments beginning with `-` are rejected before invocation (prevents option injection)
- No user input is interpolated into command strings

**Residual Risk:** None — `shell=False` with argv lists eliminates shell injection. Option injection blocked by `-` prefix rejection.

### T3: Information Leakage via Output

**Threat:** A finding, error message, or log line contains a raw secret, or control characters that reshape terminal output to hide or forge findings.

**Mitigation:**
- **Finding invariant:** `Finding` class has **no field that can hold a raw secret**. `Finding.from_match()` masks, fingerprints, and drops the raw value immediately.
- **Redaction never encodes length:** All secrets shorter than the reveal threshold collapse to the same fixed-width marker (`************`).
- **Control character stripping:** `strip_control_characters()` applied to:
  - All file paths at `Location` construction
  - All error reasons at `ScanError` construction
  - All remediation text at `Finding` construction
  - All config error messages (user-typed values)
  - All JSON/Markdown/text report output
- **stdout purity:** Only the report goes to stdout. Diagnostics, per-file errors, `--output` confirmation go to stderr.
- **No raw secret in tracebacks:** Because the raw value is dropped inside `from_match()`, a stray `print()`, `repr()`, debugger session, or traceback has nothing to leak.

**Residual Risk:** Low. Fingerprints are truncated SHA-256 (12 chars) or HMAC — not reversible. Value length is reported (deliberate triage field) but masked value never encodes length.

### T4: Denial of Service via Resource Exhaustion

**Threat:** A malicious repository causes the scanner to consume unbounded memory, CPU, or time — OOM, hang, or timeout.

**Mitigation:**
| Resource | Limit | Location |
| --- | --- | --- |
| File size | `scan.max_file_size` (default 10 MiB) | `scanner.py`, `ScanConfig` |
| Line length | `scan.max_line_length` (default 65536) | `filesystem.py`, `git_history.py` |
| File count | `scan.max_files` (default 100,000) | `filesystem.py`, `PathScanConfig` |
| Tree depth | `paths.max_depth` (default unlimited, configurable) | `filesystem.py`, `PathFilterConfig` |
| Git blob size | `--max-blob-size` (default `scan.max_file_size`, 10 MiB) | `git_history.py` |
| Git commit count | `--max-commits` (default unlimited, configurable) | `git_history.py` |
| Git distinct blobs | `--max-blobs` (default 200,000) | `git_history.py` |
| Git distinct paths | `--max-refs` (default 800,000) | `git_history.py` |
| Config file size | `MAX_CONFIG_BYTES` = 1 MiB | `config.py` |
| Subprocess timeout | 300s per `git` call | `git_cmd.py` |
| Thread count | `scan.jobs` ≤ 64 | `config.py`, `filesystem.py` |

- Binary files are sniffed (`binary.max_sniff_bytes` = 8 KiB) and skipped — not scanned
- Control-character ratio > 30% → treated as binary, skipped
- Each blob in Git history read **once** (keyed by object ID) — a file moved across 1000 commits is scanned once
- When `scan.jobs` > 1, `filesystem.py` uses a fixed `ThreadPoolExecutor` pool of at most 64 workers, and the walk is materialised under the `scan.max_files` bound

**Residual Risk:** A repository with 100,001 tiny files will stop at the limit (exit code 3 = partial). User must raise `--max-files` deliberately.

### T5: Configuration Injection

**Threat:** A malicious `.secretshield.toml` in a cloned repo disables rules, widens limits, or injects malicious values.

**Mitigation:**
- Configuration is **parsed as data, never code**: `tomllib` (stdlib), `json.loads` (stdlib) — no `eval`, `exec`, `pickle`, dynamic `import`, `subprocess`
- **Unknown keys are hard errors** — silently dropped keys are settings the author believed they set
- **Duplicate keys are errors** — TOML rejects natively; JSON uses `object_pairs_hook` to reject
- **Files size-capped at 1 MiB** before parsing
- **Every value type-checked and range-checked** before reaching scanner settings
- **Environment variables:** Only `SECRETSHIELD_*` prefix recognized; unknown names are errors
- **`secret-shield git` ignores config files entirely** — takes limits only from CLI, so a history scan cannot be silently reshaped by a repo-local file

**Residual Risk:** A user who deliberately writes a bad config can disable rules or widen limits. That is a policy decision, not an injection.

### T6: Supply Chain Compromise

**Threat:** A compromised dependency or build pipeline injects malicious code into the SecretShield package.

**Mitigation:**
- **Zero runtime dependencies** — `dependencies = []` in `pyproject.toml`. Only stdlib at runtime.
- **Dev dependencies only:** `pytest` (test runner), `ruff`/`mypy` (optional lint/type) — never imported at runtime
- **Source layout** (`src/secret_shield`) — tests cannot import repo files by accident
- **Reproducible builds:** `python -m compileall -q src` passes, deterministic output
- **Release:** GitHub Actions builds from tagged commit, publishes to PyPI with trusted publisher (no password/token in CI)

**Residual Risk:** Python stdlib itself, CPython interpreter, OS, hardware — out of scope.

### T7: False Sense of Security (False Negatives)

**Threat:** User believes a clean scan means no secrets exist. Scanner misses a credential format, or a secret is in an unscanned location.

**Mitigation:**
- **Honest documentation:** README "Known limits" section states plainly what is not scanned (SHA-256 repos, non-HEAD refs, blobs > 10 MiB, binary blobs, unbounded history by default)
- **Candidates, not verdicts:** Every finding is labeled with confidence (CANDIDATE/PROBABLE/HIGH_CONFIDENCE/VERIFIED). Initial release never produces VERIFIED.
- **Entropy screen catches unknown formats:** High-entropy strings are reported at MEDIUM/PROBABLE even without a vendor rule
- **Git history scans distinct blobs** — a secret committed and later deleted is found
- **Coverage reported:** Git scan stderr line reports commits walked, distinct blobs searched, what was skipped (binary, oversized, truncated)
- **Self-scan test:** `secret-shield scan src/` produces zero findings — proves the scanner doesn't flag its own code

**Residual Risk:** Inherent to static analysis. A secret in a minified bundle, a binary blob, a non-HEAD branch, or a SHA-256 repo will not be found. User must understand the limits.

### T8: Report Tampering / Exfiltration

**Threat:** A CI job or report consumer extracts secrets from report artifacts, or a malicious repo forges findings in CI logs.

**Mitigation:**
- **Reports contain no raw secrets** — only masked values (`************`), fingerprints (truncated digest), lengths, locations
- **Fingerprints are not reversible** — SHA-256 truncated to 12 hex chars, or HMAC with user-provided key
- **HMAC key required for low-entropy values** — `--fingerprint hmac` requires `SECRETSHIELD_FINGERPRINT_KEY` env var; per-run random key would break determinism
- **`--fingerprint none`** omits digest entirely for public reports — unkeyed digest of low-entropy value is brute-forceable
- **stdout is data only** — `--format json` is pipeable; nothing else corrupts it
- **Control characters stripped** — a hostile repo cannot inject ANSI escapes to hide/forge findings in terminal output

**Residual Risk:** Fingerprints correlate occurrences. If an attacker has a candidate secret, they can compute its fingerprint and search reports for it. This is by design — correlation is a feature. HMAC key prevents this for low-entropy values.

### T9: Git History Tampering

**Threat:** Scanner modifies the repository (checks out commits, writes files, creates refs).

**Mitigation:**
- **Read-only Git subcommands:** `rev-parse`, `log`, `cat-file` only
- **Nothing checked out, written, fetched, or referenced**
- **No ref, index, or working-tree file modified** — `git status` after scan is identical to before
- **SHA-256 repos detected and refused** — `unsupported-object-format` error, not mis-scanned

**Residual Risk:** None — scanner is read-only by construction.

## Security Invariants (Enforced by Tests)

| Invariant | Test Location |
| --- | --- |
| No raw secret in `Finding` | `tests/unit/test_models.py::test_finding_cannot_hold_a_raw_secret` |
| Control chars stripped from paths | `tests/functional/test_cli.py::test_a_filename_with_control_characters_is_sanitised` |
| Symlink outside root skipped | `tests/unit/test_path_filter.py::test_a_symlink_out_of_the_root_is_refused` |
| Git argv list, no shell | `tests/unit/test_git_cmd.py::test_this_is_the_only_module_in_the_package_that_imports_subprocess` |
| Config unknown key = error | `tests/unit/test_config.py::test_unknown_key_raises` |
| Config size cap enforced | `tests/unit/test_config.py::test_config_file_size_cap` |
| Binary files skipped | `tests/unit/test_binary_detection.py` |
| Exit code 3 > exit code 1 | `tests/functional/test_cli.py::test_partial_scan_is_three_and_beats_findings` |
| Deterministic output | `tests/functional/test_cli.py::test_repeated_runs_are_byte_identical` |
| Self-scan clean | `tests/integration/test_directory_scan.py::test_the_package_source_produces_nothing` |

## Assumptions

1. **Python 3.11+** with stdlib intact — no monkey-patching of `subprocess`, `tomllib`, `json`, `hashlib`
2. **Git CLI available** for `secret-shield git` — version ≥ 2.30 (for `--object-format` detection)
3. **Filesystem permissions** allow reading the scan target — unreadable files produce `ScanError`, not silent skip
4. **User controls the scan root** — they choose what to scan; scanner does not auto-discover repos
5. **Report consumers treat findings as candidates** — not verified secrets

## Out of Scope

- Verifying secrets against issuing services (future `VERIFIED` confidence)
- Rewriting Git history to remove secrets (rotation is the fix, not rewriting)
- Scanning non-Git VCS (Mercurial, SVN, etc.)
- Scanning container images, artifacts, or non-filesystem sources
- Network calls of any kind (no verification, no telemetry, no updates)
- Protecting the user's environment from a malicious *scanner* (that's the OS/package manager's job)
- Secrets in memory of running processes (runtime scanning)

## Incident Response

If a real credential is found in this repository:
1. Rotate the credential at the issuing service immediately
2. Remove from Git history (`git filter-repo` or BFG)
3. Force-push cleaned history
4. Investigate access logs for the rotated credential
5. Report privately per [SECURITY.md](../SECURITY.md)

If a vulnerability is found in the scanner:
1. Report privately per [SECURITY.md](../SECURITY.md)
2. Fix developed on private branch
3. Patch release with minimal changelog
4. Public disclosure after fix released
