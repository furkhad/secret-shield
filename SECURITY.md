# Security Policy

## Supported Versions

SecretShield is in early development. Only the latest release on the default branch receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Do not open a public issue for a security vulnerability.**

If you believe you have found a real credential in this repository, or a vulnerability in the scanner itself, report it privately:

- Email: **security@secret-shield.example** (replace with actual contact)
- Or use GitHub's private vulnerability reporting: Security tab → "Report a vulnerability"

We will acknowledge receipt within 72 hours and provide a status update within 7 days.

## What We Consider a Security Issue

### In the scanner code
- Path traversal or symlink escape during filesystem scanning
- Command injection in Git history scanning (`git_cmd.py` uses argv lists with `shell=False`)
- Denial of service via resource exhaustion (oversized files, deep trees, many files)
- Information leakage through error messages, logs, or tracebacks
- Failure to redact secrets in any output channel (stdout, stderr, JSON, Markdown)

### In the repository
- Any real credential committed to this repository (test fixtures must be synthetic and marked)

## What We Do Not Consider a Security Issue

- False positives or false negatives in detection — these are quality issues
- Missing support for a credential format — file a feature request
- Performance on extremely large repositories — file a performance issue
- Configuration mistakes by the user — the schema validates strictly

## Hardened Design Choices

These are not configurable and will not be changed:

1. **No runtime dependencies** — only the Python standard library
2. **No shell invocation** — `subprocess` calls use argv lists, `shell=False`, explicit timeouts
3. **No execution of scanned content** — content is never `eval`ed, `exec`ed, or interpolated
4. **Control-character stripping** — all output paths strip ANSI escapes, bidirectional overrides, and control characters before display
5. **Findings never hold raw secrets** — `Finding.from_match()` masks and fingerprints the value, then drops it
6. **Configuration is untrusted** — TOML/JSON parsed with stdlib only, size-capped at 1 MiB, unknown keys are hard errors
7. **Symlink safety** — a symlink whose target resolves outside the scan root is skipped even when `follow_symlinks=true`
8. **Binary files are not searched** — they are sniffed and skipped
9. **Git history is read-only** — only `rev-parse`, `log`, `cat-file` are invoked; nothing is checked out, written, or fetched

## Testing Security Properties

The test suite includes:
- Synthetic fixtures only (`tests/vendor_fixtures.py` enforces `SYNTH` marker)
- Path traversal and symlink escape attempts
- Binary file handling
- Oversized file and line handling
- Control character injection in filenames and content
- Configuration injection attempts (malformed TOML/JSON, unknown keys, oversized files)
- Exit code contract verification (partial results outrank findings)

Run the full test suite:

```bash
pytest -q
```

## Disclosure Timeline

1. Report received → acknowledgment within 72 hours
2. Triage → severity assessment within 7 days
3. Fix development → target within 14 days for CRITICAL/HIGH
4. Release → patch release with fix, no details in changelog until users have time to upgrade
5. Public disclosure → after fix is released, with CVE if applicable

## Attribution

Security research is credited in release notes unless the reporter requests anonymity.
