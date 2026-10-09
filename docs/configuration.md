# Configuration Reference

SecretShield uses a **layered configuration** model. Later layers always win — there is no merging, no extension, and no silent fallback. Every setting has exactly one effective value, and `Config.source_of(key)` tells you which layer set it.

## Layer Precedence (lowest → highest)

1. **Built-in defaults** — hard-coded in each module's `default_*_config()` factory
2. **`pyproject.toml`** — `[tool.secretshield]` section
3. **`.secretshield.toml`** — project-root TOML file
4. **`.secretshield.json`** — project-root JSON file (for CI systems that only emit JSON)
5. **`SECRETSHIELD_*` environment variables** — one per setting
6. **Explicit overrides** — `load_config(overrides={...})` from the CLI or API

> **Why only these files?** Three is enough. `pyproject.toml` is where Python projects already keep settings. `.secretshield.toml` is the human-facing file. JSON exists for CI. No other format is accepted — every additional format is a second schema to keep in sync and a second parser to keep secure.

> **Why no list extension?** Every list **replaces**. If a layer sets `paths.ignored_directories`, the shipped defaults are gone, not merged. Replacement is associative, visible, and a committed file states its policy completely. The cost (restating defaults to add one entry) is worth the auditability.

## Configuration Files

### pyproject.toml

```toml
[tool.secretshield]
# all settings live under this table
```

### .secretshield.toml

```toml
# top-level keys are sections, or use dotted keys
[scan]
max_file_size = 1048576
jobs = 4

[paths]
max_depth = 3
ignored_directories = ["vendor", "dist"]

[rules]
disabled = ["stripe-test-key"]
```

### .secretshield.json

```json
{
  "scan": {
    "max_file_size": 1048576,
    "jobs": 4
  },
  "paths": {
    "max_depth": 3,
    "ignored_directories": ["vendor", "dist"]
  },
  "rules": {
    "disabled": ["stripe-test-key"]
  }
}
```

Both TOML and JSON accept **nested tables** (`[section] key = value`) and **flat dotted keys** (`"section.key" = value`). They produce the same flat mapping.

### Environment Variables

Prefix: `SECRETSHIELD_` + uppercase setting name (leaf only, no section).

| Setting | Environment Variable |
| --- | --- |
| `scan.max_file_size` | `SECRETSHIELD_MAX_FILE_SIZE` |
| `paths.max_depth` | `SECRETSHIELD_MAX_DEPTH` |
| `rules.disabled` | `SECRETSHIELD_DISABLED` (comma-separated) |
| `entropy.min_length` | `SECRETSHIELD_MIN_LENGTH` |

**Boolean values:** `1`, `true`, `yes`, `on` / `0`, `false`, `no`, `off` (case-insensitive)

**Optional integer "no limit":** `none`, `null`, `unlimited`, `unset` (case-insensitive). Empty string is **not** accepted — it is treated as an error because `MAX_DEPTH=` in a CI template is more likely a mistake than a deliberate unlimited scan.

**String lists:** Comma-separated, whitespace trimmed per entry. `ignored_directories = "vendor, dist"`

**Severity values:** `low`, `medium`, `high`, `critical` (case-insensitive, hyphens/underscores normalized)

### CLI Overrides

Command-line flags map directly to settings and are passed as the `overrides` layer (highest precedence). Validation is identical to file layers — `--jobs 0` fails with the same message and exit code as `jobs = 0` in a file.

```bash
secret-shield scan . --jobs 8 --max-depth 3 --fail-on high
```

## Complete Setting Reference

### scan

| Setting | Type | Default | Min | Max | Description |
| --- | --- | --- | --- | --- | --- |
| `scan.max_file_size` | integer | 10485760 (10 MiB) | 1 | — | Largest file read, in bytes |
| `scan.max_files` | integer | 100000 | 1 | — | Largest number of files one scan will read before it stops |
| `scan.max_line_length` | integer | 65536 | 1 | — | Longest line handed to the candidate extractor, in characters |
| `scan.jobs` | integer | 1 | 1 | 64 | Number of worker threads. 1 = serial |

### paths

| Setting | Type | Default | Min | Max | Description |
| --- | --- | --- | --- | --- | --- |
| `paths.max_depth` | optional integer | `null` (no limit) | 0 | — | Deepest file to scan from root. Unset = no limit |
| `paths.follow_symlinks` | boolean | `false` | — | — | Whether a symlink inside the root may be followed. Even when true, a symlink resolving outside the root is skipped |
| `paths.ignored_directories` | string list | `[".git", ".hg", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".svn", ".tox", ".venv", "__pycache__", "env", "node_modules", "venv"]` | — | — | Directory names skipped anywhere in the tree. **Replaces defaults** |
| `paths.ignored_filenames` | string list | `[".DS_Store", ".Spotlight-V100", "Thumbs.db", "desktop.ini"]` | — | — | Exact file names skipped anywhere in the tree. **Replaces defaults** |
| `paths.ignored_extensions` | string list | `[".7z", ".a", ".aac", ".ai", ".avi", ".avif", ".beam", ".bin", ".bmp", ".bz2", ".class", ".core", ".dat", ".db", ".dll", ".dmg", ".doc", ".docx", ".dsym", ".dylib", ".eot", ".eps", ".exe", ".flac", ".gif", ".gz", ".heic", ".ico", ".iso", ".jar", ".jpeg", ".jpg", ".lib", ".m4a", ".mdb", ".mkv", ".mov", ".mp3", ".mp4", ".o", ".obj", ".ogg", ".otf", ".pdb", ".pdf", ".png", ".ppt", ".pptx", ".prof", ".psd", ".pyc", ".pyd", ".pyo", ".rar", ".so", ".sqlite", ".sqlite3", ".tar", ".tgz", ".tif", ".tiff", ".ttf", ".war", ".wasm", ".wav", ".webm", ".webp", ".whl", ".wmv", ".woff", ".woff2", ".xls", ".xlsx", ".xz", ".zip", ".zst"]` | — | — | Extensions skipped (with or without leading dot). **Replaces defaults** |
| `paths.ignored_paths` | string list | `[]` (empty) | — | — | Relative POSIX paths skipped with everything under them. **Replaces default (empty)** |

### binary

| Setting | Type | Default | Min | Max | Description |
| --- | --- | --- | --- | --- | --- |
| `binary.max_sniff_bytes` | integer | 8192 | 1 | — | Leading bytes inspected to classify a file as text |
| `binary.max_control_ratio` | number | 0.30 | 0.0 | 1.0 | Control-character ratio above which a file is treated as binary |

### entropy

| Setting | Type | Default | Min | Max | Description |
| --- | --- | --- | --- | --- | --- |
| `entropy.min_length` | integer | 20 | 1 | — | Shortest high-entropy candidate considered, in characters |
| `entropy.min_raw_entropy` | number | 3.5 | 0.0 | — | Minimum Shannon entropy (bits/char) |
| `entropy.max_raw_entropy` | number | 8.0 | 0.0 | — | Candidates above this are ignored as non-credential text |
| `entropy.min_normalized_entropy` | number | 0.8 | 0.0 | 1.0 | Minimum evenness ratio (0..1) |
| `entropy.max_prose_words` | integer | 2 | 0 | — | Candidates with more than this many multi-char words are ignored |
| `entropy.max_severity` | severity | `medium` | — | `medium` | Severity ceiling for entropy-only findings. Cannot exceed MEDIUM |

### rules

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `rules.disabled` | string list | `[]` | IDs of vendor rules to switch off. No allow list exists. Unknown IDs are a hard error. |

## Defaults Summary

The shipped defaults are conservative:

- **Scan:** 10 MiB file cap, 100k file cap, 65536-character line cap, 1 worker
- **Paths:** No depth limit, no symlink following; ignores VCS metadata, tool caches, virtualenvs and `node_modules`, OS junk files, and media, font, archive and compiled-binary extensions. It deliberately does **not** skip build output (`dist`, `build`, `vendor`) or text lockfiles — secrets land there
- **Binary:** 8 KiB sniff, 30% control-character ratio
- **Entropy:** Length ≥ 20, raw entropy ≥ 3.5, normalized ≥ 0.8, ≤ 2 prose words, severity capped at MEDIUM
- **Rules:** None disabled

## Validation Rules

- **Unknown keys are hard errors** — a misspelled setting that is quietly dropped applies a limit nobody set. Error message includes a "did you mean" suggestion.
- **Type mismatches are errors** — a string where a list is expected, a boolean where an integer is expected, etc.
- **Range violations are errors** — out-of-bounds numbers, invalid severity labels.
- **Duplicate keys are errors** — in TOML (stdlib rejects), in JSON (custom hook rejects), in env (impossible), in overrides (validated).
- **Files are size-capped** at 1 MiB before parsing — a hostile checkout cannot OOM the scanner via a huge config file.
- **Control characters are stripped** from all error messages — a crafted filename cannot repaint a terminal.

## Viewing Effective Configuration

```bash
# The CLI does not have a dedicated "config show" command yet.
# For now, run a scan with --format json and inspect the summary,
# or use the Python API:

python -c "
from pathlib import Path
from secret_shield.config import load_config
cfg = load_config(project_root=Path('.'))
print('Root:', cfg.root)
print('Origins:', [(o.layer.value, o.location, o.keys) for o in cfg.origins])
print('Max file size:', cfg.path_scan.scan.max_file_size)
print('Jobs:', cfg.path_scan.jobs)
print('Disabled rules:', cfg.path_scan.registry.ids() if cfg.path_scan.registry else 'all enabled')
"
```

## Configuration for `git` Subcommand

**`secret-shield git` does not read configuration files.** It takes its limits on the command line only (`--max-commits`, `--max-blobs`, `--max-refs`, `--max-blob-size`, `--max-line-length`, `--timeout`, `--since`, `--until`, `--respect-path-filters`). This is intentional: a history scan cannot be silently reshaped by a repository-local file that the scanner is about to audit.

## Common Patterns

### Ignore a vendor directory

```toml
# .secretshield.toml
[paths]
ignored_directories = ["vendor", "third_party", "external"]
```

### Reduce scan depth for monorepos

```toml
[paths]
max_depth = 3
```

### Disable noisy test-key rules

```toml
[rules]
disabled = ["stripe-test-key", "stripe-publishable-key"]
```

### Tighten entropy for fewer false positives

```toml
[entropy]
min_length = 24
min_normalized_entropy = 0.85
```

### CI: fail only on CRITICAL

```bash
secret-shield scan . --fail-on critical
# or in config:
# [scan]
# fail_on = "critical"  (not a real setting yet; use CLI flag)
```

> **Note:** `--fail-on` is a CLI-only flag, not a configuration setting. It controls the exit code threshold, not the scan behavior.

## Security Notes

- Configuration files are **untrusted input**. They are parsed as data only — no `eval`, `exec`, `pickle`, dynamic `import`, or `subprocess`.
- No setting value is ever compiled into a regex. Custom user-supplied rules are deferred; the schema has no placeholder for them.
- `Config.source_of(key)` returns the layer that set a key, or `None` if the default stands. This makes "why is this value what it is?" answerable without re-running the merge.
