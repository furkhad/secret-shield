# Detection Rules Reference

SecretShield ships with a built-in catalog of vendor-specific pattern rules and one entropy-based rule. Rules are data — adding a rule means appending to the `RULES` tuple in `src/secret_shield/detectors/catalog.py`; no engine code changes.

## Rule Properties

Every rule carries:

| Property | Meaning |
| --- | --- |
| `id` | Stable kebab-case identifier (e.g., `aws-secret-access-key`) |
| `name` | Human-readable name for reports |
| `category` | `SecretCategory` — what kind of credential (aws, github, database, etc.) |
| `severity` | Impact **if the match is real** — LOW, MEDIUM, HIGH, CRITICAL |
| `specificity` | `EXACT` (known prefix + length) or `HEURISTIC` (shape only) |
| `base_confidence` | Starting confidence for a match — CANDIDATE, PROBABLE, HIGH_CONFIDENCE |
| `keywords` | Variable names that increase confidence when on the same line |
| `min_entropy` | Entropy floor; matches below are discarded |
| `requires_context` | If true, a keyword must be present for the rule to fire |
| `priority` | Tie-breaker when multiple rules match the same bytes (lower = earlier) |
| `false_positive_notes` | Documented known false positives |
| `remediation` | Actionable advice for a confirmed finding |

## Severity vs Confidence

**Severity** answers: *If this is real, how bad is it?* It comes from the rule and is fixed.

**Confidence** answers: *How sure are we this match is real?* It comes from the evidence for *this particular match*.

Examples:
- `stripe-publishable-key` → **LOW** severity (designed to be public), **HIGH_CONFIDENCE** (known prefix + length)
- `aws-secret-access-key` → **CRITICAL** severity (full account access), **PROBABLE** confidence (shape only, requires context keyword)
- Generic `password = "..."` → **CRITICAL** severity, **MEDIUM** confidence (context-driven)
- Entropy-only match → **MEDIUM** severity (capped), **PROBABLE** confidence (statistical only)

## Vendor Rules

### AWS

| Rule ID | Name | Severity | Specificity | Confidence | Context Required |
| --- | --- | --- | --- | --- | --- |
| `aws-access-key-id` | AWS access key ID | MEDIUM | EXACT | HIGH_CONFIDENCE | No |
| `aws-secret-access-key` | AWS secret access key | CRITICAL | HEURISTIC | PROBABLE | Yes |

**Notes:**
- Access key ID (AKIA/ASIA prefix, 20 chars) is public by design — appears in CloudTrail, billing, IAM policies. Alone it grants nothing.
- Secret access key is a 40-char base64 string with no distinguishing prefix. The rule **only fires when a context keyword** (`aws_secret_access_key`, `secret_access_key`, etc.) appears on the same line. This prevents burying other rules in false positives from SHA-1 hashes, certificate fingerprints, etc.
- A real secret stored under an uninformative name (`CREDS`, `VALUE`) will be missed by this rule but caught by the entropy screen at MEDIUM/PROBABLE.

### OpenAI

| Rule ID | Name | Severity | Specificity | Confidence |
| --- | --- | --- | --- | --- |
| `openai-api-key-legacy` | OpenAI API key (legacy `sk-` format) | HIGH | EXACT | HIGH_CONFIDENCE |
| `openai-api-key` | OpenAI API key (project/service account) | HIGH | EXACT | HIGH_CONFIDENCE |

**Notes:**
- Legacy `sk-` format: exactly 48 alphanumerics after prefix.
- Current formats: `sk-proj-...` and `sk-svcacct-...` with no published length (lower bound 20 chars).
- Disjoint patterns — a key matches exactly one rule.

### GitHub

| Rule ID | Name | Severity | Specificity | Confidence |
| --- | --- | --- | --- | --- |
| `github-pat-classic` | GitHub personal access token (classic) | HIGH | EXACT | HIGH_CONFIDENCE |
| `github-pat-fine-grained` | GitHub fine-grained PAT | HIGH | EXACT | HIGH_CONFIDENCE |
| `github-app-token` | GitHub app or refresh token | MEDIUM | EXACT | HIGH_CONFIDENCE |

**Notes:**
- Classic PAT: `ghp_`, `gho_`, `ghu_` — 36 chars after prefix. User-scoped, broad access.
- Fine-grained: `github_pat_` + 82+ chars with underscores. Minimum length only (no published exact length).
- App/refresh: `ghs_` (server-to-server), `ghr_` (refresh) — 36 chars. Narrower scope than classic PAT.

### Stripe

| Rule ID | Name | Severity | Specificity | Confidence |
| --- | --- | --- | --- | --- |
| `stripe-secret-key-live` | Stripe live secret key | CRITICAL | EXACT | HIGH_CONFIDENCE |
| `stripe-restricted-key-live` | Stripe live restricted key | HIGH | EXACT | HIGH_CONFIDENCE |
| `stripe-test-key` | Stripe test-mode key | MEDIUM | EXACT | HIGH_CONFIDENCE |
| `stripe-publishable-key` | Stripe publishable key | LOW | EXACT | HIGH_CONFIDENCE |

**Notes:**
- No published key lengths — all patterns use a 16-char lower bound.
- Test keys (`sk_test_`, `rk_test_`) are MEDIUM: often documentation, not leaks.
- Publishable keys (`pk_live_`, `pk_test_`) are LOW: designed to be public (embedded in browsers).
- Severity split is intentional: all four rules are equally certain they found a Stripe key; they differ entirely in what that key is worth.

### Slack

| Rule ID | Name | Severity | Specificity | Confidence |
| --- | --- | --- | --- | --- |
| `slack-incoming-webhook` | Slack incoming webhook URL | MEDIUM | EXACT | HIGH_CONFIDENCE |

**Notes:**
- Matches documented `https://hooks.slack.com/services/T.../B.../token` structure.
- MEDIUM: incoming webhook can post messages but cannot read history, enumerate channels, or act as a user.
- Structurally plausible fake URLs appear in documentation and are indistinguishable without contacting Slack.

### Private Keys

| Rule ID | Name | Severity | Specificity | Confidence |
| --- | --- | --- | --- | --- |
| `private-key-block` | Private key block | CRITICAL | EXACT | HIGH_CONFIDENCE |

**Notes:**
- Matches `-----BEGIN *PRIVATE KEY...-----` headers (RSA, DSA, EC, OPENSSH, PGP, ENCRYPTED).
- `PUBLIC KEY` and `CERTIFICATE` headers explicitly excluded — they are designed to be public.
- Body bounded at 40,000 chars so a missing footer cannot turn one header into a whole-file match.
- Truncated keys (paste cut off mid-block) are still reported.

### Database Connection Strings

| Rule ID | Name | Severity | Specificity | Confidence |
| --- | --- | --- | --- | --- |
| `database-uri-with-password` | Database connection string with password | CRITICAL | EXACT | HIGH_CONFIDENCE |

**Notes:**
- Schemes: `postgres`, `postgresql`, `mysql`, `mongodb`, `mongodb+srv`, `redis`.
- Requires `user:password@` — URIs without a password component do not match.
- Password captured as named group `secret` so only the password is reported (not host/db).
- Password < 4 chars treated as filler.
- Template URIs (`postgres://u:${PG_PASS}@host/db`) are suppressed as templates.

## Entropy Rule

| Rule ID | Name | Severity | Confidence | Category |
| --- | --- | --- | --- | --- |
| `high-entropy-string` | High-entropy string | MEDIUM (capped) | PROBABLE | UNKNOWN |

**What it claims:** *This text has enough character variety to be worth a human look.*

**What it does not claim:** *This text is a credential.*

**Gates (all must pass):**
1. Length ≥ `entropy.min_length` (default: 20)
2. Not prose: ≤ `entropy.max_prose_words` space-separated words of ≥2 chars (default: 2)
3. Shannon entropy ≥ `entropy.min_raw_entropy` (default: 3.5 bits/char)
4. Shannon entropy ≤ `entropy.max_raw_entropy` (default: 8.0 bits/char)
5. Normalized entropy (evenness ratio) ≥ `entropy.min_normalized_entropy` (default: 0.8)

**Why 3.5 not 4.0?** Hex alphabet has a mathematical ceiling of exactly 4.0 bits/char. Real hex tokens measure 3.93–3.98. A gate at 4.0 would silently discard them. The floor sits at 3.5; normalized entropy does the discriminating.

**False positives to expect:** Git commit/blob hashes, UUIDs, checksums, minified assets, embedded images (data URIs), compiled binary blobs, hex-encoded API keys that belong to a vendor rule which did not match.

**Suppression:** Disable for a path in configuration, or tune `entropy.min_length` / `entropy.min_normalized_entropy`. Do not trust a single hit.

## Rule Interaction: Fusion

When a pattern rule and the entropy rule match overlapping spans, the pipeline fuses them into a single **COMPOSITE** finding:

- Severity = max(pattern severity, entropy severity)
- Confidence = upgraded (entropy corroborates pattern)
- Detector = `COMPOSITE`
- Category = pattern rule's category
- Remediation = pattern rule's remediation

This prevents double-reporting the same secret and upgrades confidence when both detectors agree.

## Disabling Rules

Only a deny list exists: `rules.disabled = ["rule-id-1", "rule-id-2"]` in configuration.

**No allow list.** An allow list committed months ago would silently disable rules added to the catalog since — the worst failure mode for a secret scanner. A deny list has the opposite property: new catalog rules show up as new findings, which a human triages, rather than as silence.

Unknown rule IDs in `rules.disabled` are a configuration error (hard fail).

## Listing Rules

```bash
# Human-readable table
secret-shield rules list

# Machine-readable JSON
secret-shield rules list --format json
```

Output includes: id, name, category, severity, specificity, confidence, keywords, priority, and whether context is required.

## Adding a Rule (For Contributors)

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-vendor-rule). Summary:

1. Add `Rule` to `RULES` in `src/secret_shield/detectors/catalog.py`
2. Use synthetic fixtures only — no real credentials
3. Document `false_positive_notes` honestly
4. Write actionable `remediation`
5. Add tests in `tests/unit/test_vendor_rules.py` and `tests/vendor_fixtures.py`
6. Update this file (`docs/rules.md`)
7. Run `pytest -q`
