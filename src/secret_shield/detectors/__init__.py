"""Detection rules for SecretShield.

Two kinds of detector live here, and the distinction is the whole point of the
package:

* **Pattern rules** (:mod:`secret_shield.detectors.catalog`) ask what a value is.
  A ``sk-proj-`` prefix, or a ``postgres://app:${DB_PASSWORD}@host/db`` URI
  whose password has been filled in, identifies a vendor and a credential type
  -- evidence that entropy cannot supply.
* **The entropy rule** (:mod:`secret_shield.detectors.entropy_rule`) asks only
  whether a value *could* be one. It is deliberately blunt, and it is where
  candidates that no vendor claims -- a homemade HMAC, an unlabelled opaque
  token -- still get caught.

Both produce the same kind of result, and neither can prove a credential is
live. Confidence is capped at ``HIGH_CONFIDENCE`` across both, because nothing
in SecretShield contacts an issuing service.

Running both over one file reports one secret twice, so neither module decides
what to do about it: each publishes its evidence, and
:mod:`secret_shield.pipeline` decides whether two matches describe one secret or
two. :func:`entropy_candidates` exists for that -- it is :func:`detect` without
the redaction, so the comparison can happen while the spans are still known.

The engine (:mod:`secret_shield.detectors.base`) knows nothing about any vendor.
Adding a provider is a change to the catalog's data, never to the engine.
"""

from __future__ import annotations

from .base import (
    MAX_MATCH_LENGTH,
    VALUE_GROUP_NAMES,
    DetectorKind,
    DetectorRegistry,
    RawMatch,
    Rule,
    Specificity,
    find_matches,
    findings_from,
)
from .catalog import CATALOG_VERSION, RULES, default_registry, rule_by_id
from .context import (
    CONTEXT_VOCABULARY,
    assignment_name,
    is_placeholder,
    is_template_expression,
    keyword_score,
    looks_like_hash,
)
from .entropy_rule import (
    RULE_ID,
    RULE_NAME,
    REMEDIATION,
    EntropyCandidate,
    EntropyRuleConfig,
    default_entropy_config,
    detect,
    entropy_candidates,
    evaluate,
)

__all__ = [
    # Engine
    "DetectorKind",
    "DetectorRegistry",
    "RawMatch",
    "Rule",
    "Specificity",
    "find_matches",
    "findings_from",
    "MAX_MATCH_LENGTH",
    "VALUE_GROUP_NAMES",
    # Catalog
    "RULES",
    "CATALOG_VERSION",
    "default_registry",
    "rule_by_id",
    # Context
    "CONTEXT_VOCABULARY",
    "assignment_name",
    "is_placeholder",
    "is_template_expression",
    "keyword_score",
    "looks_like_hash",
    # Stage 1 entropy rule, preserved
    "EntropyRuleConfig",
    "RULE_ID",
    "RULE_NAME",
    "REMEDIATION",
    "default_entropy_config",
    "detect",
    "evaluate",
    # Entropy evidence, for Stage 4 fusion
    "EntropyCandidate",
    "entropy_candidates",
]
