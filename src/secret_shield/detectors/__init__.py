"""Detection rules for SecretShield.

Stage 1 ships exactly one detector: high-entropy screening. Vendor-specific
pattern rules are deliberately absent; they arrive in a later stage.
"""

from __future__ import annotations

from .entropy_rule import (
    RULE_ID,
    RULE_NAME,
    REMEDIATION,
    EntropyRuleConfig,
    default_entropy_config,
    detect,
    evaluate,
)

__all__ = [
    "RULE_ID",
    "RULE_NAME",
    "REMEDIATION",
    "EntropyRuleConfig",
    "default_entropy_config",
    "detect",
    "evaluate",
]