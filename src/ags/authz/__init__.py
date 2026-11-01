"""Authorization for agent tool calls (chapter 4).

A default-deny policy decision point with deny-overrides,
explainable decisions and human-approval verdicts, plus a
tenant guard that checks the resource, not just the role.
"""

from ags.authz.guards import AuthzGuard, TenantGuard
from ags.authz.pdp import (
    Condition,
    Explanation,
    PolicyDecisionPoint,
    Rule,
    cmp,
    resolve,
)

__all__ = [
    "AuthzGuard",
    "Condition",
    "Explanation",
    "PolicyDecisionPoint",
    "Rule",
    "TenantGuard",
    "cmp",
    "resolve",
]
