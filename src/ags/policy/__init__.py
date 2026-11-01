"""Chapter 16: policy as code for agent authorization.

Versioned JSON policy documents, validated and compiled to a
runtime guard with a decision log; unit cases with expected
verdicts; impact analysis that replays recorded tool calls
against a candidate policy.
"""

from ags.policy.document import (
    Policy,
    PolicyError,
    Ruling,
    support_policy,
    validate,
)
from ags.policy.guard import (
    DecisionRecord,
    PolicyGuard,
    compile_policy,
)
from ags.policy.review import (
    CaseResult,
    Change,
    impact,
    run_cases,
)

__all__ = [
    "CaseResult",
    "Change",
    "DecisionRecord",
    "Policy",
    "PolicyError",
    "PolicyGuard",
    "Ruling",
    "compile_policy",
    "impact",
    "run_cases",
    "support_policy",
    "validate",
]
