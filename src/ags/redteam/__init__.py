"""Chapter 13: red-teaming agents as a repeatable test.

Attack scenarios with observable success conditions, benign
tasks to catch over-blocking, small defense configurations,
a harness reporting attack success rate per configuration
and category, and a release gate.
"""

from ags.redteam.defenses import (
    CONFIGS,
    Defense,
    EgressAllowlist,
    KeywordFilter,
    RefundLimit,
    TaintRule,
    TenantCheck,
    ToolDenylist,
)
from ags.redteam.harness import (
    Gate,
    Report,
    Result,
    clean_env,
    evaluate,
    gate,
    run_scenario,
)
from ags.redteam.scenarios import ATTACKS, BENIGN, Scenario, act

__all__ = [
    "ATTACKS",
    "BENIGN",
    "CONFIGS",
    "Defense",
    "EgressAllowlist",
    "Gate",
    "KeywordFilter",
    "RefundLimit",
    "Report",
    "Result",
    "Scenario",
    "TaintRule",
    "TenantCheck",
    "ToolDenylist",
    "act",
    "clean_env",
    "evaluate",
    "gate",
    "run_scenario",
]
