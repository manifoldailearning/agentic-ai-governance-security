"""Chapter 7: information flow control for agents.

Instead of asking "is this text malicious?", ask "given what
this run has already seen, may this action happen?". Labels
travel with data, a policy table decides by label and effect,
and a plan locked before untrusted input bounds the agent.
"""

from ags.flow.guard import FlowGuard, provenance
from ags.flow.labels import (
    DEFAULT_POLICY,
    LABELS,
    POLICY_TABLE,
    FlowRule,
    decide,
    join,
    parse_policy,
)
from ags.flow.plan import ANY, PlanLock, Step, step

__all__ = [
    "ANY",
    "DEFAULT_POLICY",
    "LABELS",
    "POLICY_TABLE",
    "FlowGuard",
    "FlowRule",
    "PlanLock",
    "Step",
    "decide",
    "join",
    "provenance",
    "parse_policy",
    "step",
]
