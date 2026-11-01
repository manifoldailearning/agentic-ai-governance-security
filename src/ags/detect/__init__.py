"""Chapter 14: detecting attacks in agent event streams.

Rules over the runtime's ``Event`` stream raise ``Alert``
objects with evidence and generic tactic tags; scenarios
drive the real runtime to produce normal and attack traffic.
"""

from ags.detect.rules import (
    Alert,
    ApprovalBypass,
    BulkPiiEgress,
    CrossTenant,
    DeniedBurst,
    RareSequence,
    Rule,
    SensitiveAfterUntrusted,
    SequenceBaseline,
    default_rules,
    detect,
    effects_of,
)
from ags.detect.scenarios import (
    ASHA,
    ATTACKS,
    NORMAL,
    RefundLimit,
    Scenario,
    play,
    support_runtime,
)

__all__ = [
    "ASHA",
    "ATTACKS",
    "NORMAL",
    "Alert",
    "ApprovalBypass",
    "BulkPiiEgress",
    "CrossTenant",
    "DeniedBurst",
    "RareSequence",
    "RefundLimit",
    "Rule",
    "Scenario",
    "SensitiveAfterUntrusted",
    "SequenceBaseline",
    "default_rules",
    "detect",
    "effects_of",
    "play",
    "support_runtime",
]
