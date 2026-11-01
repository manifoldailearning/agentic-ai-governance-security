"""Threat modeling for agents (chapter 2).

Build a ``SystemModel`` from the agent's tool specs, then
enumerate STRIDE and agent-specific threats into a scored,
mitigation-keyed register you can review and version.
"""

from ags.threat.model import (
    Element,
    Flow,
    SystemModel,
    from_specs,
)
from ags.threat.threats import (
    MITIGATIONS,
    Threat,
    threat_register,
    to_markdown,
    trifecta,
)

__all__ = [
    "MITIGATIONS",
    "Element",
    "Flow",
    "SystemModel",
    "Threat",
    "from_specs",
    "threat_register",
    "to_markdown",
    "trifecta",
]
