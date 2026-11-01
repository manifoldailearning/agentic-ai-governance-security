"""Shared types: who acts, what tools do, and what was decided.

Security decisions need three facts every time: the principal
(who, on whose behalf), the tool's declared effect (does it
read, write, or reach outside), and the data that is already
in the agent's context. These types carry exactly that, so
every guard in this repository reasons over the same facts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

EFFECTS = ("read", "write", "external", "exec")
RISKS = ("low", "medium", "high")
VERDICTS = ("allow", "deny", "approve")  # approve = ask a human


@dataclass(frozen=True)
class Principal:
    id: str
    kind: str = "user"  # user | agent | service
    tenant: str = "default"
    roles: frozenset[str] = frozenset()
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    effect: str  # read | write | external | exec
    risk: str = "low"
    labels: frozenset[str] = frozenset()  # labels on output
    description: str = ""

    def __post_init__(self) -> None:
        if self.effect not in EFFECTS:
            raise ValueError(f"unknown effect {self.effect!r}")
        if self.risk not in RISKS:
            raise ValueError(f"unknown risk {self.risk!r}")


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]

    def key(self) -> str:
        return self.name + json.dumps(self.args, sort_keys=True)


@dataclass
class Message:
    role: str  # user | model | tool
    content: str
    labels: frozenset[str] = frozenset()
    source: str = ""  # tool name or "user"


@dataclass(frozen=True)
class Decision:
    verdict: str  # allow | deny | approve
    guard: str
    reason: str = ""
    text: str | None = None  # rewritten output, if any

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


ALLOW = Decision("allow", "-")
