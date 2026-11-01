"""Containment: switches that stop a compromised agent now.

When detection fires, responders need controls that bite on
the very next tool call: freeze an agent, disable a tool,
revoke a delegation token, pull poisoned memory out of reach.
Each switch is a guard wired in ahead of the others, idle
until thrown, and every action is recorded for the incident.
"""

from __future__ import annotations

from collections.abc import Iterable, MutableMapping
from dataclasses import dataclass
from typing import Any

from ags.core import (
    ALLOW,
    Clock,
    Context,
    Decision,
    Guard,
    ToolCall,
    ToolSpec,
)


@dataclass(frozen=True)
class Action:
    ts: float
    action: str  # freeze-agent | disable-tool | revoke-token...
    target: str
    reason: str


class KillSwitch:
    """Freeze agents: every call they propose is denied."""

    name = "kill-switch"

    def __init__(self) -> None:
        self.frozen: dict[str, str] = {}  # agent or "*" -> why

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        why = self.frozen.get(ctx.agent) or self.frozen.get("*")
        if why is None:
            return ALLOW
        return Decision("deny", self.name, f"agent frozen: {why}")


class ToolDisable:
    """Take one tool out of service for every agent."""

    name = "tool-disable"

    def __init__(self) -> None:
        self.disabled: dict[str, str] = {}

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        why = self.disabled.get(spec.name)
        if why is None:
            return ALLOW
        return Decision(
            "deny", self.name, f"tool disabled: {why}"
        )


class TokenRevocation:
    """Deny calls made under a revoked delegation token."""

    name = "token-revocation"

    def __init__(self, claim: str = "jti") -> None:
        self.claim = claim  # principal attribute holding the id
        self.revoked: set[str] = set()

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        token = ctx.principal.attrs.get(self.claim)
        if token is None:  # fail closed: nothing to check
            why = f"no {self.claim} on the principal"
            return Decision("deny", self.name, why)
        if token in self.revoked:
            why = f"token {token} revoked"
            return Decision("deny", self.name, why)
        return ALLOW


class Containment:
    """The responder's switchboard, with an action record."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.kill_switch = KillSwitch()
        self.tools = ToolDisable()
        self.tokens = TokenRevocation()
        self.quarantined: dict[str, Any] = {}
        self.actions: list[Action] = []

    def guards(self) -> list[Guard]:
        """Put these first in the runtime's guard chain."""
        return [self.kill_switch, self.tools, self.tokens]

    def _record(self, action: str, target: str, why: str) -> None:
        now = self.clock.now()
        self.actions.append(Action(now, action, target, why))

    def freeze(self, agent: str, reason: str) -> None:
        self.kill_switch.frozen[agent] = reason
        self._record("freeze-agent", agent, reason)

    def thaw(self, agent: str, reason: str) -> None:
        self.kill_switch.frozen.pop(agent, None)
        self._record("thaw-agent", agent, reason)

    def disable(self, tool: str, reason: str) -> None:
        self.tools.disabled[tool] = reason
        self._record("disable-tool", tool, reason)

    def revoke(self, token_id: str, reason: str) -> None:
        self.tokens.revoked.add(token_id)
        self._record("revoke-token", token_id, reason)

    def quarantine(
        self,
        store: MutableMapping[str, Any],
        ids: Iterable[str],
        reason: str,
    ) -> list[str]:
        """Move entries out of a memory store; keep them."""
        moved = [i for i in ids if i in store]
        for i in moved:
            self.quarantined[i] = store.pop(i)
            self._record("quarantine-memory", i, reason)
        return moved
