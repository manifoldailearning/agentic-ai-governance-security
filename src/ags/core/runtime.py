"""The agent runtime: every tool call passes through guards.

The model proposes; the runtime decides. Each proposed call
is checked by a chain of guards before it runs. The first
``deny`` wins; an ``approve`` verdict asks a human approver
and is denied when nobody approves. Tool results carry data
labels (``pii``, ``untrusted``...) into the run's context,
so later guards know what the agent has already seen.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ags.core.clock import Clock, FakeClock
from ags.core.events import Event, EventLog
from ags.core.model import Final
from ags.core.types import (
    ALLOW,
    Decision,
    Message,
    Principal,
    ToolCall,
    ToolSpec,
)


@dataclass
class Context:
    run_id: str
    agent: str
    principal: Principal
    labels: set[str] = field(default_factory=set)
    calls: list[ToolCall] = field(default_factory=list)
    now: float = 0.0


class Guard(Protocol):
    name: str

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision: ...


class OutputGuard(Protocol):
    name: str

    def check_output(
        self, ctx: Context, text: str
    ) -> Decision: ...


Approver = Callable[[Context, ToolSpec, ToolCall, Decision], bool]


@dataclass
class Tool:
    spec: ToolSpec
    fn: Callable[..., Any]


@dataclass
class RunResult:
    run_id: str
    status: str  # completed | blocked | step_limit
    output: str
    calls: list[ToolCall]
    denied: list[tuple[ToolCall, Decision]]
    labels: set[str]


class Runtime:
    def __init__(
        self,
        tools: Iterable[Tool],
        guards: Iterable[Guard] = (),
        output_guards: Iterable[OutputGuard] = (),
        approver: Approver | None = None,
        log: EventLog | None = None,
        clock: Clock | None = None,
        agent: str = "support-agent",
        max_steps: int = 8,
    ) -> None:
        self.tools = {t.spec.name: t for t in tools}
        self.guards = list(guards)
        self.output_guards = list(output_guards)
        self.approver = approver
        self.log = log if log is not None else EventLog()
        self.clock = clock or FakeClock()
        self.agent = agent
        self.max_steps = max_steps
        self._runs = 0

    def authorize(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        """First deny wins; ``approve`` needs a human yes."""
        for guard in self.guards:
            d = guard.check(ctx, spec, call)
            if d.verdict == "deny":
                return d
            if d.verdict == "approve":
                if self.approver is None:
                    why = "no approver: " + d.reason
                    return Decision("deny", d.guard, why)
                if not self.approver(ctx, spec, call, d):
                    why = "approval refused: " + d.reason
                    return Decision("deny", d.guard, why)
        return ALLOW

    def _event(self, ctx: Context, kind: str, **kw: Any) -> None:
        self.log.add(
            Event(
                self.clock.now(),
                ctx.run_id,
                self.agent,
                ctx.principal.id,
                ctx.principal.tenant,
                kind,
                labels=sorted(ctx.labels),
                **kw,
            )
        )

    def run(
        self, principal: Principal, task: str, model: Any
    ) -> RunResult:
        self._runs += 1
        ctx = Context(
            f"run-{self._runs:04d}", self.agent, principal
        )
        msgs = [
            Message("user", task, frozenset({"user"}), "user")
        ]
        denied: list[tuple[ToolCall, Decision]] = []
        self._event(ctx, "task", detail={"task": task})
        for _ in range(self.max_steps):
            ctx.now = self.clock.now()
            step = model.next(msgs)
            if isinstance(step, Final):
                out = self._output(ctx, step.text)
                status = "blocked" if out is None else "completed"
                return RunResult(
                    ctx.run_id,
                    status,
                    out or "",
                    ctx.calls,
                    denied,
                    ctx.labels,
                )
            msgs.append(self._step(ctx, step, denied))
            self.clock.sleep(1.0)
        return RunResult(
            ctx.run_id,
            "step_limit",
            "",
            ctx.calls,
            denied,
            ctx.labels,
        )

    def _step(
        self,
        ctx: Context,
        call: ToolCall,
        denied: list[tuple[ToolCall, Decision]],
    ) -> Message:
        tool = self.tools.get(call.name)
        if tool is None:
            d = Decision("deny", "runtime", "unknown tool")
        else:
            d = self.authorize(ctx, tool.spec, call)
        self._event(
            ctx,
            "tool_call",
            tool=call.name,
            verdict=d.verdict,
            guard=d.guard,
            reason=d.reason,
            detail={"args": call.args},
        )
        if not d.allowed or tool is None:
            denied.append((call, d))
            text = f"DENIED by {d.guard}: {d.reason}"
            return Message("tool", text, source=call.name)
        try:
            result = tool.fn(**call.args)
        except Exception as exc:  # tool failures are data
            self._event(
                ctx,
                "error",
                tool=call.name,
                reason=f"{type(exc).__name__}: {exc}",
            )
            return Message(
                "tool", f"ERROR: {exc}", source=call.name
            )
        ctx.calls.append(call)
        ctx.labels |= tool.spec.labels
        text = (
            result
            if isinstance(result, str)
            else json.dumps(result, sort_keys=True)
        )
        return Message("tool", text, tool.spec.labels, call.name)

    def _output(self, ctx: Context, text: str) -> str | None:
        """Output guards; ``None`` means the answer is blocked."""
        for guard in self.output_guards:
            d = guard.check_output(ctx, text)
            if d.verdict != "allow":
                self._event(
                    ctx,
                    "output",
                    verdict=d.verdict,
                    guard=d.guard,
                    reason=d.reason,
                )
            if d.verdict == "deny":
                return None
            if d.text is not None:
                text = d.text
        self._event(ctx, "output", verdict="allow")
        return text
