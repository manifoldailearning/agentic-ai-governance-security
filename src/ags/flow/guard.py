"""FlowGuard: judge each call by the data already in context.

The guard looks up the context's labels and the tool's
effect in the policy table. Every non-allow reason carries
provenance: which earlier calls brought each label in, so a
reviewer sees "pii<-export_customers#call-2", not just "no".
A call that matches a plan locked before untrusted input is
endorsed past ``approve`` rows; ``deny`` rows still apply.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ags.core import (
    ALLOW,
    Context,
    Decision,
    Tool,
    ToolCall,
    ToolSpec,
)
from ags.flow.labels import DEFAULT_POLICY, FlowRule, decide
from ags.flow.plan import PlanLock


def provenance(
    ctx: Context, labels: Iterable[str], sources: dict
) -> str:
    """Which executed calls introduced each label."""
    parts = []
    for label in sorted(labels):
        origin = [
            f"{c.name}#{c.id}"
            for c in ctx.calls
            if label in sources.get(c.name, ())
        ]
        parts.append(f"{label}<-{','.join(origin) or '?'}")
    return "; ".join(parts)


@dataclass
class FlowGuard:
    sources: dict[str, frozenset[str]]  # tool -> result labels
    policy: tuple[FlowRule, ...] = DEFAULT_POLICY
    plan: PlanLock | None = None
    name: str = "flow"

    @classmethod
    def for_tools(cls, tools: Iterable[Tool], **kw) -> FlowGuard:
        return cls(
            {t.spec.name: t.spec.labels for t in tools}, **kw
        )

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        hit = decide(self.policy, ctx.labels, spec.effect)
        if hit is None:
            return ALLOW
        origin = provenance(ctx, hit.labels, self.sources)
        if hit.verdict == "approve" and self.plan:
            if self.plan.planned(ctx, call):
                why = f"endorsed by locked plan ({origin})"
                return Decision("allow", self.name, why)
        why = f"{hit.why} -> {spec.effect} call [{origin}]"
        return Decision(hit.verdict, self.name, why)
