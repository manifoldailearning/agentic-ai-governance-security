"""Compile a policy document into a guard with a decision log.

The runtime only records a verdict; an auditor also needs to
know which rule of which policy version produced it. The
compiled guard keeps a decision log in which every entry
names the policy, its version and the digest of the exact
document, and can hand each entry to an external sink.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from ags.core import Context, Decision, ToolCall, ToolSpec
from ags.policy.document import Policy


@dataclass(frozen=True)
class DecisionRecord:
    ts: float
    run_id: str
    principal: str
    tenant: str
    tool: str
    args: dict[str, Any]
    verdict: str
    rule: str
    policy: str
    version: str
    digest: str
    kind: str = field(default="policy_decision")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


Sink = Callable[[DecisionRecord], Any]


class PolicyGuard:
    """A ``Guard`` that evaluates one loaded policy."""

    name = "policy"

    def __init__(
        self, policy: Policy, sink: Sink | None = None
    ) -> None:
        self.policy = policy
        self.sink = sink
        self.decisions: list[DecisionRecord] = []

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        ruling = self.policy.evaluate(ctx, spec, call)
        p = self.policy
        record = DecisionRecord(
            ctx.now,
            ctx.run_id,
            ctx.principal.id,
            ctx.principal.tenant,
            spec.name,
            dict(call.args),
            ruling.verdict,
            ruling.rule,
            p.name,
            p.version,
            p.digest,
        )
        self.decisions.append(record)
        if self.sink is not None:
            self.sink(record)
        return ruling.decision()


def compile_policy(
    doc: Mapping[str, Any], sink: Sink | None = None
) -> PolicyGuard:
    """Validate ``doc`` and return a guard ready for Runtime."""
    return PolicyGuard(Policy.load(doc), sink)
