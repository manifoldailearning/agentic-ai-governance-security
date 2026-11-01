"""Test a policy before it ships, and measure what it changes.

Two checks belong in CI for every policy change: unit cases
with expected verdicts, including known bypass attempts, and
an impact report that replays recorded tool calls against
the candidate and lists every decision that would change,
so reviewers approve consequences, not just a diff.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ags.core import (
    Context,
    Event,
    Principal,
    ToolCall,
    ToolSpec,
)
from ags.policy.document import Policy, Ruling


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected: str
    got: Ruling

    @property
    def passed(self) -> bool:
        return self.got.verdict == self.expected


def run_cases(
    policy: Policy,
    cases: Iterable[Mapping[str, Any]],
    specs: Mapping[str, ToolSpec],
) -> list[CaseResult]:
    """Each case: name, tool, args, roles, labels, expect."""
    results = []
    for case in cases:
        who = Principal(
            "tester",
            tenant=case.get("tenant", "acme"),
            roles=frozenset(case.get("roles", ())),
        )
        labels = set(case.get("labels", ()))
        ctx = Context("case", "policy-test", who, labels)
        call = ToolCall(
            "case", case["tool"], case.get("args", {})
        )
        got = policy.evaluate(ctx, specs[case["tool"]], call)
        results.append(
            CaseResult(case["name"], case["expect"], got)
        )
    return results


@dataclass(frozen=True)
class Change:
    event: Event
    before: Ruling
    after: Ruling


def impact(
    events: Iterable[Event],
    current: Policy,
    candidate: Policy,
    specs: Mapping[str, ToolSpec],
    directory: Mapping[str, Principal] | None = None,
) -> list[Change]:
    """Recorded tool calls whose verdict the candidate changes.

    Events do not carry roles, so principals are looked up in
    ``directory``; unknown ones replay with no roles at all.
    """
    directory = directory or {}
    changes = []
    for e in events:
        if e.kind != "tool_call" or e.tool not in specs:
            continue
        who = directory.get(e.principal) or Principal(
            e.principal, tenant=e.tenant
        )
        ctx = Context(
            e.run_id, e.actor, who, set(e.labels), now=e.ts
        )
        call = ToolCall(
            "replay", e.tool, e.detail.get("args", {})
        )
        before = current.evaluate(ctx, specs[e.tool], call)
        after = candidate.evaluate(ctx, specs[e.tool], call)
        if before.verdict != after.verdict:
            changes.append(Change(e, before, after))
    return changes
