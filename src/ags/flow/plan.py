"""Plan-then-execute: lock the plan before reading data.

The tools and arguments a task needs are decided from the
user's request alone, before any untrusted content is read.
``PlanLock`` then denies every call outside that plan, so
an injected instruction can at most fill in a free argument
(``ANY``); it cannot add a tool, a recipient or a URL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ags.core import ALLOW, Context, Decision, ToolCall, ToolSpec

ANY = re.compile(r".*", re.S)  # a free string argument


def fits(want: Any, got: Any) -> bool:
    if isinstance(want, re.Pattern):
        return isinstance(got, str) and bool(want.fullmatch(got))
    return type(got) is type(want) and got == want


@dataclass(frozen=True)
class Step:
    tool: str
    args: dict[str, Any]  # exact value or regex to fullmatch
    uses: int = 1

    def matches(self, call: ToolCall) -> bool:
        return (
            call.name == self.tool
            and call.args.keys() <= self.args.keys()
            and all(
                fits(self.args[k], v)
                for k, v in call.args.items()
            )
        )


def step(tool: str, uses: int = 1, **args: Any) -> Step:
    return Step(tool, args, uses)


@dataclass(frozen=True)
class PlanLock:
    steps: tuple[Step, ...]
    name: str = "plan_lock"

    def planned(
        self, ctx: Context, call: ToolCall
    ) -> Step | None:
        """The first unused plan step this call matches."""
        for s in self.steps:
            used = sum(s.matches(c) for c in ctx.calls)
            if s.matches(call) and used < s.uses:
                return s
        return None

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        if self.planned(ctx, call):
            return ALLOW
        why = f"{call.name} is outside the plan locked at start"
        return Decision("deny", self.name, why)
