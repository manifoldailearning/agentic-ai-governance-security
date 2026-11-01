"""A policy decision point: explicit rules, default deny.

Every tool call asks the classic question: may this
principal take this action on this resource, now? Rules
match roles, tools, effects and conditions. No match means
deny; among matches, deny beats approve beats allow. A rule
whose condition cannot be evaluated denies: fail closed.
"""

from __future__ import annotations

import math
import operator
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ags.core.runtime import Context
from ags.core.types import Decision, ToolCall, ToolSpec

Condition = Callable[[Context, ToolCall], bool]
PRECEDENCE = ("deny", "approve", "allow")
OPS: dict[str, Callable[[Any, Any], bool]] = {
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "==": operator.eq,
    "!=": operator.ne,
    "in": lambda value, allowed: value in allowed,
}


def resolve(ctx: Context, call: ToolCall, path: str) -> Any:
    """``args.amount``, ``principal.tenant``, ``labels``..."""
    root, *parts = path.split(".")
    roots = {
        "args": call.args,
        "principal": ctx.principal,
        "labels": ctx.labels,
        "agent": ctx.agent,
    }
    value: Any = roots[root]
    for part in parts:  # a missing key raises: fail closed
        is_map = isinstance(value, dict)
        value = value[part] if is_map else getattr(value, part)
    return value


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(
        value, bool
    )


def _number(value: Any) -> float:
    """Reject bools, strings, NaN and infinity as numbers."""
    if not _is_number(value) or not math.isfinite(value):
        raise TypeError(f"not a finite number: {value!r}")
    return value


def cmp(path: str, op: str, expected: Any) -> Condition:
    """Declarative check: ``cmp("args.amount", "<=", 200)``."""
    fn, numeric = OPS[op], _is_number(expected)

    def condition(ctx: Context, call: ToolCall) -> bool:
        value = resolve(ctx, call, path)
        return fn(_number(value) if numeric else value, expected)

    condition.__name__ = f"{path} {op} {expected!r}"
    return condition


@dataclass(frozen=True)
class Rule:
    id: str
    effect: str  # allow | approve | deny
    roles: frozenset[str] = frozenset()  # any of; empty = anyone
    tools: frozenset[str] = frozenset()  # empty = any tool
    effects: frozenset[str] = frozenset()  # read, write...
    when: tuple[Condition, ...] = ()  # all must hold
    reason: str = ""

    def __post_init__(self) -> None:
        if self.effect not in PRECEDENCE:
            raise ValueError(f"unknown effect {self.effect!r}")
        for name in ("roles", "tools", "effects"):
            value = frozenset(getattr(self, name))
            object.__setattr__(self, name, value)
        object.__setattr__(self, "when", tuple(self.when))

    def matches(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> bool:
        if self.roles and not self.roles & ctx.principal.roles:
            return False
        if self.tools and spec.name not in self.tools:
            return False
        if self.effects and spec.effect not in self.effects:
            return False
        return all(cond(ctx, call) for cond in self.when)


@dataclass(frozen=True)
class Explanation:
    verdict: str
    rule: Rule | None  # the deciding rule; None = default deny
    matched: tuple[str, ...] = ()  # every matching rule id
    error: str = ""

    def __str__(self) -> str:
        if self.rule is None:
            return "no rule matched (default deny)"
        if self.error:
            return (
                f"{self.rule.id}: condition failed: {self.error}"
            )
        return (
            f"{self.rule.id}: {self.rule.reason or self.verdict}"
        )


class PolicyDecisionPoint:
    def __init__(self, rules: list[Rule]) -> None:
        ids = [r.id for r in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        self.rules = list(rules)

    def explain(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Explanation:
        matched = []
        for rule in self.rules:
            try:
                if rule.matches(ctx, spec, call):
                    matched.append(rule)
            except Exception as exc:  # fail closed, say why
                why = f"{type(exc).__name__}: {exc}"
                return Explanation("deny", rule, (rule.id,), why)
        ids = tuple(r.id for r in matched)
        for verdict in PRECEDENCE:
            for rule in matched:
                if rule.effect == verdict:
                    return Explanation(verdict, rule, ids)
        return Explanation("deny", None)

    def decide(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        e = self.explain(ctx, spec, call)
        return Decision(e.verdict, "authz", str(e))
