"""Risk tiers and approval requirements for agent actions.

Human approval works only when it is rare and meaningful.
``ApprovalPolicy`` scores each proposed call from the tool's
declared risk and effect, the amount at stake and what the
run has already seen, then requires no approval, a single
approver, or two (four-eyes) according to the tier. It also
writes the summary the approver reads before deciding.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ags.core import (
    ALLOW,
    Context,
    Decision,
    ToolCall,
    ToolSpec,
)

RISK_POINTS = {"low": 0, "medium": 1, "high": 2}
EFFECT_POINTS = {"read": 0, "write": 1, "external": 1, "exec": 2}
TIERS = ("low", "medium", "high")
NEEDS = {"low": "none", "medium": "single", "high": "four-eyes"}
QUORUM = {"none": 0, "single": 1, "four-eyes": 2}


@dataclass(frozen=True)
class Risk:
    tier: str
    score: int
    factors: tuple[str, ...]

    @property
    def needs(self) -> str:
        return NEEDS[self.tier]

    @property
    def quorum(self) -> int:
        return QUORUM[self.needs]


def amount_of(call: ToolCall) -> float:
    """The money at stake; unparseable amounts count as huge."""
    try:
        return abs(float(call.args.get("amount", 0)))
    except (TypeError, ValueError):
        return math.inf


@dataclass
class ApprovalPolicy:
    notable: float = 100.0  # amount that adds a point
    large: float = 500.0  # amount that adds two
    name: str = "oversight"

    def assess(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Risk:
        points = [
            (RISK_POINTS[spec.risk], f"tool:{spec.risk}"),
            (EFFECT_POINTS[spec.effect], f"effect:{spec.effect}"),
        ]
        amount = amount_of(call)
        if amount >= self.large:
            points.append((2, f"amount>={self.large:g}"))
        elif amount >= self.notable:
            points.append((1, f"amount>={self.notable:g}"))
        if spec.effect != "read" and "untrusted" in ctx.labels:
            points.append((2, "untrusted"))
        if spec.effect == "external" and "pii" in ctx.labels:
            points.append((1, "pii"))
        score = sum(p for p, _ in points)
        tier = "low" if score <= 1 else "medium"
        if score >= 5:
            tier = "high"
        return Risk(tier, score, tuple(f for _, f in points))

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        risk = self.assess(ctx, spec, call)
        if risk.needs == "none":
            return ALLOW
        factors = ", ".join(risk.factors)
        why = f"{risk.needs}: {risk.tier} ({factors})"
        return Decision("approve", self.name, why)


def _short(value: object, width: int = 28) -> str:
    text = str(value)
    if len(text) > width:
        text = text[: width - 3] + "..."
    return text


def summarize(
    ctx: Context, spec: ToolSpec, call: ToolCall, risk: Risk
) -> list[str]:
    """What the approver sees: action, why, data, influence."""
    lines = [spec.name]
    lines += [f"  {k}: {_short(v)}" for k, v in call.args.items()]
    lines.append(f"risk: {risk.tier} ({', '.join(risk.factors)})")
    lines.append(f"seen: {', '.join(sorted(ctx.labels)) or '-'}")
    history = " > ".join(c.name for c in ctx.calls) or "-"
    lines.append(f"after: {history}")
    if "untrusted" in ctx.labels:
        lines.append("WARNING: untrusted content may steer this")
    return lines
