"""Risk register: inherent risk, controls, residual risk, owners.

Risk committees and auditors ask the same questions: what
can go wrong, how likely, how bad, what reduces it, who owns
it and when it was last reviewed. ``RiskRegister`` keeps the
answers as data, computes residual scores from control
effectiveness and reports risks that lack controls, sit
above appetite or are overdue for review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from ags.risk.controls import CONTROLS

MAX_EFFECTIVENESS = 0.9  # no control is claimed to be perfect
BANDS = (
    (15, "critical"),
    (10, "high"),
    (5, "medium"),
    (0, "low"),
)


def band(score: float) -> str:
    return next(name for floor, name in BANDS if score >= floor)


@dataclass
class Risk:
    id: str
    title: str
    likelihood: int  # 1 rare .. 5 almost certain
    impact: int  # 1 minor .. 5 severe
    owner: str
    review_by: date
    controls: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for value in (self.likelihood, self.impact):
            if not 1 <= value <= 5:
                raise ValueError(f"{self.id}: scale is 1..5")

    @property
    def inherent(self) -> int:
        return self.likelihood * self.impact

    @property
    def residual(self) -> float:
        """Each control removes its share of what is left.

        Assumes controls fail independently: optimistic when
        two controls share a failure mode.
        """
        left = 1.0
        for effectiveness in self.controls.values():
            left *= 1 - effectiveness
        return round(self.inherent * left, 1)


class RiskRegister:
    def __init__(self, appetite: float = 6.0) -> None:
        self.appetite = appetite  # highest acceptable residual
        self.risks: dict[str, Risk] = {}

    def add(self, risk: Risk) -> Risk:
        if risk.id in self.risks:
            raise ValueError(f"duplicate risk id {risk.id}")
        self.risks[risk.id] = risk
        return risk

    def mitigate(
        self, risk_id: str, control: str, effectiveness: float
    ) -> Risk:
        if control not in CONTROLS:
            raise ValueError(f"unknown control {control!r}")
        if not 0 < effectiveness <= MAX_EFFECTIVENESS:
            top = MAX_EFFECTIVENESS
            raise ValueError(
                f"effectiveness must be in (0, {top}]"
            )
        risk = self.risks[risk_id]
        risk.controls[control] = effectiveness
        return risk

    def implemented(self) -> set[str]:
        return {
            c for r in self.risks.values() for c in r.controls
        }

    def coverage(self, today: date) -> dict[str, list[str]]:
        """What a reviewer must act on, by category."""
        rs = sorted(self.risks.values(), key=lambda r: r.id)
        return {
            "no controls": [r.id for r in rs if not r.controls],
            "above appetite": [
                r.id for r in rs if r.residual > self.appetite
            ],
            "review overdue": [
                r.id for r in rs if r.review_by < today
            ],
        }

    def to_markdown(self) -> str:
        rows = [
            "| ID | Risk | L x I | Inherent | Residual | Owner "
            "| Review |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in sorted(self.risks.values(), key=lambda r: r.id):
            rows.append(
                f"| {r.id} | {r.title} | {r.likelihood}x"
                f"{r.impact} | {r.inherent} ({band(r.inherent)})"
                f" | {r.residual} ({band(r.residual)}) "
                f"| {r.owner} | {r.review_by.isoformat()} |"
            )
        return "\n".join(rows)
