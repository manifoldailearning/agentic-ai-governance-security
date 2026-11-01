"""Use-case risk tiering: how much governance does an agent need?

Not every agent needs four-eyes approval and a red team. A
short questionnaire scores autonomy, data sensitivity,
external actions, user impact and scale, maps the answers to
a tier and lists the controls that tier requires. Tier names
echo risk-based regulation; placing a real system in a legal
category is a judgment for counsel, not for this code.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ags.core.types import ToolSpec

QUESTIONS: dict[str, dict[str, int]] = {  # answer -> score
    "autonomy": {
        "suggests": 0,
        "approved": 1,
        "supervised": 2,
        "acts_alone": 3,
    },
    "data": {
        "public": 0,
        "internal": 1,
        "personal": 2,
        "sensitive": 3,
    },
    "actions": {
        "none": 0,
        "internal_write": 1,
        "external": 2,
        "irreversible": 3,
    },
    "impact": {
        "negligible": 0,
        "service": 1,
        "financial": 2,
        "rights_or_safety": 3,
    },
    "scale": {
        "team": 0,
        "company": 1,
        "customers": 2,
        "public": 3,
    },
}

# Example red lines an organization may refuse outright.
RED_LINES = frozenset(
    {"covert_manipulation", "social_scoring", "exploit_minors"}
)

TIER_CONTROLS = {  # cumulative: each tier adds to the one below
    "minimal": ("inventory", "usage-policy"),
    "limited": ("transparency", "event-logging", "output-dlp"),
    "high": (
        "least-privilege",
        "injection-defense",
        "flow-control",
        "human-approval",
        "red-team",
        "audit-trail",
        "incident-response",
    ),
}
TIERS = ("minimal", "limited", "high", "unacceptable")


@dataclass(frozen=True)
class Assessment:
    use_case: str
    tier: str
    score: int
    drivers: tuple[str, ...]  # answers that pushed the tier up
    controls: tuple[str, ...]  # required before go-live

    def gaps(self, implemented: Iterable[str]) -> list[str]:
        done = set(implemented)
        return [c for c in self.controls if c not in done]


def score_answers(answers: Mapping[str, str]) -> dict[str, int]:
    """Validate every answer; unknown or missing ones raise."""
    extra = answers.keys() - QUESTIONS.keys()
    missing = QUESTIONS.keys() - answers.keys()
    if extra or missing:
        raise ValueError(
            f"unknown {sorted(extra)}, missing {sorted(missing)}"
        )
    scores = {}
    for question, options in QUESTIONS.items():
        answer = answers[question]
        if answer not in options:
            raise ValueError(f"{question}: bad answer {answer!r}")
        scores[question] = options[answer]
    return scores


def tier_for(scores: Mapping[str, int]) -> str:
    """Maximum impact alone is enough; it is never averaged."""
    total = sum(scores.values())
    unattended = min(scores["autonomy"], scores["actions"]) == 3
    if scores["impact"] == 3 or unattended or total >= 9:
        return "high"
    if total >= 3 or scores["actions"] >= 2:
        return "limited"
    return "minimal"


def required_controls(tier: str) -> tuple[str, ...]:
    if tier == "unacceptable":
        return ()  # no control set makes it deployable
    upto = TIERS.index(tier) + 1
    return tuple(
        c for t in TIERS[:upto] for c in TIER_CONTROLS.get(t, ())
    )


def assess(
    use_case: str,
    answers: Mapping[str, str],
    practices: Iterable[str] = (),
) -> Assessment:
    scores = score_answers(answers)
    total = sum(scores.values())
    declared = {p.strip().lower() for p in practices}
    crossed = sorted(declared & RED_LINES)
    if crossed:
        reasons = tuple(f"red line: {p}" for p in crossed)
        return Assessment(
            use_case, "unacceptable", total, reasons, ()
        )
    tier = tier_for(scores)
    drivers = tuple(
        f"{q}={answers[q]}" for q, s in scores.items() if s >= 2
    )
    return Assessment(
        use_case, tier, total, drivers, required_controls(tier)
    )


def infer_answers(specs: Iterable[ToolSpec]) -> dict[str, str]:
    """Answer the data and actions questions from the tools.

    Owners underestimate what their agent can touch; the tool
    inventory does not.
    """
    specs = list(specs)
    labels = set().union(*(s.labels for s in specs))
    effects = {(s.effect, s.risk) for s in specs}
    if "secret" in labels:
        data = "sensitive"
    elif "pii" in labels:
        data = "personal"
    else:
        data = "internal" if "internal" in labels else "public"
    if {("write", "high"), ("exec", "high")} & effects:
        actions = "irreversible"
    elif any(e == "external" for e, _ in effects):
        actions = "external"
    elif any(e in ("write", "exec") for e, _ in effects):
        actions = "internal_write"
    else:
        actions = "none"
    return {"data": data, "actions": actions}
