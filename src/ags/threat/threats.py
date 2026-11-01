"""Automated threat enumeration and a scored threat register.

STRIDE-per-element gives the classic baseline. Agent rules
add what STRIDE misses: prompt injection through untrusted
tool results, tool misuse, excessive agency, exfiltration,
cross-tenant reach and the lethal trifecta. Scores are
likelihood x impact on 1-5 scales: explainable, and meant
to be recalibrated by your team, not trusted blindly.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace

from ags.threat.model import (
    ACTIONS,
    SENSITIVE,
    Element,
    SystemModel,
)

STRIDE = {
    "S": ("Spoofing", "{} is impersonated"),
    "T": ("Tampering", "{} or its data is altered"),
    "R": ("Repudiation", "actions via {} cannot be attributed"),
    "I": ("Information disclosure", "data in {} reaches others"),
    "D": ("Denial of service", "{} is exhausted or unavailable"),
    "E": ("Elevation of privilege", "{} acts beyond its rights"),
}
LETTERS = {  # the classic STRIDE-per-element table
    "actor": "SR",
    "external": "SR",
    "process": "STRIDE",
    "store": "TID",
}
MITIGATIONS = {  # control -> chapter where it is built
    "Spoofing": "ch03 identity tokens; ch19 pinned components",
    "Tampering": "ch08 argument schemas; ch17 audit chain",
    "Repudiation": "ch17 tamper-evident audit log",
    "Information disclosure": "ch09 DLP; ch11 minimization",
    "Denial of service": "runtime step limits; ch08 sandbox",
    "Elevation of privilege": "ch04 policy decision point",
    "Prompt injection": "ch06 screening; ch07 flow control",
    "Tool misuse": "ch08 argument schemas; ch12 approvals",
    "Excessive agency": "ch04 least privilege; ch12 oversight",
    "Data exfiltration": "ch07 flow control; ch08/ch09 egress",
    "Lethal trifecta": "ch07 split the legs: FlowGuard, PlanLock",
    "Cross-tenant access": "ch04 TenantGuard; ch10 isolation",
}
RISK = {"low": 2, "medium": 3, "high": 4}
SEVERITY = ((20, "critical"), (12, "high"), (6, "medium"))


@dataclass(frozen=True)
class Threat:
    category: str
    target: str
    text: str
    likelihood: int  # 1 rare .. 5 expected
    impact: int  # 1 negligible .. 5 severe
    id: str = ""

    @property
    def score(self) -> int:
        return self.likelihood * self.impact

    @property
    def severity(self) -> str:
        for floor, name in SEVERITY:
            if self.score >= floor:
                return name
        return "low"

    @property
    def mitigation(self) -> str:
        return MITIGATIONS[self.category]


def impact(m: SystemModel, e: Element) -> int:
    """Agent compromise is as bad as its worst tool."""
    if e.kind == "process":
        return max((impact(m, t) for t in m.tools()), default=2)
    base = RISK[e.risk] if e.kind == "tool" else 3
    bulky = bool(e.labels & {"bulk", "secret"})
    return min(5, base + (bulky or e.effect == "exec"))


def likelihood(m: SystemModel, e: Element) -> int:
    """Baseline for generic STRIDE rows. Agent rules that name
    a concrete attack path score higher (see ``_exposure``)."""
    exposed = e.zone == "internet" or (
        e.kind == "process" and m.sources({"untrusted"})
    )
    return 3 if exposed else 2


def letters(e: Element) -> str:
    if e.kind == "tool":  # reads behave like stores
        return "TRDE" if e.effect in ACTIONS else "TID"
    return LETTERS[e.kind]


def stride(m: SystemModel) -> Iterator[Threat]:
    """STRIDE per element, plus disclosure on sensitive flows."""
    for e in m.elements.values():
        lk, im = likelihood(m, e), impact(m, e)
        for letter in letters(e):
            category, text = STRIDE[letter]
            yield Threat(
                category, e.name, text.format(e.name), lk, im
            )
    for f in m.flows:
        data = f.labels & SENSITIVE
        if data and m.crosses(f):
            im = min(5, 3 + len(data & {"pii", "bulk", "secret"}))
            what = f"{f.what} carries {', '.join(sorted(data))}"
            where = f"{f.src}->{f.dst}"
            yield Threat(
                "Information disclosure", where, what, 3, im
            )


def trifecta(m: SystemModel) -> dict[str, list[str]] | None:
    """Untrusted input, sensitive data, external channel."""
    legs = {
        "untrusted": m.sources({"untrusted"}),
        "sensitive": m.sources(SENSITIVE),
        "external": m.sinks(),
    }
    names = {
        k: sorted(e.name for e in v) for k, v in legs.items()
    }
    return names if all(names.values()) else None


def _exposure(m: SystemModel) -> int:
    return 4 if m.sources({"untrusted"}) else 2


def prompt_injection(m: SystemModel) -> Iterator[Threat]:
    im = impact(m, m.agent())
    for s in m.sources({"untrusted"}):
        why = f"text returned by {s.name} steers the agent"
        yield Threat("Prompt injection", s.name, why, 5, im)


def tool_misuse(m: SystemModel) -> Iterator[Threat]:
    for t in m.actions():
        if t.risk == "high":
            why = f"{t.name} runs with attacker-chosen args"
            lk, im = _exposure(m), impact(m, t)
            yield Threat("Tool misuse", t.name, why, lk, im)


def excessive_agency(m: SystemModel) -> Iterator[Threat]:
    if effects := sorted({t.effect for t in m.actions()}):
        agent = m.agent()
        why = f"can {', '.join(effects)} without a human"
        im = impact(m, agent)
        yield Threat("Excessive agency", agent.name, why, 3, im)


def exfiltration(m: SystemModel) -> Iterator[Threat]:
    data = set().union(*(t.labels & SENSITIVE for t in m.tools()))
    kinds, lk = ", ".join(sorted(data)), _exposure(m)
    im = 5 if data & {"bulk", "secret"} else 4
    for sink in m.sinks() if data else []:
        why = f"{kinds} sent out via {sink.name}"
        yield Threat("Data exfiltration", sink.name, why, lk, im)


def lethal_trifecta(m: SystemModel) -> Iterator[Threat]:
    if trifecta(m):
        why = "untrusted input + sensitive data + egress"
        yield Threat("Lethal trifecta", m.agent().name, why, 5, 5)


def cross_tenant(m: SystemModel) -> Iterator[Threat]:
    for e in m.elements.values():
        if not e.shared:
            continue
        why = f"{e.name} can return another tenant's records"
        im = impact(m, e)
        yield Threat("Cross-tenant access", e.name, why, 3, im)


AGENT_RULES = (
    prompt_injection,
    tool_misuse,
    excessive_agency,
    exfiltration,
    lethal_trifecta,
    cross_tenant,
)


def threat_register(m: SystemModel) -> list[Threat]:
    """All threats, highest score first, with stable ids."""
    found = list(stride(m))
    for rule in AGENT_RULES:
        found.extend(rule(m))
    found.sort(key=lambda t: (-t.score, t.category, t.target))
    return [
        replace(t, id=f"T-{i:03d}")
        for i, t in enumerate(found, 1)
    ]


def to_markdown(m: SystemModel, threats: list[Threat]) -> str:
    rows = [
        f"# Threat register: {m.name}",
        "",
        "| ID | Severity | LxI | Category | Target | Threat"
        " | Mitigation |",
        "|---|---|---|---|---|---|---|",
    ]
    for t in threats:
        rows.append(
            f"| {t.id} | {t.severity} | {t.likelihood}x{t.impact}"
            f" | {t.category} | {t.target} | {t.text}"
            f" | {t.mitigation} |"
        )
    return "\n".join(rows) + "\n"
