"""A security and governance maturity scorecard for agents.

Teams overestimate their controls because nobody checks the
quiet ones. The scorecard lists the book's practices as
yes/no checks by domain and level; a level counts only when
every practice at that level and below is in place.
"""

from __future__ import annotations

from dataclasses import dataclass

LEVELS = ("ad hoc", "basic", "managed", "assured")
DOMAINS = (
    "identity",
    "boundary",
    "data",
    "assurance",
    "response",
    "governance",
)

PRACTICES = [  # (domain, level, practice)
    ("identity", 1, "agent has its own identity"),
    ("identity", 2, "scoped, expiring delegation"),
    ("identity", 2, "default-deny tool authorization"),
    ("identity", 3, "secrets brokered, never in context"),
    ("boundary", 1, "tool results labeled by trust"),
    ("boundary", 2, "information flow control"),
    ("boundary", 2, "egress allowlist"),
    ("boundary", 3, "code runs in an isolated sandbox"),
    ("data", 1, "outbound DLP on email and URLs"),
    ("data", 2, "ACL filter before retrieval ranking"),
    ("data", 3, "purpose-bound minimization"),
    ("assurance", 1, "risky actions need approval"),
    ("assurance", 2, "red-team suite in CI"),
    ("assurance", 3, "approval fatigue measured"),
    ("response", 1, "every decision logged"),
    ("response", 2, "detection rules on agent events"),
    ("response", 3, "containment rehearsed"),
    ("governance", 1, "threat model per agent"),
    ("governance", 2, "policy as code with tests"),
    ("governance", 2, "tamper-evident audit trail"),
    ("governance", 3, "signed AI bill of materials"),
    ("governance", 3, "launch review gate"),
]


@dataclass(frozen=True)
class DomainScore:
    domain: str
    level: int
    next_steps: tuple[str, ...]

    @property
    def label(self) -> str:
        return LEVELS[self.level]


def score(in_place: set[str]) -> list[DomainScore]:
    """Highest level per domain with no gaps below it."""
    unknown = in_place - {p for _, _, p in PRACTICES}
    if unknown:
        raise ValueError(f"unknown practices: {sorted(unknown)}")
    out = []
    for domain in DOMAINS:
        mine = [
            (lvl, p) for d, lvl, p in PRACTICES if d == domain
        ]
        level = 0
        for lvl in (1, 2, 3):
            if all(p in in_place for x, p in mine if x == lvl):
                level = lvl
            else:
                break
        nxt = tuple(
            p
            for x, p in mine
            if x == level + 1 and p not in in_place
        )
        out.append(DomainScore(domain, level, nxt))
    return out
