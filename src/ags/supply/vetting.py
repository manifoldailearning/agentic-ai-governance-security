"""Vetting third-party tools before an agent may call them.

A tool or tool server is code you did not write, running
with the agent's authority. The scorecard compares scopes
requested with scopes needed and weighs data access, network
egress, maintainer and update policy. It returns approve,
conditional (with the conditions) or reject. Hard failures,
such as wildcard scopes, reject whatever the score.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

DATA_RISK = {"none": 0, "internal": 1, "pii": 2, "secrets": 3}
MAINTAINER_RISK = {
    "vendor": 0,
    "community": 1,
    "individual": 2,
    "unknown": 3,
}
UPDATE_RISK = {"pinned": 0, "reviewed": 1, "auto": 3}


@dataclass(frozen=True)
class ToolProfile:
    name: str
    scopes_requested: frozenset[str]
    scopes_needed: frozenset[str]
    data_access: str = "none"  # none | internal | pii | secrets
    egress: frozenset[str] = frozenset()  # hosts it contacts
    maintainer: str = "unknown"
    update_policy: str = "auto"  # pinned | reviewed | auto


@dataclass(frozen=True)
class Issue:
    points: int
    text: str
    fix: str = ""  # condition that would remove the issue
    fatal: bool = False


@dataclass(frozen=True)
class Vetting:
    tool: str
    verdict: str  # approve | conditional | reject
    score: int
    issues: tuple[Issue, ...]

    @property
    def conditions(self) -> list[str]:
        return [i.fix for i in self.issues if i.fix]


def _norm(items: Iterable[str]) -> set[str]:
    return {i.strip().lower().rstrip(".") for i in items}


def is_wildcard(scope: str) -> bool:
    s = scope.strip().lower()
    return s in ("*", "admin") or s.endswith((":*", ":admin"))


def scope_issues(p: ToolProfile) -> Iterator[Issue]:
    needed = _norm(p.scopes_needed)
    for s in sorted(_norm(p.scopes_requested)):
        if is_wildcard(s):
            yield Issue(3, f"wildcard scope {s}", fatal=True)
        elif s not in needed:
            yield Issue(2, f"excess scope {s}", f"drop {s}")


def egress_issues(
    p: ToolProfile, allowed: Iterable[str]
) -> Iterator[Issue]:
    ok = _norm(allowed)
    for host in sorted(_norm(p.egress)):
        if host == "*":
            yield Issue(3, "egress to any host", fatal=True)
        elif host not in ok:
            yield Issue(2, f"egress to {host}", f"block {host}")


def profile_issues(p: ToolProfile) -> Iterator[Issue]:
    if points := DATA_RISK[p.data_access]:
        yield Issue(points, f"reads {p.data_access} data")
    if points := MAINTAINER_RISK[p.maintainer]:
        yield Issue(points, f"maintainer: {p.maintainer}")
    if points := UPDATE_RISK[p.update_policy]:
        fix = "pin version" if p.update_policy == "auto" else ""
        yield Issue(points, f"updates: {p.update_policy}", fix)


def vet(
    p: ToolProfile,
    allowed_hosts: Iterable[str] = (),
    approve_below: int = 3,
    reject_at: int = 8,
) -> Vetting:
    issues = (
        *scope_issues(p),
        *egress_issues(p, allowed_hosts),
        *profile_issues(p),
    )
    score = sum(i.points for i in issues)
    if any(i.fatal for i in issues) or score >= reject_at:
        verdict = "reject"
    elif score >= approve_below:
        verdict = "conditional"
    else:
        verdict = "approve"
    return Vetting(p.name, verdict, score, issues)
