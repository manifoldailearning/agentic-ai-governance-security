"""Data labels and the table that says where they may flow.

Labels form a simple lattice: a context's label set only
grows (join is set union), so once a run has read untrusted
mail or bulk personal data, every later call is judged with
that in mind. The policy table maps (labels in context x
tool effect) to allow, approve or deny; the strictest
matching row wins, and no matching row means allow.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

LABELS = {
    "untrusted": "written by someone outside the boundary",
    "internal": "company-internal, not for outsiders",
    "pii": "personal data about an identifiable person",
    "bulk": "many records at once",
    "secret": "credentials, keys and tokens",
}
STRICTNESS = {"allow": 0, "approve": 1, "deny": 2}

POLICY_TABLE = """
labels     effects              verdict  why
secret     external,write,exec  deny     secret data
pii,bulk   external             deny     bulk personal data
untrusted  exec                 deny     untrusted input
untrusted  external,write       approve  untrusted input
internal   external             approve  internal data
"""


def join(*label_sets: Iterable[str]) -> frozenset[str]:
    """Least upper bound: data derived from all of these."""
    return frozenset().union(*label_sets)


@dataclass(frozen=True)
class FlowRule:
    labels: frozenset[str]  # all must be in the context
    effects: frozenset[str]  # the tool effects it governs
    verdict: str
    why: str


def parse_policy(table: str) -> tuple[FlowRule, ...]:
    """Rows of: labels effects verdict why (header skipped)."""
    rules = []
    for row in table.strip().splitlines()[1:]:
        labels, effects, verdict, why = row.split(None, 3)
        names = frozenset(labels.split(","))
        if names - LABELS.keys() or verdict not in STRICTNESS:
            raise ValueError(f"bad policy row: {row!r}")
        effect_set = frozenset(effects.split(","))
        rules.append(FlowRule(names, effect_set, verdict, why))
    return tuple(rules)


DEFAULT_POLICY = parse_policy(POLICY_TABLE)


def decide(
    policy: Iterable[FlowRule], labels: set[str], effect: str
) -> FlowRule | None:
    """The strictest matching rule, or None for allow."""
    hits = [
        r
        for r in policy
        if r.labels <= labels and effect in r.effects
    ]
    if not hits:
        return None
    return max(hits, key=lambda r: STRICTNESS[r.verdict])
