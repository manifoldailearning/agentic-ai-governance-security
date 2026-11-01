"""Detection rules over the runtime's security event stream.

A guard judges one call at a time. Detection looks across
calls and runs for patterns no single decision reveals: a
burst of denials, an outbound call right after untrusted
input, a refund retried after its approval was refused.
Each rule reads ``Event`` rows and raises evidence-backed
``Alert`` objects, merged to one per rule per run.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict, deque
from collections.abc import (
    Callable,
    Iterable,
    Iterator,
    Mapping,
    Sequence,
)
from dataclasses import dataclass, field, replace
from itertools import pairwise
from typing import Protocol

from ags.core.events import Event
from ags.core.runtime import Tool

SEVERITY = ("low", "medium", "high", "critical")
ACTING = frozenset({"write", "external", "exec"})
EGRESS = frozenset({"external", "exec"})
REFUSED = ("no approver:", "approval refused:")
PII = re.compile(
    r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"  # email address
    r"|\b(?:\d{4}[ -]?){3}\d{4}\b"  # 16-digit card number
)


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str  # low | medium | high | critical
    run_id: str
    summary: str
    tactics: tuple[str, ...] = ()
    evidence: tuple[Event, ...] = ()

    @property
    def rank(self) -> int:
        return SEVERITY.index(self.severity)

    def merge(self, other: Alert) -> Alert:
        """Keep the worse alert; pool the evidence of both."""
        worst = other if other.rank > self.rank else self
        extra = [
            e for e in other.evidence if e not in self.evidence
        ]
        return replace(
            worst, evidence=self.evidence + tuple(extra)
        )


class Rule(Protocol):
    name: str

    def scan(
        self, events: Sequence[Event]
    ) -> Iterable[Alert]: ...


def effects_of(tools: Iterable[Tool]) -> dict[str, str]:
    """Tool name -> declared effect, for rules that need it."""
    return {t.spec.name: t.spec.effect for t in tools}


def tool_calls(events: Iterable[Event]) -> list[Event]:
    return [e for e in events if e.kind == "tool_call"]


def by_run(events: Iterable[Event]) -> dict[str, list[Event]]:
    """Tool-call events grouped per run, in stream order."""
    runs: dict[str, list[Event]] = defaultdict(list)
    for e in tool_calls(events):
        runs[e.run_id].append(e)
    return runs


def severity(e: Event, executed: str, blocked: str) -> str:
    """Worse when the control let the call through."""
    return executed if e.verdict == "allow" else blocked


def args_of(e: Event) -> dict:
    return e.detail.get("args", {})


@dataclass
class DeniedBurst:
    """``threshold`` denials for one agent within ``window`` s."""

    threshold: int = 3
    window: float = 5.0
    name: str = "denied-burst"

    def scan(self, events: Sequence[Event]) -> Iterator[Alert]:
        recent: dict[str, deque[Event]] = defaultdict(deque)
        for e in tool_calls(events):
            if e.verdict != "deny":
                continue
            q = recent[e.actor]
            q.append(e)
            while e.ts - q[0].ts > self.window:
                q.popleft()
            if len(q) >= self.threshold:
                yield Alert(
                    self.name,
                    "medium",
                    e.run_id,
                    f"{len(q)} denials in {self.window:g}s",
                    ("discovery", "defense-evasion"),
                    tuple(q),
                )


@dataclass
class SensitiveAfterUntrusted:
    """An acting call made while untrusted data is in context."""

    effects: Mapping[str, str]
    name: str = "sensitive-after-untrusted"

    def scan(self, events: Sequence[Event]) -> Iterator[Alert]:
        for e in tool_calls(events):
            acting = self.effects.get(e.tool) in ACTING
            if acting and "untrusted" in e.labels:
                yield Alert(
                    self.name,
                    severity(e, "high", "medium"),
                    e.run_id,
                    f"{e.tool} {e.verdict} (untrusted)",
                    ("execution", "exfiltration"),
                    (e,),
                )


@dataclass
class BulkPiiEgress:
    """Outbound call holding bulk PII, by label or by content."""

    effects: Mapping[str, str]
    min_values: int = 3
    name: str = "bulk-pii-egress"

    def scan(self, events: Sequence[Event]) -> Iterator[Alert]:
        for e in tool_calls(events):
            if self.effects.get(e.tool) not in EGRESS:
                continue
            found = set(PII.findall(json.dumps(args_of(e))))
            labelled = {"pii", "bulk"} <= set(e.labels)
            if labelled or len(found) >= self.min_values:
                yield Alert(
                    self.name,
                    severity(e, "critical", "high"),
                    e.run_id,
                    f"{e.tool} {e.verdict} (bulk PII)",
                    ("collection", "exfiltration"),
                    (e,),
                )


@dataclass
class CrossTenant:
    """An argument names a record owned by another tenant."""

    tenant_of: Callable[[str], str | None]
    name: str = "cross-tenant"

    def scan(self, events: Sequence[Event]) -> Iterator[Alert]:
        for e in tool_calls(events):
            for value in args_of(e).values():
                if not isinstance(value, str):
                    continue
                record = value.strip().upper()
                owner = self.tenant_of(record)
                if owner and owner != e.tenant:
                    yield Alert(
                        self.name,
                        severity(e, "high", "medium"),
                        e.run_id,
                        f"{e.tenant} -> {owner} record {record}",
                        ("privilege-escalation", "collection"),
                        (e,),
                    )


@dataclass
class ApprovalBypass:
    """Same tool tried again after its approval was refused."""

    name: str = "approval-bypass"

    def scan(self, events: Sequence[Event]) -> Iterator[Alert]:
        for run_id, calls in by_run(events).items():
            refused: dict[str, Event] = {}
            for e in calls:
                if first := refused.get(e.tool):
                    yield Alert(
                        self.name,
                        severity(e, "high", "medium"),
                        run_id,
                        f"{e.tool} retried",
                        (
                            "defense-evasion",
                            "privilege-escalation",
                        ),
                        (first, e),
                    )
                elif e.reason.startswith(REFUSED):
                    refused[e.tool] = e


@dataclass
class SequenceBaseline:
    """Counts of tool-to-tool steps seen in normal runs."""

    counts: Counter[tuple[str, str]] = field(
        default_factory=Counter
    )

    def fit(self, events: Iterable[Event]) -> SequenceBaseline:
        for calls in by_run(events).values():
            self.counts.update(steps(calls))
        return self


def steps(calls: Sequence[Event]) -> list[tuple[str, str]]:
    """Bigrams of tool names; ``^`` marks the start of a run."""
    return list(pairwise(["^", *(e.tool for e in calls)]))


@dataclass
class RareSequence:
    """A step between tools that normal runs rarely take."""

    baseline: SequenceBaseline
    min_count: int = 1
    name: str = "rare-sequence"

    def scan(self, events: Sequence[Event]) -> Iterator[Alert]:
        for run_id, calls in by_run(events).items():
            for (a, b), e in zip(
                steps(calls), calls, strict=True
            ):
                if self.baseline.counts[a, b] < self.min_count:
                    yield Alert(
                        self.name,
                        "low",
                        run_id,
                        f"{a} -> {b}",
                        ("execution",),
                        (e,),
                    )


def default_rules(
    effects: Mapping[str, str],
    tenant_of: Callable[[str], str | None],
    baseline: SequenceBaseline,
) -> list[Rule]:
    return [
        DeniedBurst(),
        SensitiveAfterUntrusted(effects),
        BulkPiiEgress(effects),
        CrossTenant(tenant_of),
        ApprovalBypass(),
        RareSequence(baseline),
    ]


def detect(
    events: Sequence[Event], rules: Iterable[Rule]
) -> list[Alert]:
    """One alert per (rule, run); per run, worst first."""
    merged: dict[tuple[str, str], Alert] = {}
    for rule in rules:
        for alert in rule.scan(events):
            key = (alert.rule, alert.run_id)
            old = merged.get(key)
            merged[key] = old.merge(alert) if old else alert
    return sorted(
        merged.values(),
        key=lambda a: (a.run_id, -a.rank, a.rule),
    )
