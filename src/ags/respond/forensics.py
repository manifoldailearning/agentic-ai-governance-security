"""Forensics: what happened, in order, and how far it reached.

After containment the questions are always the same. What did
the agent do, step by step? Which data did it hold at each
step? Which records left, and to which outside destinations?
These functions answer from the event stream alone, keep
blocked attempts apart from real egress, and draft the notes.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from ags.core import Event
from ags.detect import Alert
from ags.respond.containment import Action

RECORD_ID = re.compile(r"\bC-\d{3,}\b")
DATA_CLASSES = {
    "card": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
    "email": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    "phone": re.compile(r"\+\d[\d ]{7,14}\d"),
}


@dataclass(frozen=True)
class Step:
    ts: float
    what: str  # tool name, or event kind
    verdict: str
    gained: tuple[str, ...]  # data labels this step added
    note: str


def _note(e: Event) -> str:
    if e.kind == "task":
        return repr(e.detail.get("task", ""))
    if e.verdict == "deny" or e.kind == "error":
        return f"{e.guard}: {e.reason}"
    args = e.detail.get("args", {})
    return " ".join(f"{k}={v}" for k, v in args.items())


def timeline(events: Iterable[Event], run_id: str) -> list[Step]:
    """One run, in order, with the labels each step brought in."""
    run = [e for e in events if e.run_id == run_id]
    run.sort(key=lambda e: e.ts)  # stable: ties keep log order
    steps = []
    for e, nxt in zip(run, [*run[1:], None], strict=True):
        gained = set(nxt.labels) - set(e.labels) if nxt else set()
        what, verdict = e.tool or e.kind, e.verdict or "-"
        steps.append(
            Step(
                e.ts,
                what,
                verdict,
                tuple(sorted(gained)),
                _note(e),
            )
        )
    return steps


def render_timeline(
    steps: Iterable[Step], width: int = 60
) -> list[str]:
    lines = []
    for s in steps:
        tail = " ".join([*(f"+{g}" for g in s.gained), s.note])
        line = f"{s.ts:>4.0f}s {s.what:<16} {s.verdict:<5} {tail}"
        line = line.rstrip()
        cut = len(line) > width
        lines.append(line[: width - 3] + "..." if cut else line)
    return lines


@dataclass(frozen=True)
class BlastRadius:
    reached: tuple[str, ...]  # destinations data actually went to
    blocked: tuple[str, ...]  # egress attempted and denied
    records: tuple[str, ...]
    tenants: tuple[str, ...]
    data: tuple[str, ...]  # data classes found in what left
    labels: tuple[str, ...]  # context labels at egress time


def _destination(args: Mapping) -> str:
    if "url" in args:
        return urlsplit(str(args["url"])).hostname or "?"
    return str(args.get("to", "?"))


def blast_radius(
    events: Iterable[Event],
    effects: Mapping[str, str],
    tenant_of: Callable[[str], str | None] = lambda _: None,
) -> BlastRadius:
    """What left through external tools, and what was stopped."""
    reached, blocked, labels = set(), set(), set()
    payload = []
    for e in events:
        if (
            e.kind != "tool_call"
            or effects.get(e.tool) != "external"
        ):
            continue
        args = e.detail.get("args", {})
        if e.verdict != "allow":
            blocked.add(_destination(args))
            continue
        reached.add(_destination(args))
        labels |= set(e.labels)
        rest = {k: v for k, v in args.items() if k != "to"}
        payload.append(json.dumps(rest))
    text = "\n".join(payload)
    records = set(RECORD_ID.findall(text))
    tenants = {t for r in records if (t := tenant_of(r))}
    data = {
        n for n, rx in DATA_CLASSES.items() if rx.search(text)
    }
    return BlastRadius(
        *(tuple(sorted(s)) for s in (reached, blocked, records)),
        *(tuple(sorted(s)) for s in (tenants, data, labels)),
    )


def incident_notes(
    run_id: str,
    alerts: Iterable[Alert],
    steps: Iterable[Step],
    radius: BlastRadius,
    actions: Iterable[Action],
) -> str:
    """A Markdown draft for the responder to correct and file."""

    def items(values: Iterable[str]) -> str:
        return ", ".join(values) or "none"

    lines = [f"# Incident draft: {run_id}", "", "## Detections"]
    lines += [
        f"- {a.severity} {a.rule}: {a.summary}" for a in alerts
    ]
    lines += ["", "## Timeline", "```"]
    lines += [
        *render_timeline(steps),
        "```",
        "",
        "## Blast radius",
    ]
    lines += [
        f"- Data reached: {items(radius.reached)}",
        f"- Egress blocked: {items(radius.blocked)}",
        f"- Records: {items(radius.records)}",
        f"- Tenants: {items(radius.tenants)}",
        f"- Data classes: {items(radius.data)}",
        "",
        "## Containment",
    ]
    lines += [
        f"- t={a.ts:g} {a.action} {a.target}: {a.reason}"
        for a in actions
    ]
    lines += ["", "## Next steps", *NEXT_STEPS]
    return "\n".join(lines) + "\n"


NEXT_STEPS = [
    "- Confirm scope with the owner of every affected tenant.",
    "- Preserve the event log and audit chain as evidence.",
    "- Assess notification duties for the data classes above.",
    "- Fix the root cause and re-test before thawing the agent.",
]
