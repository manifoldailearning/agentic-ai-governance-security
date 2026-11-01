"""Security events: one row per decision the runtime makes.

Every tool call, every guard verdict and every output check
becomes an ``Event``. Detection, forensics, audit and
compliance evidence in later chapters all read this stream,
so it is written before the action runs, not after.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Event:
    ts: float
    run_id: str
    actor: str  # the agent identity
    principal: str  # the user it acts for
    tenant: str
    kind: str  # task | tool_call | output | error
    tool: str = ""
    verdict: str = ""  # allow | deny | approve
    guard: str = ""
    reason: str = ""
    labels: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventLog:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def add(self, event: Event) -> Event:
        self.events.append(event)
        return event

    def where(self, **match: Any) -> list[Event]:
        return [
            e
            for e in self.events
            if all(getattr(e, k) == v for k, v in match.items())
        ]

    def save(self, path: str | Path) -> int:
        with Path(path).open("w") as f:
            for e in self.events:
                f.write(json.dumps(e.to_dict(), sort_keys=True))
                f.write("\n")
        return len(self.events)


def load_events(path: str | Path) -> list[Event]:
    rows = Path(path).read_text().splitlines()
    return [Event(**json.loads(r)) for r in rows if r.strip()]


def kinds(events: Iterable[Event]) -> list[str]:
    return [e.kind for e in events]
