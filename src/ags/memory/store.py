"""Agent memory with access control, expiry and quarantine.

Three memory failures recur: one tenant's notes surfacing for
another, stale data outliving its purpose, and poisoned
entries that re-inject instructions into every later session.
``MemoryStore`` filters by tenant and owner/role BEFORE it
ranks, expires entries by TTL, and quarantines untrusted or
instruction-like writes until a reviewer releases them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from ags.core import Clock, FakeClock, Principal
from ags.memory.screen import instruction_reason

UNTRUSTED_SOURCES = frozenset({"read_inbox", "fetch_url"})


@dataclass
class MemoryEntry:
    id: str
    text: str
    tenant: str
    owner: str
    source: str  # "user" or the tool that produced the text
    trust: str = "trusted"  # trusted | untrusted
    labels: frozenset[str] = frozenset()
    readers: frozenset[str] = frozenset()  # roles; owner always
    created: float = 0.0
    ttl: float | None = None  # seconds; None = no expiry
    provenance: tuple[str, ...] = ()
    status: str = "active"  # active | quarantined
    reason: str = ""  # why it was quarantined

    def expired(self, now: float) -> bool:
        if self.ttl is None:
            return False
        return now >= self.created + self.ttl

    def readable_by(self, p: Principal) -> bool:
        if self.tenant != p.tenant:
            return False
        return self.owner == p.id or bool(self.readers & p.roles)


def tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


class MemoryStore:
    def __init__(
        self,
        clock: Clock | None = None,
        screen: bool = True,
        untrusted_sources: frozenset[str] = UNTRUSTED_SOURCES,
    ) -> None:
        self.clock = clock or FakeClock()
        self.screen = screen
        self.untrusted_sources = untrusted_sources
        self.entries: dict[str, MemoryEntry] = {}
        self._n = 0

    def write(
        self,
        owner: Principal,
        text: str,
        source: str = "user",
        *,
        labels: Iterable[str] = (),
        readers: Iterable[str] = (),
        ttl: float | None = None,
        provenance: tuple[str, ...] = (),
    ) -> MemoryEntry:
        """Store ``text`` for ``owner``; screen it first."""
        self._n += 1
        untrusted = source in self.untrusted_sources
        entry = MemoryEntry(
            f"mem-{self._n:04d}",
            text,
            owner.tenant,
            owner.id,
            source,
            "untrusted" if untrusted else "trusted",
            frozenset(labels),
            frozenset(readers),
            self.clock.now(),
            ttl,
            (*provenance, f"{owner.id} via {source}"),
        )
        if self.screen:
            self._quarantine_if_suspect(entry)
        self.entries[entry.id] = entry
        return entry

    def _quarantine_if_suspect(self, entry: MemoryEntry) -> None:
        reason = instruction_reason(entry.text)
        if reason is None and entry.trust == "untrusted":
            reason = f"untrusted source {entry.source}"
        if reason:
            entry.status, entry.reason = "quarantined", reason

    def search(
        self, reader: Principal, query: str, k: int = 3
    ) -> list[MemoryEntry]:
        """Top-``k`` matches among entries ``reader`` may see.

        The ACL filter runs first, so an entry the reader may
        not see never competes for a slot, however well it
        matches, and ranking cannot leak that it exists.
        """
        now = self.clock.now()
        visible = [
            e
            for e in self.entries.values()
            if e.status == "active"
            and not e.expired(now)
            and e.readable_by(reader)
        ]
        terms = tokens(query)
        scored = [
            (len(terms & tokens(e.text)), e) for e in visible
        ]
        hits = sorted(
            (s for s in scored if s[0] > 0),
            key=lambda s: (-s[0], s[1].id),
        )
        return [e for _, e in hits[:k]]

    def quarantined(self) -> list[MemoryEntry]:
        return [
            e
            for e in self.entries.values()
            if e.status == "quarantined"
        ]

    def release(
        self, entry_id: str, reviewer: str
    ) -> MemoryEntry:
        """A reviewer vouches for a quarantined entry."""
        entry = self.entries[entry_id]
        entry.status, entry.reason = "active", ""
        entry.provenance += (f"released by {reviewer}",)
        return entry

    def sweep(self) -> list[str]:
        """Delete expired entries; return their ids."""
        now = self.clock.now()
        gone = [
            i for i, e in self.entries.items() if e.expired(now)
        ]
        for entry_id in gone:
            del self.entries[entry_id]
        return gone

    def forget(
        self, owner: str, tenant: str | None = None
    ) -> int:
        """Erase all ``owner`` wrote, quarantined entries too."""
        gone = [
            i
            for i, e in self.entries.items()
            if e.owner == owner and tenant in (None, e.tenant)
        ]
        for entry_id in gone:
            del self.entries[entry_id]
        return len(gone)
