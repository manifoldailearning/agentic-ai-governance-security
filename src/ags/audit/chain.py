"""Tamper-evident audit log: HMAC-chained canonical JSON.

An audit trail is evidence only if changes to it show. Each
entry's HMAC-SHA256 covers its canonical JSON and the MAC of
the entry before it, so editing, deleting or reordering an
entry fails verification at exactly that entry. Anchors (the
head MAC, exported elsewhere) expose truncation and rewrites.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> bytes:
    """One byte form per value: sorted keys, no spaces, UTF-8,
    no NaN. (Cross-language verifiers: use RFC 8785 JCS.)"""
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def seal(key: bytes, body: Mapping[str, Any]) -> str:
    return hmac.new(
        key, canonical(body), hashlib.sha256
    ).hexdigest()


def same(a: Any, b: Any) -> bool:
    """Constant-time compare that never raises on odd input."""
    return hmac.compare_digest(str(a).encode(), str(b).encode())


@dataclass(frozen=True)
class Entry:
    seq: int
    key_id: str
    prev: str  # MAC of the previous entry, or GENESIS
    record: dict[str, Any]
    mac: str

    def body(self) -> dict[str, Any]:
        """Everything the MAC covers: all fields but the MAC."""
        d = asdict(self)
        del d["mac"]
        return d


@dataclass(frozen=True)
class Anchor:
    seq: int
    mac: str


class AuditLog:
    """Append-only chain, anchored every ``anchor_every``.

    HMAC proves integrity to key holders only: anyone with the
    key can forge, so keep it away from the writers' hosts
    and store anchors where those writers cannot reach.
    """

    def __init__(
        self, key: bytes, key_id: str, anchor_every: int = 0
    ) -> None:
        self._key, self.key_id = key, key_id
        self.anchor_every = anchor_every
        self.entries: list[Entry] = []
        self.anchors: list[Anchor] = []

    @property
    def head(self) -> str:
        return self.entries[-1].mac if self.entries else GENESIS

    def rotate(self, key: bytes, key_id: str) -> None:
        """New entries use the new key; old ones keep theirs."""
        self._key, self.key_id = key, key_id

    def append(self, record: Any) -> Entry:
        """Seal a dict (or anything with ``to_dict``)."""
        if hasattr(record, "to_dict"):
            record = record.to_dict()
        frozen = json.loads(canonical(record))  # a private copy
        body = {
            "seq": len(self.entries),
            "key_id": self.key_id,
            "prev": self.head,
            "record": frozen,
        }
        entry = Entry(**body, mac=seal(self._key, body))
        self.entries.append(entry)
        if (
            self.anchor_every
            and len(self.entries) % self.anchor_every == 0
        ):
            self.anchors.append(Anchor(entry.seq, entry.mac))
        return entry


@dataclass(frozen=True)
class Verification:
    ok: bool
    checked: int
    bad_index: int | None = None
    problem: str = ""

    def __str__(self) -> str:
        if self.ok:
            return f"PASS: {self.checked} entries verified"
        return f"FAIL at entry {self.bad_index}: {self.problem}"


def _check(
    entry: Entry, prev: str, keys: Mapping[str, bytes]
) -> str:
    key = keys.get(entry.key_id)
    if key is None:
        return f"unknown key id {entry.key_id!r}"
    if not same(entry.prev, prev):
        return "chain broken (entry missing, added or moved)"
    try:
        expected = seal(key, entry.body())
    except (TypeError, ValueError):  # not JSON any more
        return "content altered"
    return "" if same(entry.mac, expected) else "content altered"


def verify(
    entries: Sequence[Entry],
    keys: Mapping[str, bytes],
    anchors: Iterable[Anchor] = (),
) -> Verification:
    """Walk the chain; report the first entry that fails."""
    prev = GENESIS
    for i, entry in enumerate(entries):
        if problem := _check(entry, prev, keys):
            return Verification(False, i, i, problem)
        prev = entry.mac
    n = len(entries)
    for a in anchors:
        if a.seq >= n:
            return Verification(
                False,
                n,
                a.seq,
                "truncated: anchored entry missing",
            )
        if not same(entries[a.seq].mac, a.mac):
            return Verification(
                False, n, a.seq, "anchor mismatch: log rewritten"
            )
    return Verification(True, n)


def save(entries: Iterable[Entry], path: str | Path) -> None:
    lines = [canonical(asdict(e)).decode() for e in entries]
    Path(path).write_text("".join(x + "\n" for x in lines))


def load(path: str | Path) -> list[Entry]:
    rows = Path(path).read_text().splitlines()
    return [Entry(**json.loads(r)) for r in rows if r.strip()]
