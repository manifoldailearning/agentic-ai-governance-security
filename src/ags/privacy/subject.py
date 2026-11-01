"""Data subject requests and retention across agent stores.

Agents scatter personal data: the system of record, memory,
event logs. An access or erasure request must find every copy.
``fulfil`` asks each registered store to export or erase what
mentions the subject and returns a report an auditor can read.
Logs kept as evidence are pseudonymized with a keyed hash
rather than deleted. ``retention_sweep`` ages rows out.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable
from dataclasses import (
    asdict,
    dataclass,
    field,
    fields,
    is_dataclass,
)
from typing import Any, Protocol

from ags.core import Event


def matcher(identifiers: Iterable[str]) -> re.Pattern[str]:
    """Whole-token, case-insensitive match: C-100, not C-1000."""
    alts = "|".join(re.escape(i) for i in sorted(identifiers))
    return re.compile(rf"(?<![\w@.-])(?:{alts})(?![\w-])", re.I)


def mentions(value: Any, pattern: re.Pattern[str]) -> bool:
    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    if isinstance(value, str):
        return bool(pattern.search(value))
    if isinstance(value, dict):
        items = [*value.keys(), *value.values()]
        return any(mentions(v, pattern) for v in items)
    if isinstance(value, list | tuple | set | frozenset):
        return any(mentions(v, pattern) for v in value)
    return False


def scrub(
    value: Any, pattern: re.Pattern[str], token: str
) -> Any:
    if isinstance(value, str):
        return pattern.sub(token, value)
    if isinstance(value, dict):
        return {
            k: scrub(v, pattern, token) for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub(v, pattern, token) for v in value]
    return value


class SubjectStore(Protocol):
    name: str

    def find(self, pattern: re.Pattern[str]) -> list[Any]: ...

    def erase(
        self, pattern: re.Pattern[str], token: str
    ) -> str: ...


@dataclass
class DictStore:
    """Rows keyed by id: a system of record or a memory table."""

    name: str
    rows: dict[str, Any]

    def _keys(self, pattern: re.Pattern[str]) -> list[str]:
        return [
            k
            for k, v in self.rows.items()
            if mentions(k, pattern) or mentions(v, pattern)
        ]

    def find(self, pattern: re.Pattern[str]) -> list[Any]:
        return [self.rows[k] for k in self._keys(pattern)]

    def erase(self, pattern: re.Pattern[str], token: str) -> str:
        for key in self._keys(pattern):
            del self.rows[key]
        return "deleted"


@dataclass
class EventStore:
    """Security events: retained as evidence, pseudonymized."""

    name: str
    events: list[Event]

    def find(self, pattern: re.Pattern[str]) -> list[Any]:
        return [e for e in self.events if mentions(e, pattern)]

    def erase(self, pattern: re.Pattern[str], token: str) -> str:
        for e in self.find(pattern):
            for f in fields(e):  # every field find() searched
                value = getattr(e, f.name)
                setattr(e, f.name, scrub(value, pattern, token))
        return "pseudonymized"


@dataclass(frozen=True)
class DataSubjectRequest:
    id: str
    kind: str  # export | erase
    identifiers: frozenset[str]


@dataclass
class DSRReport:
    request: DataSubjectRequest
    found: dict[str, int] = field(default_factory=dict)
    actions: dict[str, str] = field(default_factory=dict)
    export: dict[str, list[Any]] = field(default_factory=dict)

    def lines(self) -> list[str]:
        return [
            f"{name:<10} {n} found  {self.actions.get(name, '-')}"
            for name, n in self.found.items()
        ]


def pseudonym(request: DataSubjectRequest, key: bytes) -> str:
    """Stable keyed token: linkable for audit, not reversible."""
    ids = sorted(i.lower() for i in request.identifiers)
    msg = "|".join(ids).encode()
    digest = hmac.new(key, msg, hashlib.sha256).hexdigest()
    return f"subject:{digest[:10]}"


def fulfil(
    request: DataSubjectRequest,
    stores: Iterable[SubjectStore],
    key: bytes,
) -> DSRReport:
    """Export or erase the subject's data in every store."""
    pattern = matcher(request.identifiers)
    token = pseudonym(request, key)
    report = DSRReport(request)
    for store in stores:
        rows = store.find(pattern)
        report.found[store.name] = len(rows)
        if request.kind == "export":
            report.export[store.name] = rows
        elif rows:
            report.actions[store.name] = store.erase(
                pattern, token
            )
    return report


def retention_sweep(
    rows: dict[str, dict[str, Any]],
    now: float,
    max_age: float,
    holds: frozenset[str] = frozenset(),
) -> list[str]:
    """Delete rows older than ``max_age`` unless on legal hold."""
    old = [
        k
        for k, row in rows.items()
        if now - row["ts"] > max_age and k not in holds
    ]
    for key in old:
        del rows[key]
    return old
