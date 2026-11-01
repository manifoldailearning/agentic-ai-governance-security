"""Purpose binding: an agent sees only what its task needs.

Minimization is easiest to enforce at the tool boundary:
project each record onto the fields its declared purpose
allows and derive coarse values (last four digits) instead of
passing raw ones. What never enters the context cannot be
leaked, injected out or remembered. Consent gates purposes
that need it; a guard keeps a session to its purpose's tools.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from ags.core import (
    ALLOW,
    Context,
    Decision,
    Tool,
    ToolCall,
    ToolSpec,
)

PII_FIELDS = frozenset({"name", "email", "phone", "card"})

# derived field -> (source field, coarsening function)
DERIVED: dict[str, tuple[str, Callable[[str], str]]] = {
    "last4": ("card", lambda v: v[-4:]),
    "email_domain": ("email", lambda v: v.partition("@")[2]),
}


@dataclass(frozen=True)
class Purpose:
    name: str
    fields: frozenset[str]
    tools: frozenset[str]
    needs_consent: bool = False


def purpose(name: str, fields: str, tools: str, **kw) -> Purpose:
    return Purpose(
        name,
        frozenset(fields.split()),
        frozenset(tools.split()),
        **kw,
    )


PURPOSES = {
    p.name: p
    for p in (
        purpose(
            "refund",
            "id plan last4",
            "lookup_customer issue_refund read_doc",
        ),
        purpose(
            "support",
            "id name email plan",
            "lookup_customer read_inbox read_doc send_email",
        ),
        purpose(
            "marketing",
            "id plan email_domain",
            "export_customers",
            needs_consent=True,
        ),
    )
}


def minimize(data: Any, purpose: Purpose) -> Any:
    """Project a record (or a list of them) onto a purpose."""
    if isinstance(data, list):
        return [minimize(item, purpose) for item in data]
    if not isinstance(data, dict):
        return data
    out = {}
    for name in sorted(purpose.fields):
        if name in data:
            out[name] = data[name]
        elif name in DERIVED and DERIVED[name][0] in data:
            source, coarsen = DERIVED[name]
            out[name] = coarsen(str(data[source]))
    return out


@dataclass
class ConsentRegistry:
    grants: dict[str, set[str]] = field(default_factory=dict)

    def grant(self, subject: str, purpose: str) -> None:
        self.grants.setdefault(subject, set()).add(purpose)

    def withdraw(self, subject: str, purpose: str) -> None:
        self.grants.get(subject, set()).discard(purpose)

    def allows(self, subject: str, purpose: Purpose) -> bool:
        if not purpose.needs_consent:
            return True
        return purpose.name in self.grants.get(subject, set())


class MinimizingTool(Tool):
    """A tool whose results are projected to one purpose.

    If no direct identifier survives the projection, the
    ``pii`` label is dropped too, so downstream guards see
    the context as it really is: less sensitive.
    """

    def __init__(
        self,
        tool: Tool,
        purpose: Purpose,
        consent: ConsentRegistry | None = None,
    ) -> None:
        labels = tool.spec.labels
        if not purpose.fields & PII_FIELDS:
            labels -= {"pii"}
        super().__init__(
            replace(tool.spec, labels=labels), self._run
        )
        self.inner, self.purpose = tool, purpose
        self.consent = consent or ConsentRegistry()

    def _run(self, **args: Any) -> Any:
        data = self.inner.fn(**args)
        if isinstance(data, list):
            return [self._project(r) for r in data]
        return self._project(data)

    def _project(self, record: Any) -> Any:
        if not isinstance(record, dict):
            return record
        subject = str(record.get("id", ""))
        if not self.consent.allows(subject, self.purpose):
            why = f"no consent for {self.purpose.name}"
            return {"id": subject, "withheld": why}
        return minimize(record, self.purpose)


@dataclass
class PurposeGuard:
    """Deny tools the session's declared purpose does not need."""

    purpose: Purpose
    name: str = "purpose"

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        if spec.name in self.purpose.tools:
            return ALLOW
        why = f"{spec.name} not needed for {self.purpose.name!r}"
        return Decision("deny", self.name, why)
