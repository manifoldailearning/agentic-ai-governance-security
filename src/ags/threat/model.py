"""A system model of an agent, derived from its tool specs.

You cannot defend what you have not drawn. ``SystemModel``
records the elements of an agent system, the trust zone
each one lives in and the data flows between them.
``from_specs`` builds it from the same ``ToolSpec`` list the
runtime enforces, so the model cannot drift from the code.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from ags.core.types import ToolSpec

SENSITIVE = frozenset({"pii", "bulk", "secret", "internal"})
ACTIONS = ("write", "external", "exec")  # tool effects


@dataclass(frozen=True)
class Element:
    name: str
    kind: str  # actor | process | external | tool | store
    zone: str  # user | agent | provider | internal | internet
    labels: frozenset[str] = frozenset()  # data it yields
    effect: str = ""  # tools only
    risk: str = "low"
    shared: bool = False  # serves data of many tenants


@dataclass(frozen=True)
class Flow:
    src: str
    dst: str
    what: str
    labels: frozenset[str] = frozenset()


@dataclass
class SystemModel:
    name: str
    elements: dict[str, Element] = field(default_factory=dict)
    flows: list[Flow] = field(default_factory=list)

    def add(self, element: Element) -> None:
        self.elements[element.name] = element

    def connect(
        self, src: str, dst: str, what: str, labels=frozenset()
    ) -> None:
        self.flows.append(Flow(src, dst, what, frozenset(labels)))

    def add_store(
        self,
        name: str,
        readers: Iterable[str],
        multi_tenant: bool,
    ) -> None:
        """A data store and the tools that read from it."""
        tools = [self.elements[r] for r in readers]
        held = frozenset().union(*(t.labels for t in tools))
        shared = multi_tenant and "pii" in held
        store = Element(name, "store", "internal", held)
        self.add(replace(store, shared=shared))
        for t in tools:
            self.connect(name, t.name, "records", t.labels)

    def crosses(self, flow: Flow) -> bool:
        """True when the flow crosses a trust boundary."""
        el = self.elements
        return el[flow.src].zone != el[flow.dst].zone

    def of_kind(self, kind: str) -> list[Element]:
        found = self.elements.values()
        return [e for e in found if e.kind == kind]

    def tools(self) -> list[Element]:
        return self.of_kind("tool")

    def agent(self) -> Element:
        return self.of_kind("process")[0]

    def actions(self) -> list[Element]:
        """Tools with side effects: write, external, exec."""
        return [t for t in self.tools() if t.effect in ACTIONS]

    def sources(self, labels: Iterable[str]) -> list[Element]:
        """Tools whose results carry any of ``labels``."""
        wanted = set(labels)
        return [t for t in self.tools() if t.labels & wanted]

    def sinks(self) -> list[Element]:
        """Tools that can move data outside the organisation."""
        return [t for t in self.tools() if t.effect == "external"]


def zone_of(spec: ToolSpec) -> str:
    """Tools that reach or ingest the outside live outside."""
    if spec.effect == "external" or "untrusted" in spec.labels:
        return "internet"
    return "internal"


def from_specs(
    name: str,
    specs: Iterable[ToolSpec],
    stores: dict[str, Iterable[str]] | None = None,
    multi_tenant: bool = True,
) -> SystemModel:
    """User, agent, model provider, tools and data stores.

    ``stores`` maps a store to the tools that read it; with
    ``multi_tenant`` any element holding pii is shared.
    """
    m = SystemModel(name)
    m.add(Element("user", "actor", "user"))
    m.add(Element(name, "process", "agent"))
    m.add(Element("llm", "external", "provider"))
    m.connect("user", name, "task")
    m.connect(name, "user", "answer")
    for s in specs:
        shared = multi_tenant and "pii" in s.labels
        m.add(
            Element(
                s.name,
                "tool",
                zone_of(s),
                s.labels,
                effect=s.effect,
                risk=s.risk,
                shared=shared,
            )
        )
        m.connect(name, s.name, "call arguments")
        m.connect(s.name, name, "result", s.labels)
    for store, readers in (stores or {}).items():
        m.add_store(store, readers, multi_tenant)
    seen = frozenset().union(*(t.labels for t in m.tools()))
    m.connect(name, "llm", "prompt and context", seen)
    m.connect("llm", name, "proposed tool calls", {"untrusted"})
    return m
