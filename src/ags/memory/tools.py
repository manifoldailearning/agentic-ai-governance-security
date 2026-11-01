"""Memory as agent tools, bound to one principal.

The model chooses what to remember and what to look up, but
never whose memory: tenant and owner come from the session's
principal, not from tool arguments, so an injected ``tenant``
or ``owner`` argument has nothing to bind to and the call
fails instead of reaching another tenant's notes.
"""

from __future__ import annotations

from ags.core import Principal, Tool, ToolSpec
from ags.memory.store import MemoryStore


def memory_tools(
    store: MemoryStore, principal: Principal, k: int = 3
) -> list[Tool]:
    """``recall`` and ``remember`` tools for one session."""

    def recall(query: str) -> list[dict[str, str]]:
        hits = store.search(principal, query, k)
        return [{"id": e.id, "text": e.text} for e in hits]

    def remember(text: str) -> str:
        entry = store.write(principal, text, "remember")
        return f"{entry.id} {entry.status}"

    return [
        Tool(
            ToolSpec(
                "recall", "read", "low", frozenset({"memory"})
            ),
            recall,
        ),
        Tool(ToolSpec("remember", "write", "low"), remember),
    ]
