"""A scripted, deliberately gullible model for security tests.

Real models sometimes follow instructions they find inside
documents, emails or web pages. ``ScriptedModel`` makes that
failure reproducible: it executes its planned tool calls,
and with ``gullible=True`` it also obeys any ``ACTION:``
directive that appears in a tool result. ``$LAST`` inside a
string argument is replaced with the latest tool result,
which is how a model pastes data it has seen into a call.
Same script, same attack, every run, no network, no key.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ags.core.types import Message, ToolCall

DIRECTIVE = re.compile(r"ACTION:\s*(\w+)\s*(\{.*?\})", re.S)


@dataclass
class Final:
    text: str


def call(name: str, **args: Any) -> ToolCall:
    return ToolCall("", name, args)


def directives(text: str) -> list[ToolCall]:
    """Tool calls injected as ``ACTION: name {json}``."""
    found = []
    text = text.replace('\\"', '"')  # quotes inside JSON results
    for m in DIRECTIVE.finditer(text):
        try:
            args = json.loads(m.group(2))
        except json.JSONDecodeError:
            continue
        found.append(call(m.group(1), **args))
    return found


@dataclass
class ScriptedModel:
    plan: list[ToolCall]
    answer: str = "Done."
    gullible: bool = False
    _queue: list[ToolCall] = field(default_factory=list)
    _seen: int = 0
    _n: int = 0

    def next(self, messages: list[Message]) -> ToolCall | Final:
        if self.gullible:
            for m in messages[self._seen :]:
                if m.role == "tool":
                    self._queue.extend(directives(m.content))
        self._seen = len(messages)
        last = next(
            (
                m.content
                for m in reversed(messages)
                if m.role == "tool"
            ),
            "",
        )
        if self._queue:
            return self._number(self._queue.pop(0), last)
        if self.plan:
            return self._number(self.plan.pop(0), last)
        return Final(self.answer)

    def _number(self, c: ToolCall, last: str) -> ToolCall:
        self._n += 1
        args = {
            k: v.replace("$LAST", last)
            if isinstance(v, str)
            else v
            for k, v in c.args.items()
        }
        return ToolCall(f"call-{self._n}", c.name, args)
