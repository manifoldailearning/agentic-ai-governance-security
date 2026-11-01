"""A secret broker: tools get credentials, the model never does.

Secrets live in a versioned in-memory vault. The agent only
sees handles such as ``{{secret:crm_api}}``; a bound tool
resolves them at execution time, and only for secrets that
were granted to that tool. Values never enter the prompt,
the context or the event log, and rotation is one call.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import Any

from ags.core.runtime import Tool

HANDLE = re.compile(r"\{\{secret:([A-Za-z0-9_.-]+)\}\}")
MIN_LENGTH = 12  # shorter values cannot be scanned for safely


class SecretError(Exception):
    """A handle that must not be resolved for this tool."""


def walk(obj: Any, fn: Callable[[str], str]) -> Any:
    """Apply ``fn`` to every string inside nested data."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):
        return {k: walk(v, fn) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return type(obj)(walk(v, fn) for v in obj)
    return obj


def strings(
    obj: Any, path: str = ""
) -> Iterator[tuple[str, str]]:
    """Yield (path, text) for every string inside nested data."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from strings(
                v, f"{path}.{k}" if path else str(k)
            )
    elif isinstance(obj, list | tuple):
        for i, v in enumerate(obj):
            yield from strings(v, f"{path}[{i}]")


def handle(name: str) -> str:
    return "{{secret:" + name + "}}"


class SecretBroker:
    def __init__(self) -> None:
        self._versions: dict[str, list[str]] = {}
        self._grants: dict[str, set[str]] = {}  # secret -> tools

    def put(self, name: str, value: str) -> int:
        """Store a new version; the newest is current."""
        if len(value) < MIN_LENGTH:
            raise ValueError(f"{name}: secret is too short")
        self._versions.setdefault(name, []).append(value)
        return len(self._versions[name])

    def rotate(self, name: str, value: str) -> int:
        if name not in self._versions:
            raise KeyError(name)
        return self.put(name, value)

    def grant(self, name: str, tool: str) -> None:
        self._grants.setdefault(name, set()).add(tool)

    def granted(self, name: str, tool: str) -> bool:
        return tool in self._grants.get(name, set())

    def current(self, name: str) -> str:
        return self._versions[name][-1]

    def known_values(self) -> dict[str, str]:
        """Every version, old ones too: a rotated key that
        leaks is still a leak worth reporting."""
        return {
            value: f"{name}@v{i}"
            for name, versions in self._versions.items()
            for i, value in enumerate(versions, 1)
        }

    def resolve(self, tool: str, obj: Any) -> Any:
        """Swap handles for values, for granted secrets only."""

        def value_for(m: re.Match[str]) -> str:
            name = m.group(1)
            if name not in self._versions:
                raise SecretError(f"unknown secret {name}")
            if not self.granted(name, tool):
                raise SecretError(f"{name} not granted to {tool}")
            return self.current(name)

        return walk(obj, lambda text: HANDLE.sub(value_for, text))

    def scrub(self, text: str) -> str:
        """Replace any known secret value with its label."""
        for value, label in self.known_values().items():
            text = text.replace(value, f"[{label}]")
        return text

    def bind(self, tool: Tool) -> Tool:
        """Resolve handles on the way in; scrub on the way out."""
        name = tool.spec.name

        def run(**args: Any) -> Any:
            result = tool.fn(**self.resolve(name, args))
            return walk(result, self.scrub)

        return Tool(tool.spec, run)
