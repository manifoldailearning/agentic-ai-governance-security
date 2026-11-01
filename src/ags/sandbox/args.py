"""Validate tool arguments before a tool ever sees them.

Arguments come from text the model read, so treat them as
attacker input. ``ArgSchemaGuard`` enforces a schema per
tool (names, required, exact types, lengths, patterns) and
denies tools without one. ``PathGuard`` confines paths to
allowed roots after resolving ``..`` and symlinks; a file
swapped between check and open still wins that race.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ags.core import ALLOW, Context, Decision, ToolCall, ToolSpec


@dataclass(frozen=True)
class Field:
    type: type = str
    required: bool = True
    max_len: int = 256
    pattern: str | None = None  # must fullmatch


def field_problem(name: str, f: Field, value: Any) -> str | None:
    ok_type = isinstance(value, f.type)
    if isinstance(value, bool) and f.type is not bool:
        ok_type = False  # True is an int in Python
    if f.type is float and type(value) is int:
        ok_type = True
    if not ok_type:
        return f"{name}: expected {f.type.__name__}"
    if isinstance(value, str):
        if len(value) > f.max_len:
            return f"{name}: longer than {f.max_len}"
        if f.pattern and not re.fullmatch(f.pattern, value):
            return f"{name}: does not match {f.pattern}"
    return None


@dataclass
class ArgSchemaGuard:
    schemas: dict[str, dict[str, Field]]
    name: str = "arg_schema"

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        schema = self.schemas.get(call.name)
        if schema is None:
            return self._deny(f"no schema for {call.name}")
        if extra := sorted(call.args.keys() - schema.keys()):
            return self._deny(f"unexpected args {extra}")
        for name, f in schema.items():
            if name not in call.args:
                if f.required:
                    return self._deny(f"{name}: required")
                continue
            if why := field_problem(name, f, call.args[name]):
                return self._deny(why)
        return ALLOW

    def _deny(self, why: str) -> Decision:
        return Decision("deny", self.name, why)


@dataclass
class PathGuard:
    roots: tuple[Path, ...]
    path_args: tuple[str, ...] = ("path",)
    name: str = "path"

    def problem(self, raw: str) -> str | None:
        if any(c in raw for c in "\0\\%"):
            return "NUL, backslash or %-encoding in path"
        base = self.roots[0].resolve()  # for relative paths
        target = (base / raw).resolve()  # follows symlinks
        for root in self.roots:
            if target.is_relative_to(root.resolve()):
                return None
        return f"{raw} resolves outside allowed roots"

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        for arg in self.path_args:
            value = call.args.get(arg)
            if value is None:
                continue
            why = "path must be a string"
            if isinstance(value, str):
                why = self.problem(value)
            if why:
                return Decision("deny", self.name, why)
        return ALLOW
