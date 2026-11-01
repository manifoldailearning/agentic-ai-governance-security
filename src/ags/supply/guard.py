"""Only tools in a verified, signed manifest may run.

Tool servers can add tools or quietly change what an
approved tool does after review. ``ToolAllowlistGuard``
fails closed: with a bad signature nothing runs, an unlisted
tool is denied, and a tool whose definition (effect, risk,
labels) no longer matches its signed hash is denied.
"""

from __future__ import annotations

from collections.abc import Mapping

from ags.core.runtime import Context
from ags.core.types import ALLOW, Decision, ToolCall, ToolSpec
from ags.supply.bom import (
    SignedManifest,
    sha256,
    tool_definition,
    verify,
)


class ToolAllowlistGuard:
    name = "tool-allowlist"

    def __init__(
        self, signed: SignedManifest, keys: Mapping[str, bytes]
    ) -> None:
        self.trusted = verify(signed, keys)
        self.tools = {
            c.name: c.sha256
            for c in signed.manifest.components
            if c.kind == "tool"
        }

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        if not self.trusted:
            return self._deny("manifest signature invalid")
        expected = self.tools.get(spec.name)
        if expected is None:
            return self._deny("not in signed manifest")
        if sha256(tool_definition(spec)) != expected:
            return self._deny("definition changed since signing")
        return ALLOW

    def _deny(self, reason: str) -> Decision:
        return Decision("deny", self.name, reason)
