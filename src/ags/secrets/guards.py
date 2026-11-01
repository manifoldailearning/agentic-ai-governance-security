"""Guards that keep secrets out of tool calls and answers.

``SecretArgGuard`` denies a call whose arguments carry a
secret value, a credential-shaped string or a handle the
tool was not granted. ``SecretRedactor`` rewrites the final
answer, so a secret that reached the context still stays in.
"""

from __future__ import annotations

from ags.core.runtime import Context
from ags.core.types import Decision, ToolCall, ToolSpec
from ags.secrets.broker import HANDLE, SecretBroker, strings
from ags.secrets.scan import LeakScanner


def _rank(kind: str) -> tuple[int, str]:
    """Most specific evidence first: known, pattern, entropy."""
    order = ("known", "pattern", "entropy")
    return order.index(kind.split(":")[0]), kind


class SecretArgGuard:
    name = "secret-args"

    def __init__(
        self,
        scanner: LeakScanner,
        broker: SecretBroker | None = None,
    ) -> None:
        self.scanner = scanner
        self.broker = broker

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        tool = spec.name
        for path, text in strings(call.args):
            for secret in HANDLE.findall(text):
                if not self._granted(secret, tool):
                    why = f"handle {secret} not granted to {tool}"
                    return Decision("deny", self.name, why)
            visible = HANDLE.sub(" ", text)  # handles are fine
            if found := self.scanner.scan(visible):
                kinds = sorted({f.kind for f in found}, key=_rank)
                why = f"{path} carries {', '.join(kinds)}"
                return Decision("deny", self.name, why)
        return Decision("allow", self.name)

    def _granted(self, secret: str, tool: str) -> bool:
        return bool(
            self.broker and self.broker.granted(secret, tool)
        )


class SecretRedactor:
    name = "secret-redact"

    def __init__(self, scanner: LeakScanner) -> None:
        self.scanner = scanner

    def check_output(self, ctx: Context, text: str) -> Decision:
        found = self.scanner.scan(text)
        if not found:
            return Decision("allow", self.name)
        kinds = sorted({f.kind for f in found}, key=_rank)
        why = f"redacted {', '.join(kinds)}"  # kinds, not values
        clean = self.scanner.redact(text)
        return Decision("allow", self.name, why, text=clean)
