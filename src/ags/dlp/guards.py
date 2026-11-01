"""DLP at the two exits: tool calls going out, answers going back.

``OutboundGuard`` inspects outgoing email and URLs: bulk
personal data is denied anywhere, any personal data is denied
to domains outside the allowlist, and so are links that carry
data in their query string. ``DLPOutputGuard`` masks personal
data in the final answer, and blocks answers that hold many
records or embed a data-carrying image or link.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import getaddresses
from urllib.parse import unquote, urlsplit

from ags.core import ALLOW, Context, Decision, ToolCall, ToolSpec
from ags.dlp.detect import records, redact, scan

LINK = re.compile(
    r"\]\(\s*<?(https?://[^)\s>]+)"  # markdown link or image
    r"|(?:src|href)\s*=\s*[\"']?(https?://[^\"'\s>]+)",  # HTML
    re.I,
)
MASKING = {"card": "mask", "email": "mask", "phone": "mask"}
ROUTES = {  # tool -> (destination arg, content args)
    "send_email": ("to", ("subject", "body")),
    "fetch_url": ("url", ("url",)),
}


def domain_ok(domain: str, allow: tuple[str, ...]) -> bool:
    domain = domain.lower().rstrip(".")
    return any(
        domain == a or domain.endswith("." + a) for a in allow
    )


def destinations(value: str) -> list[str]:
    """Domains of every recipient, or the host of a URL."""
    if "://" in value:
        return [urlsplit(value).hostname or ""]
    pairs = getaddresses([value])
    return [addr.rpartition("@")[2] for _, addr in pairs] or [""]


def exfil_links(text: str, allow: tuple[str, ...]) -> list[str]:
    """Links to outside hosts that carry data in the URL."""
    found = []
    for groups in LINK.findall(text):
        url = next(g for g in groups if g)
        parts = urlsplit(url)
        if domain_ok(parts.hostname or "", allow):
            continue
        data = unquote(parts.path + "?" + parts.query)
        if scan(data) or len(parts.query) >= 24:
            found.append(url)
    return found


@dataclass
class OutboundGuard:
    allow: tuple[str, ...]  # domains that may receive pii
    max_records: int = 3
    routes: dict = field(default_factory=lambda: dict(ROUTES))
    name: str = "outbound_dlp"

    def problem(self, dest: str, content: str) -> str | None:
        found = scan(content)
        kinds = ", ".join(sorted({m.kind for m in found}))
        if (n := records(found)) >= self.max_records:
            return f"bulk personal data ({n} records: {kinds})"
        if links := exfil_links(content, self.allow):
            return f"data-carrying link {links[0][:40]}"
        outside = [
            d
            for d in destinations(dest)
            if not domain_ok(d, self.allow)
        ]
        if found and outside:
            return f"{kinds} to {outside[0] or 'unknown'}"
        return None

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        if call.name not in self.routes:
            return ALLOW
        dest_arg, content_args = self.routes[call.name]
        text = [str(call.args.get(a, "")) for a in content_args]
        dest = str(call.args.get(dest_arg, ""))
        if why := self.problem(dest, "\n".join(text)):
            return Decision("deny", self.name, why)
        return ALLOW


@dataclass
class DLPOutputGuard:
    policy: dict[str, str] = field(
        default_factory=lambda: dict(MASKING)
    )
    max_records: int = 3
    allow: tuple[str, ...] = ()  # hosts answers may link to
    name: str = "dlp_output"

    def check_output(self, ctx: Context, text: str) -> Decision:
        if links := exfil_links(text, self.allow):
            why = f"data-carrying link {links[0][:40]}"
            return Decision("deny", self.name, why)
        if (n := records(scan(text))) >= self.max_records:
            why = f"{n} records of personal data in the answer"
            return Decision("deny", self.name, why)
        clean = redact(text, self.policy)
        if clean == text:
            return ALLOW
        return Decision("allow", self.name, "masked", text=clean)
