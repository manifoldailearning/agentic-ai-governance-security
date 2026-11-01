"""Egress control: where may the agent send a request?

An injected instruction usually ends in an outbound request
that carries data away. ``EgressGuard`` allows only https to
listed hosts, and rejects the usual tricks: userinfo before
the host, IP literals in any notation, unusual ports, raw
pasted data in the URL, and long or high-entropy queries.
Small, slow leaks to an allowed host still get through.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from ags.core import ALLOW, Context, Decision, ToolCall, ToolSpec

RAW = re.compile(r"[^\x21-\x7e]|[\"'<>\\^`{|}]|\$\{?\w")
NUMERIC_HOST = re.compile(
    r"(0x[0-9a-f]*|\d+)(\.(0x[0-9a-f]*|\d+))*"
)


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    n = len(text)
    probs = [c / n for c in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)


def host_allowed(host: str, allow: tuple[str, ...]) -> bool:
    """Exact host, or "*.example.com" for its subdomains."""
    for entry in map(str.lower, allow):
        if entry.startswith("*."):
            if host.endswith(entry[1:]):
                return True
        elif host == entry:
            return True
    return False


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:  # 2130706433, 0x7f.1, 0177.0.0.1 too
        return bool(NUMERIC_HOST.fullmatch(host))


@dataclass
class EgressGuard:
    allow: tuple[str, ...]
    url_args: tuple[str, ...] = ("url",)
    max_query: int = 64
    max_entropy: float = 3.8  # for query values >= 20 chars
    name: str = "egress"

    def problem(self, url: str) -> str | None:
        if RAW.search(url):
            return "raw data or a placeholder in the URL"
        parts = urlsplit(url)
        if parts.scheme != "https":
            return f"scheme {parts.scheme or 'missing'!r}"
        if "@" in parts.netloc:
            return "userinfo before the host"
        try:
            port = parts.port
        except ValueError:
            return "invalid port"
        if port not in (None, 443):
            return f"port {port}"
        why = self.host_problem(parts.hostname or "")
        return why or self.query_problem(
            parts.query + parts.fragment
        )

    def host_problem(self, host: str) -> str | None:
        host = host.rstrip(".")
        if is_ip_literal(host):
            return f"IP literal host {host}"
        if not host_allowed(host, self.allow):
            return f"{host} not allowlisted"
        return None

    def query_problem(self, query: str) -> str | None:
        if len(query) > self.max_query:
            return f"query of {len(query)} chars"
        for value in re.split(r"[&=;]", unquote(query)):
            if len(value) < 20:
                continue  # too short for entropy to mean much
            if entropy(value) > self.max_entropy:
                return "high-entropy query value"
        return None

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        for arg in self.url_args:
            if arg in call.args:
                why = self.problem(str(call.args[arg]))
                if why:
                    return Decision("deny", self.name, why)
        return ALLOW
