"""Leak scanning: find secrets in text before it leaves.

Three detectors: known secret values from the broker (with
common encodings), credential-shaped patterns, and high-
entropy tokens. Scanning is a backstop, not the boundary:
it misses split or re-encoded secrets. The real control is
that an agent which never sees a secret cannot leak it.
"""

from __future__ import annotations

import base64
import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

PATTERNS = {
    "private-key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "bearer-token": r"(?i)\bbearer\s+[\w.~+/-]{16,}=*",
    "key-assignment": r"(?i)\b(?:api[_-]?key|secret|token|"
    r"passw(?:or)?d)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
    "prefixed-key": r"\b[a-z]{2,8}_(?:live|test|prod)_\w{12,}",
    "jwt-like": r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}",
}
TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


@dataclass(frozen=True)
class Finding:
    kind: str  # known:<label> | pattern:<name> | entropy
    start: int
    end: int  # spans only: findings never hold the secret


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    n = len(text)
    probs = [c / n for c in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)


def _mixed(token: str) -> bool:
    """Letters and digits: skips long words and long numbers."""
    has_digit = any(c.isdigit() for c in token)
    return has_digit and any(c.isalpha() for c in token)


def variants(value: str) -> set[str]:
    """The value plus the encodings a model might produce."""
    raw = value.encode()
    return {
        value,
        base64.b64encode(raw).decode().rstrip("="),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
        raw.hex(),
    }


class LeakScanner:
    def __init__(
        self,
        known: Callable[[], dict[str, str]] = dict,
        min_entropy: float = 3.5,
    ) -> None:
        self.known = known  # () -> {value: label}, read live
        self.min_entropy = min_entropy
        self.patterns = {
            k: re.compile(p) for k, p in PATTERNS.items()
        }

    def scan(self, text: str) -> list[Finding]:
        found = self._known(text) + self._patterns(text)
        found += self._entropy(text)
        return sorted(found, key=lambda f: (f.start, -f.end))

    def _known(self, text: str) -> list[Finding]:
        out = []
        for value, label in self.known().items():
            kind = f"known:{label}"
            for v in variants(value):  # case tricks fail too
                spans = re.finditer(re.escape(v), text, re.I)
                out += [Finding(kind, *m.span()) for m in spans]
        return out

    def _patterns(self, text: str) -> list[Finding]:
        return [
            Finding(f"pattern:{name}", *m.span())
            for name, rx in self.patterns.items()
            for m in rx.finditer(text)
        ]

    def _entropy(self, text: str) -> list[Finding]:
        out = []
        for m in TOKEN.finditer(text):
            tok = m.group()
            if _mixed(tok) and entropy(tok) >= self.min_entropy:
                out.append(Finding("entropy", *m.span()))
        return out

    def redact(self, text: str) -> str:
        """Replace every finding; overlapping spans merge."""
        out, pos = [], 0
        for f in self.scan(text):
            if f.start < pos:  # inside a span already redacted
                pos = max(pos, f.end)
                continue
            out += [text[pos : f.start], f"[REDACTED:{f.kind}]"]
            pos = f.end
        return "".join(out) + text[pos:]
