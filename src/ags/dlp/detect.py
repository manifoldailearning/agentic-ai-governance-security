"""Find personal data and secrets in text, and mask them.

Detectors for email, phone, payment card (Luhn-checked),
national-id-shaped numbers and credentials. Text is first
normalized (NFKC, invisible characters removed) and also
scanned in decoded views (percent, HTML and base64), so the
easy disguises fail. Pattern DLP still misses data that is
paraphrased, spelled out or split across messages.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from urllib.parse import unquote

INVISIBLE = re.compile("[\u00ad\u200b-\u200f\u2060-\u2064\ufeff]")
B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
DETECTORS = {  # earlier kinds claim overlapping text first
    "secret": r"\b(?:sk|api|key|tok)[-_][\w-]{16,}|"
    r"\bAKIA[0-9A-Z]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY",
    "email": r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+",
    "card": r"(?<!\d)(?:\d[ .-]?){12,18}\d(?!\d)",
    "national_id": r"\b\d{3}-\d{2}-\d{4}\b",
    "phone": r"(?<![\w+])\+?\d[\d ().-]{6,}\d(?!\d)",
}
COMPILED = {k: re.compile(rx) for k, rx in DETECTORS.items()}


@dataclass(frozen=True)
class Match:
    kind: str
    value: str
    start: int
    end: int


def digits(text: str) -> str:
    return re.sub(r"\D", "", text)


def luhn(number: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def plausible(kind: str, value: str) -> bool:
    n = digits(value)
    if kind == "card":
        return luhn(n)
    if kind == "phone":  # +E.164, or a 10-12 digit local number
        if value.startswith("+"):
            return 8 <= len(n) <= 15
        return 10 <= len(n) <= 12
    return True


def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", INVISIBLE.sub("", text))


def find(text: str) -> list[Match]:
    """Non-overlapping matches in already-normalized text."""
    found: list[Match] = []
    for kind, rx in COMPILED.items():
        for m in rx.finditer(text):
            clash = any(
                m.start() < f.end and f.start < m.end()
                for f in found
            )
            if not clash and plausible(kind, m.group()):
                found.append(Match(kind, m.group(), *m.span()))
    return sorted(found, key=lambda m: m.start)


def views(text: str) -> list[str]:
    """The text plus its percent, HTML and base64 decodings."""
    text = normalize(text)
    out = [text, unquote(text), html.unescape(text)]
    for token in B64.findall(text):
        try:
            raw = base64.b64decode(token, validate=True)
            out.append(normalize(raw.decode("utf-8")))
        except (binascii.Error, ValueError):
            continue
    return out


def scan(text: str) -> list[Match]:
    """Distinct findings across every decoded view."""
    seen: dict[tuple[str, str], Match] = {}
    for view in views(text):
        for m in find(view):
            numeric = m.kind in ("card", "phone", "national_id")
            key = (
                m.kind,
                digits(m.value) if numeric else m.value,
            )
            seen.setdefault(key, m)
    return list(seen.values())


def records(found: list[Match]) -> int:
    """Rough record count: most values of any one kind."""
    counts = Counter(m.kind for m in found if m.kind != "secret")
    return max(counts.values(), default=0)


def mask(m: Match) -> str:
    if m.kind == "card":
        return "**** **** **** " + digits(m.value)[-4:]
    if m.kind == "email":
        user, _, domain = m.value.partition("@")
        return f"{user[0]}***@{domain}"
    if m.kind == "phone":
        return "*** " + digits(m.value)[-2:]
    return f"[{m.kind}]"


def redact(text: str, policy: dict[str, str]) -> str:
    """Apply mask | redact | allow per kind; redact by default."""
    text, out, pos = normalize(text), [], 0
    for m in find(text):
        action = policy.get(m.kind, "redact")
        if action == "allow":
            continue
        shown = mask(m) if action == "mask" else f"[{m.kind}]"
        out += [text[pos : m.start], shown]
        pos = m.end
    return "".join(out) + text[pos:]
