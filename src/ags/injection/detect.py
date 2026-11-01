"""Score untrusted text for instruction-like content.

Indirect prompt injection hides instructions in data the
agent reads. The detector first undoes common disguises
(HTML entities, invisible characters, full-width letters,
look-alike letters, base64) and then scores the text against
known patterns. It is a speed bump, not a boundary: anyone
can phrase an instruction that no pattern anticipates.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass

INVISIBLE = re.compile(  # zero-width, bidi controls, tag chars
    "[\u00ad\u180e\u200b-\u200f\u202a-\u202e"
    "\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)
TAGS = re.compile("[\U000e0020-\U000e007e]")  # ASCII smuggling
HOMOGLYPHS = str.maketrans(  # Cyrillic/Greek look-alikes
    "\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456"
    "\u0455\u0458\u03bf\u03b1\u03b5\u03b9",
    "aeopcxyisjoaei",
)
BASE64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")

PATTERNS = {  # matched against the normalized text
    "override": r"\b(ignore|disregard|forget|override)\b"
    r"[^.\n]{0,40}\b(instructions?|rules|guidelines|prompts?)",
    "role": r"\b(you are now|act as an?|pretend to be|"
    r"developer mode|new instructions|system prompt)\b|"
    r"^\s*(system|assistant|developer)\s*:",
    "addressee": r"\b(assistant|ai|agent|model|bot)\s*[:,]",
    "tool_syntax": r"\baction\s*:\s*\w+\s*\{|"
    r"<\s*/?\s*(tool_call|function_call)\b",
    "hidden_html": r"<!--.*?-->|display\s*:\s*none",
    "exfil": r"\b(send|email|forward|post|upload)\b"
    r"[^.\n]{0,60}(https?://|@[\w-]+\.)",
}
COMPILED = {
    k: re.compile(v, re.M | re.S) for k, v in PATTERNS.items()
}
WEIGHTS = {  # evidence each signal adds to the score
    "tool_syntax": 0.7,
    "override": 0.6,
    "role": 0.5,
    "addressee": 0.3,
    "hidden_html": 0.3,
    "exfil": 0.3,
    "invisible": 0.3,  # evasion signals from normalize()
    "encoded": 0.3,
}


@dataclass(frozen=True)
class Finding:
    score: float
    signals: tuple[str, ...]
    suspicious: bool


def decoded_base64(text: str) -> list[str]:
    """Plain ASCII text hidden in base64-looking tokens."""
    found = []
    for token in BASE64.findall(text):
        token = token.replace("-", "+").replace("_", "/")
        try:
            raw = base64.b64decode(
                token + "=" * (-len(token) % 4), validate=True
            )
        except (binascii.Error, ValueError):
            continue
        if raw.isascii() and raw.decode().isprintable():
            found.append(raw.decode())
    return found


def normalize(text: str) -> tuple[str, set[str]]:
    """Canonical text to match on, plus evasion signals seen."""
    signals = set()
    if TAGS.search(text):
        signals.add("invisible")
    text = html.unescape(text)
    text = TAGS.sub(lambda m: chr(ord(m[0]) - 0xE0000), text)
    visible = INVISIBLE.sub("", text)
    if visible != text:
        signals.add("invisible")
    text = unicodedata.normalize("NFKC", visible)
    if hidden := decoded_base64(text):
        signals.add("encoded")
        text = "\n".join([text, *hidden])
    text = text.translate(HOMOGLYPHS).casefold()
    return re.sub(r"[ \t]+", " ", text), signals


@dataclass(frozen=True)
class Detector:
    threshold: float = 0.5

    def scan(self, text: str) -> Finding:
        norm, signals = normalize(text)
        for name, rx in COMPILED.items():
            if rx.search(norm):
                signals.add(name)
        total = sum(WEIGHTS[s] for s in signals)
        score = round(min(total, 1.0), 2)
        return Finding(
            score, tuple(sorted(signals)), score >= self.threshold
        )
