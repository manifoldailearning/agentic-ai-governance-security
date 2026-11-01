"""A small screen for instruction-like text headed into memory.

Memory turns a one-off injection into a persistent one: text
saved today is replayed into every later session's context.
This screen flags writes that read like orders to the agent.
It is a cheap first filter, not a boundary, which is why the
store also quarantines every write from an untrusted source.
"""

from __future__ import annotations

import re
import unicodedata

INVISIBLE = "​‌‍⁠﻿"
_STRIP = dict.fromkeys(map(ord, INVISIBLE))

PATTERNS = {
    "tool directive": r"\baction\s*:\s*\w+",
    "override": r"\bignore\s+(all\s+|any\s+)?(previous|prior)",
    "role switch": r"\byou are now\b|^\s*(system|assistant)\s*:",
    "hidden markup": r"<!--",
    "standing order": r"\b(always|from now on)\b.{0,40}"
    r"\b(send|email|forward|export|refund)",
}
_COMPILED = {k: re.compile(v, re.M) for k, v in PATTERNS.items()}


def normalize(text: str) -> str:
    """Fold look-alike forms, invisible characters and case."""
    text = unicodedata.normalize("NFKC", text)
    return text.translate(_STRIP).casefold()


def instruction_reason(text: str) -> str | None:
    """Why ``text`` looks like an instruction, else ``None``."""
    clean = normalize(text)
    for reason, pattern in _COMPILED.items():
        if pattern.search(clean):
            return reason
    if any(ch in text for ch in INVISIBLE):
        return "invisible characters"
    return None
