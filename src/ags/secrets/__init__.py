"""Secrets for agents (chapter 5).

A broker that hands credentials to tools by handle so the
model never sees them, rotation, leak scanning, and guards
that stop secrets in tool arguments and final answers.
"""

from ags.secrets.broker import (
    HANDLE,
    SecretBroker,
    SecretError,
    handle,
    strings,
    walk,
)
from ags.secrets.guards import SecretArgGuard, SecretRedactor
from ags.secrets.scan import (
    Finding,
    LeakScanner,
    entropy,
    variants,
)

__all__ = [
    "HANDLE",
    "Finding",
    "LeakScanner",
    "SecretArgGuard",
    "SecretBroker",
    "SecretError",
    "SecretRedactor",
    "entropy",
    "handle",
    "strings",
    "variants",
    "walk",
]
