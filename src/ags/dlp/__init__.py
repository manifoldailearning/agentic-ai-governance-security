"""Chapter 9: data loss prevention for agent traffic.

Detect personal data and secrets in what the agent sends out
and in what it answers, mask what may be shown, and deny
bulk or off-domain transfers. DLP is a backstop for the
flow controls of chapter 7, not a replacement for them.
"""

from ags.dlp.detect import (
    Match,
    find,
    luhn,
    mask,
    normalize,
    records,
    redact,
    scan,
)
from ags.dlp.guards import (
    DLPOutputGuard,
    OutboundGuard,
    destinations,
    exfil_links,
)

__all__ = [
    "DLPOutputGuard",
    "Match",
    "OutboundGuard",
    "destinations",
    "exfil_links",
    "find",
    "luhn",
    "mask",
    "normalize",
    "records",
    "redact",
    "scan",
]
