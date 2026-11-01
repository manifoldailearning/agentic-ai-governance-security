"""AI supply chain: AI-BOM, vetting and tool allowlist (ch. 19).

Record and sign what the agent is built from, detect drift
between the signed manifest and what is deployed, score
third-party tools before adoption, and refuse at runtime any
tool that is not in the signed manifest.
"""

from ags.supply.bom import (
    KINDS,
    Component,
    Finding,
    Manifest,
    SignedManifest,
    component,
    detect_drift,
    sha256,
    sign,
    tool_component,
    tool_definition,
    unpinned,
    verify,
)
from ags.supply.guard import ToolAllowlistGuard
from ags.supply.vetting import Issue, ToolProfile, Vetting, vet

__all__ = [
    "KINDS",
    "Component",
    "Finding",
    "Issue",
    "Manifest",
    "SignedManifest",
    "ToolAllowlistGuard",
    "ToolProfile",
    "Vetting",
    "component",
    "detect_drift",
    "sha256",
    "sign",
    "tool_component",
    "tool_definition",
    "unpinned",
    "verify",
    "vet",
]
