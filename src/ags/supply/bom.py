"""AI bill of materials: know exactly what the agent is made of.

An agent is a model, prompts, tools, tool servers, datasets
and libraries, each from somewhere and each able to change
under you. The AI-BOM records version, source, sha256,
license and owner for every component, signs the manifest,
and detects drift: content that no longer matches its hash,
versions that float, and components nobody declared.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass

from ags.core.types import ToolSpec

KINDS = (
    "model",
    "prompt",
    "tool",
    "tool-server",
    "dataset",
    "library",
)
FLOATING = re.compile(  # aliases, ranges and wildcards move
    r"^(|\*|latest|stable|main|master|head)$|[*^~<>=]|\.x$", re.I
)


def sha256(content: str | bytes) -> str:
    if isinstance(content, str):
        content = content.encode()
    return hashlib.sha256(content).hexdigest()


def tool_definition(spec: ToolSpec) -> str:
    """Canonical form of what a tool claims to do.

    The description is included: it is text the model reads,
    so a changed description can steer the model.
    """
    return json.dumps(
        {
            "name": spec.name,
            "effect": spec.effect,
            "risk": spec.risk,
            "labels": sorted(spec.labels),
            "description": spec.description,
        },
        sort_keys=True,
    )


@dataclass(frozen=True)
class Component:
    name: str
    kind: str
    version: str
    source: str
    sha256: str
    license: str
    owner: str

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown kind {self.kind!r}")


def component(
    name: str, kind: str, content: str | bytes, **meta: str
) -> Component:
    """Hash the content now; ``meta`` is version, source..."""
    return Component(name, kind, sha256=sha256(content), **meta)


def tool_component(spec: ToolSpec, **meta: str) -> Component:
    defn = tool_definition(spec)
    return component(spec.name, "tool", defn, **meta)


@dataclass(frozen=True)
class Manifest:
    system: str
    components: tuple[Component, ...]

    def __post_init__(self) -> None:
        names = [c.name for c in self.components]
        if len(names) != len(set(names)):
            raise ValueError("duplicate component names")

    def get(self, name: str) -> Component | None:
        return next(
            (c for c in self.components if c.name == name), None
        )

    def canonical(self) -> bytes:
        """Byte-stable form: what the signature covers."""
        parts = sorted(self.components, key=lambda c: c.name)
        doc = {
            "system": self.system,
            "components": [asdict(c) for c in parts],
        }
        text = json.dumps(
            doc, sort_keys=True, separators=(",", ":")
        )
        return text.encode()


@dataclass(frozen=True)
class SignedManifest:
    manifest: Manifest
    key_id: str
    signature: str

    def to_json(self) -> str:
        doc = json.loads(self.manifest.canonical())
        doc |= {
            "key_id": self.key_id,
            "signature": self.signature,
        }
        return json.dumps(doc, indent=1, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> SignedManifest:
        doc = json.loads(text)
        parts = tuple(Component(**c) for c in doc["components"])
        manifest = Manifest(doc["system"], parts)
        return cls(manifest, doc["key_id"], doc["signature"])


def sign(
    manifest: Manifest, key: bytes, key_id: str
) -> SignedManifest:
    """HMAC-SHA256 over the canonical manifest.

    A shared key means every verifier could also sign; real
    pipelines use asymmetric signatures in the same place.
    """
    mac = hmac.new(key, manifest.canonical(), hashlib.sha256)
    return SignedManifest(manifest, key_id, mac.hexdigest())


def verify(
    signed: SignedManifest, keys: Mapping[str, bytes]
) -> bool:
    """True only for a known key id and an untouched manifest."""
    key = keys.get(signed.key_id)
    if key is None:
        return False
    expected = sign(signed.manifest, key, signed.key_id)
    return hmac.compare_digest(
        expected.signature, signed.signature
    )


@dataclass(frozen=True)
class Finding:
    component: str
    issue: str  # unpinned | missing | hash-mismatch | undeclared
    detail: str = ""


def unpinned(manifest: Manifest) -> list[Finding]:
    return [
        Finding(c.name, "unpinned", f"version {c.version!r}")
        for c in manifest.components
        if FLOATING.search(c.version.strip())
    ]


def detect_drift(
    manifest: Manifest, observed: Mapping[str, str | bytes]
) -> list[Finding]:
    """Compare what is deployed with what was signed."""
    found = unpinned(manifest)
    for c in manifest.components:
        if c.name not in observed:
            found.append(Finding(c.name, "missing"))
            continue
        actual = sha256(observed[c.name])
        if actual != c.sha256:
            why = f"expected {c.sha256[:8]}, got {actual[:8]}"
            found.append(Finding(c.name, "hash-mismatch", why))
    declared = {c.name for c in manifest.components}
    for name in sorted(observed.keys() - declared):
        found.append(Finding(name, "undeclared"))
    return found
