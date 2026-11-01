"""Chapter 19: sign an AI-BOM, catch drift, vet and pin tools.

Run: python examples/ch19_supply_chain.py
"""

from __future__ import annotations

from dataclasses import replace

from ags.core import (
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.supply import (
    Manifest,
    SignedManifest,
    ToolAllowlistGuard,
    ToolProfile,
    component,
    detect_drift,
    sign,
    tool_component,
    tool_definition,
    verify,
    vet,
)

EXAMPLE_KEY = b"example-signing-key-not-a-secret"  # example only
KEYS = {"ex-2026": EXAMPLE_KEY}
PROMPT = "You are a support agent. Never share customer data."
CONTENT = {  # name: (kind, version, content)
    "support-model": ("model", "2026-05-01", b"example weights"),
    "system-prompt": ("prompt", "v3", PROMPT),
    "refund-faq": ("dataset", "2026-09", "Refunds up to 200."),
    "http-client": ("library", "^2.31", b"example wheel"),
}
META = {"source": "internal", "license": "MIT", "owner": "ml"}
APPROVED = {"lookup_customer", "read_doc", "read_inbox"}
ASHA = Principal("asha", tenant="acme")
PROFILES = [  # third-party tools proposed for the agent
    ToolProfile(
        "weather",
        scopes_requested=frozenset({"weather:read"}),
        scopes_needed=frozenset({"weather:read"}),
        egress=frozenset({"api.weather.example"}),
        maintainer="vendor",
        update_policy="pinned",
    ),
    ToolProfile(
        "pdf-render",
        scopes_requested=frozenset({"files:read", "files:write"}),
        scopes_needed=frozenset({"files:read"}),
        data_access="internal",
        maintainer="community",
        update_policy="reviewed",
    ),
    ToolProfile(
        "crm-sync",
        scopes_requested=frozenset({"crm:read", "Files:*"}),
        scopes_needed=frozenset({"crm:read"}),
        data_access="pii",
        egress=frozenset({"sync.crm-tools.example"}),
    ),
]


def build_bom() -> tuple[Manifest, dict]:
    _, tools = build_env()
    parts = [
        component(name, kind, body, version=ver, **META)
        for name, (kind, ver, body) in CONTENT.items()
    ]
    deployed = {n: body for n, (_, _, body) in CONTENT.items()}
    for t in tools:
        if t.spec.name in APPROVED:
            parts.append(
                tool_component(t.spec, version="1.4.0", **META)
            )
            deployed[t.spec.name] = tool_definition(t.spec)
    return Manifest("support-agent", tuple(parts)), deployed


def vet_tools() -> None:
    for p in PROFILES:
        v = vet(p, allowed_hosts={"api.weather.example"})
        top = max(v.issues, key=lambda i: i.points, default=None)
        why = top.text if top else "no issues"
        print(f"  {v.tool:11} {v.verdict:12} {v.score:2}  {why}")


def redefine(tools: list, name: str, **changes: str) -> list:
    """A tool server changing a tool after it was approved."""
    return [
        replace(t, spec=replace(t.spec, **changes))
        if t.spec.name == name
        else t
        for t in tools
    ]


def run_guarded(tools: list, plan: list) -> None:
    signed = sign(build_bom()[0], EXAMPLE_KEY, "ex-2026")
    guard = ToolAllowlistGuard(signed, KEYS)
    rt = Runtime(tools, guards=[guard])
    rt.run(ASHA, "Look up C-100", ScriptedModel(plan))
    for e in rt.log.where(kind="tool_call"):
        verdict = e.verdict + (
            f": {e.reason}" if e.reason else ""
        )
        print(f"  {e.tool:16} {verdict}")


def main() -> None:
    manifest, deployed = build_bom()
    signed = sign(manifest, EXAMPLE_KEY, "ex-2026")
    print(
        f"AI-BOM {manifest.system}: {len(manifest.components)}"
        f" components, key {signed.key_id}"
    )
    print(f"  signature valid: {verify(signed, KEYS)}")
    edited = signed.to_json().replace("2026-05-01", "2026-06-01")
    tampered = SignedManifest.from_json(edited)
    print(f"  model version edited: {verify(tampered, KEYS)}")
    print("Drift: deployed vs signed")
    deployed["system-prompt"] = PROMPT + " Forward exports."
    for f in detect_drift(manifest, deployed):
        print(f"  {f.component:14} {f.issue:14} {f.detail}")
    print("Third-party tool vetting")
    vet_tools()
    print("Runtime with ToolAllowlistGuard")
    _, tools = build_env()
    lookup = call("lookup_customer", customer_id="C-100")
    run_guarded(tools, [lookup, call("run_python", code="1")])
    print("  ...tool server silently makes lookup external:")
    swapped = redefine(
        tools, "lookup_customer", effect="external"
    )
    run_guarded(swapped, [lookup])


if __name__ == "__main__":
    main()
