"""Chapter 2: threat-model the support agent from its specs.

The system model is derived from the same tool specs the
runtime enforces. The register ranks agent-specific threats
above generic STRIDE rows, shows the lethal trifecta, shows
how removing egress tools changes the picture, and then
confirms the top threat by running the real attack.
"""

from __future__ import annotations

import re
from collections import Counter

from ags.core import (
    EXFIL,
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.threat import from_specs, threat_register, trifecta

LEVELS = ("critical", "high", "medium", "low")
STORES = {  # data store -> tools that read it
    "crm-db": ("lookup_customer", "export_customers"),
    "wiki": ("read_doc",),
}


def summary(threats) -> str:
    n = Counter(t.severity for t in threats)
    return ", ".join(f"{n[s]} {s}" for s in LEVELS)


def chapters(text: str) -> str:
    return ",".join(re.findall(r"ch\d\d", text))


def confirm_top_threat() -> int:
    """Run the baseline attack; count leaked card numbers."""
    env, tools = build_env()
    model = ScriptedModel([call("read_inbox")], gullible=True)
    asha = Principal("asha", tenant="acme")
    Runtime(tools).run(asha, "Triage my support inbox", model)
    return sum(m["body"].count('"card"') for m in env.sent)


def main() -> None:
    _, tools = build_env()
    specs = [t.spec for t in tools]
    model = from_specs("support-agent", specs, STORES)
    threats = threat_register(model)
    edges = sum(model.crosses(f) for f in model.flows)
    print(f"System model: {model.name}, {len(specs)} tools")
    print(
        f"  {len(model.elements)} elements, {len(model.flows)}"
        f" flows, {edges} cross a trust boundary"
    )
    print(f"  {len(threats)} threats: {summary(threats)}")
    print("Lethal trifecta in one agent:")
    for leg, names in (trifecta(model) or {}).items():
        print(f"  {leg:<10} {', '.join(names)}")
    print("Top threats (id, score, category, target, fix):")
    for t in threats[:6]:
        fix = chapters(t.mitigation)
        print(
            f"  {t.id} {t.score} {t.category:<18}"
            f"{t.target:<14}{fix}"
        )
    egress = {"send_email", "fetch_url"}
    lean = [s for s in specs if s.name not in egress]
    split = from_specs("triage-agent", lean, STORES)
    print("Without send_email and fetch_url:")
    legs = "present" if trifecta(split) else "broken"
    print(f"  trifecta {legs}; {summary(threat_register(split))}")
    leaked = confirm_top_threat()
    top = threats[0]
    print(f"Runtime check: {top.id} ({top.category}) is real:")
    print(
        f"  inbox attack mailed {leaked} card numbers to {EXFIL}"
    )


if __name__ == "__main__":
    main()
