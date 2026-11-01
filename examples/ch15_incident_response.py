"""Chapter 15: detect, contain, investigate, recover.

Replay the inbox attack against an agent whose containment
switches are wired in but idle. Detection fires on the
event stream; the responder freezes the agent, disables the
email tool and revokes the user's token. The timeline and
blast radius come from the logged events, and a second run
of the same attack is stopped by the kill switch.
"""

from __future__ import annotations

from ags.core import (
    EXFIL,
    FakeClock,
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.detect import (
    BulkPiiEgress,
    SensitiveAfterUntrusted,
    detect,
    effects_of,
)
from ags.respond import (
    Containment,
    blast_radius,
    incident_notes,
    render_timeline,
    timeline,
)

TOKEN = "tok-asha-0001"  # example delegation token id
ASHA = Principal("asha", tenant="acme", attrs={"jti": TOKEN})
TASK = "Triage my support inbox"


def attack(rt: Runtime):
    model = ScriptedModel([call("read_inbox")], gullible=True)
    return rt.run(ASHA, TASK, model)


def main() -> None:
    env, tools = build_env()
    clock = FakeClock()
    box = Containment(clock)
    rt = Runtime(tools, box.guards(), clock=clock)
    run = attack(rt)
    leaks = sum(m["to"] == EXFIL for m in env.sent)
    print(f"{run.run_id}: {leaks} email to {EXFIL}")

    effects = effects_of(tools)
    rules = [
        SensitiveAfterUntrusted(effects),
        BulkPiiEgress(effects),
    ]
    alerts = detect(rt.log.events, rules)
    for a in alerts:
        print(f"  ALERT {a.severity:<8} {a.rule}")

    box.freeze("support-agent", "exfiltration in " + run.run_id)
    box.disable("send_email", "egress path of the incident")
    box.revoke(TOKEN, "session used in the incident")
    print("Contained:")
    for act in box.actions:
        print(f"  {act.action:<13} {act.target}")

    steps = timeline(rt.log.events, run.run_id)
    print(f"Timeline {run.run_id}:")
    for line in render_timeline(steps):
        print(" ", line)

    def tenant_of(cid: str) -> str | None:
        return env.customers.get(cid, {}).get("tenant")

    radius = blast_radius(rt.log.events, effects, tenant_of)
    print("Blast radius:")
    print("  reached ", ", ".join(radius.reached))
    print("  records ", ", ".join(radius.records))
    print("  tenants ", ", ".join(radius.tenants), "(user: acme)")
    print("  data    ", ", ".join(radius.data))

    again = attack(rt)
    guard = again.denied[0][1].guard
    n_run, n_denied = len(again.calls), len(again.denied)
    print(f"Replay {again.run_id}: {n_run} calls run,", end=" ")
    print(f"{n_denied} denied by {guard}")
    after = sum(m["to"] == EXFIL for m in env.sent)
    print(f"Emails to {EXFIL}: still {after}")
    notes = incident_notes(
        run.run_id, alerts, steps, radius, box.actions
    )
    lines = len(notes.splitlines())
    print(f"Incident notes: {lines} lines drafted")


if __name__ == "__main__":
    main()
