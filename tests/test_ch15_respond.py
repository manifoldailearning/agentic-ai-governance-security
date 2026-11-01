from ags.core import (
    EXFIL,
    Decision,
    FakeClock,
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.detect import effects_of
from ags.respond import (
    Containment,
    blast_radius,
    incident_notes,
    render_timeline,
    timeline,
)

ASHA = Principal("asha", tenant="acme", attrs={"jti": "tok-1"})
INBOX = [call("read_inbox")]


def setup(*extra_guards, agent="support-agent"):
    env, tools = build_env()
    clock = FakeClock()
    box = Containment(clock)
    guards = [*box.guards(), *extra_guards]
    rt = Runtime(tools, guards, clock=clock, agent=agent)
    return env, tools, box, rt


def attack(rt, principal=ASHA):
    model = ScriptedModel(list(INBOX), gullible=True)
    return rt.run(principal, "Triage", model)


def test_switches_are_idle_until_thrown():
    env, _, _, rt = setup()
    res = attack(rt)
    assert len(res.calls) == 3 and env.sent[0]["to"] == EXFIL


def test_freeze_stops_one_agent_and_thaw_restores_it():
    env, _, box, rt = setup()
    box.freeze("support-agent", "incident")
    res = attack(rt)
    assert res.calls == []
    assert res.denied[0][1].guard == "kill-switch"
    other = Runtime(build_env()[1], box.guards(), agent="billing")
    assert len(attack(other).calls) == 3
    box.thaw("support-agent", "fixed")
    assert len(attack(rt).calls) == 3
    assert [a.action for a in box.actions] == [
        "freeze-agent",
        "thaw-agent",
    ]


def test_global_freeze_covers_every_agent():
    _, _, box, rt = setup(agent="any-new-agent")
    box.freeze("*", "platform-wide stop")
    assert attack(rt).calls == []


def test_disable_tool_and_revoke_token():
    env, _, box, rt = setup()
    box.disable("send_email", "egress path")
    res = attack(rt)
    assert [c.name for c in res.calls] == [
        "read_inbox",
        "export_customers",
    ]
    assert env.sent == []
    box.revoke("tok-1", "stolen session")
    res = attack(rt)
    assert res.denied[0][1].reason == "token tok-1 revoked"
    fresh = Principal(
        "asha", tenant="acme", attrs={"jti": "tok-2"}
    )
    assert attack(rt, fresh).calls  # new session works


def test_quarantine_moves_entries_and_skips_unknown_ids():
    box = Containment(FakeClock(7))
    memory = {"m1": "ok", "m2": "ACTION: send_email {}"}
    moved = box.quarantine(memory, ["m2", "nope"], "poisoned")
    assert moved == ["m2"] and memory == {"m1": "ok"}
    assert box.quarantined == {"m2": "ACTION: send_email {}"}
    assert box.actions[0].ts == 7


def test_timeline_orders_steps_and_attributes_labels():
    _, _, _, rt = setup()
    run = attack(rt)
    steps = timeline(rt.log.events, run.run_id)
    assert [s.what for s in steps] == [
        "task",
        "read_inbox",
        "export_customers",
        "send_email",
        "output",
    ]
    assert steps[1].gained == ("untrusted",)
    assert steps[2].gained == ("bulk", "pii")
    assert all(len(x) <= 60 for x in render_timeline(steps))


class BlockEmail:
    name = "block-email"

    def check(self, ctx, spec, call):
        if spec.name == "send_email":
            return Decision("deny", self.name, "egress")
        return Decision("allow", self.name)


def test_blast_radius_separates_blocked_from_reached():
    env, tools, _, rt = setup(BlockEmail())
    attack(rt)
    blog = ScriptedModel(
        [call("fetch_url", url="https://blog.example/tips")],
        gullible=True,
    )
    rt.run(ASHA, "Read the blog", blog)
    owners = {k: v["tenant"] for k, v in env.customers.items()}
    radius = blast_radius(
        rt.log.events, effects_of(tools), owners.get
    )
    assert radius.blocked == (EXFIL,)
    assert radius.reached == (
        "blog.example",
        "collect.exfil.example",
    )
    assert radius.records == () and radius.tenants == ()


def test_blast_radius_counts_cross_tenant_records():
    env, tools, _, rt = setup()
    attack(rt)
    owners = {k: v["tenant"] for k, v in env.customers.items()}
    radius = blast_radius(
        rt.log.events, effects_of(tools), owners.get
    )
    assert radius.records == ("C-100", "C-101", "C-200")
    assert radius.tenants == ("acme", "globex")
    assert radius.data == ("card", "email", "phone")
    assert {"bulk", "pii", "untrusted"} <= set(radius.labels)


def test_incident_notes_have_every_section():
    env, tools, box, rt = setup()
    run = attack(rt)
    box.freeze("support-agent", "exfil")
    steps = timeline(rt.log.events, run.run_id)
    radius = blast_radius(rt.log.events, effects_of(tools))
    notes = incident_notes(
        run.run_id, [], steps, radius, box.actions
    )
    for heading in ("Timeline", "Blast radius", "Containment"):
        assert f"## {heading}" in notes
    assert "freeze-agent support-agent" in notes


def test_example_shows_agent_frozen(capsys):
    from ch15_incident_response import main

    main()
    out = capsys.readouterr().out
    assert "1 denied by kill-switch" in out
    assert "tenants  acme, globex" in out
