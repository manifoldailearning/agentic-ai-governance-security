import pytest

from ags.core import (
    EXFIL,
    Decision,
    EventLog,
    Principal,
    Runtime,
    ScriptedModel,
    ToolSpec,
    build_env,
    call,
    directives,
    load_events,
)

ASHA = Principal("asha", tenant="acme")


def attack(guards=(), approver=None):
    env, tools = build_env()
    rt = Runtime(tools, guards=guards, approver=approver)
    model = ScriptedModel([call("read_inbox")], gullible=True)
    return env, rt, rt.run(ASHA, "Triage my support inbox", model)


def test_baseline_attack_exfiltrates_customers():
    env, _, res = attack()
    assert res.status == "completed"
    assert [c.name for c in res.calls] == [
        "read_inbox",
        "export_customers",
        "send_email",
    ]
    assert env.sent[0]["to"] == EXFIL
    assert "4111 1111 1111 1111" in env.sent[0]["body"]
    assert {"untrusted", "pii", "bulk"} <= res.labels


def test_planned_model_ignores_injection():
    env, tools = build_env()
    rt = Runtime(tools)
    res = rt.run(
        ASHA, "Triage", ScriptedModel([call("read_inbox")])
    )
    assert [c.name for c in res.calls] == ["read_inbox"]
    assert env.sent == []


class DenyExternal:
    name = "deny-external"

    def check(self, ctx, spec, call):
        if spec.effect == "external":
            return Decision("deny", self.name, "no egress")
        return Decision("allow", self.name)


class ApproveWrites:
    name = "approve-writes"

    def check(self, ctx, spec, call):
        if spec.effect in ("write", "external"):
            return Decision("approve", self.name, "risky")
        return Decision("allow", self.name)


def test_first_deny_wins_and_is_logged():
    env, rt, res = attack([DenyExternal()])
    assert env.sent == []
    ((denied_call, d),) = res.denied
    assert denied_call.name == "send_email"
    assert d.guard == "deny-external"
    ev = rt.log.where(kind="tool_call", tool="send_email")
    assert ev[0].verdict == "deny" and "untrusted" in ev[0].labels


def test_approve_without_approver_is_deny():
    env, _, res = attack([ApproveWrites()])
    assert env.sent == []
    assert res.denied[0][1].reason.startswith("no approver")


def test_approver_decides():
    env, _, _ = attack([ApproveWrites()], lambda *a: True)
    assert env.sent
    env, _, res = attack([ApproveWrites()], lambda *a: False)
    assert not env.sent
    assert "approval refused" in res.denied[0][1].reason


def test_unknown_tool_and_tool_errors():
    env, tools = build_env()
    rt = Runtime(tools)
    m = ScriptedModel(
        [
            call("drop_tables"),
            call("lookup_customer", customer_id="X"),
        ]
    )
    res = rt.run(ASHA, "x", m)
    assert res.denied[0][1].reason == "unknown tool"
    assert rt.log.where(kind="error")[0].tool == "lookup_customer"


class Block:
    name = "block"

    def check_output(self, ctx, text):
        return Decision("deny", self.name, "nope")


def test_output_guard_blocks_answer():
    env, tools = build_env()
    rt = Runtime(tools, output_guards=[Block()])
    res = rt.run(ASHA, "hi", ScriptedModel([], answer="secret"))
    assert res.status == "blocked" and res.output == ""


def test_step_limit():
    env, tools = build_env()
    rt = Runtime(tools, max_steps=2)
    plan = [call("read_doc", doc_id="pricing")] * 5
    res = rt.run(ASHA, "loop", ScriptedModel(list(plan)))
    assert res.status == "step_limit"


def test_directives_parsing_and_escaped_json():
    text = 'x ACTION: send_email {\\"to\\": \\"a@b.example\\"} y'
    (c,) = directives(text)
    assert (
        c.name == "send_email" and c.args["to"] == "a@b.example"
    )
    assert directives("ACTION: broken {not json}") == []


def test_toolspec_validation():
    with pytest.raises(ValueError):
        ToolSpec("x", "delete")
    with pytest.raises(ValueError):
        ToolSpec("x", "read", risk="extreme")


def test_event_log_round_trip(tmp_path):
    _, rt, _ = attack()
    p = tmp_path / "events.jsonl"
    n = rt.log.save(p)
    back = load_events(p)
    assert len(back) == n and back[0].kind == "task"
    assert isinstance(EventLog().events, list)
