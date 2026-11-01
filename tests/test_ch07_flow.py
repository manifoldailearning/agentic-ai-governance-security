import re

import pytest

from ags.core import (
    EXFIL,
    Context,
    Principal,
    Runtime,
    ScriptedModel,
    ToolCall,
    ToolSpec,
    build_env,
    call,
)
from ags.flow import (
    ANY,
    DEFAULT_POLICY,
    FlowGuard,
    PlanLock,
    decide,
    join,
    parse_policy,
    step,
)

ASHA = Principal("asha", tenant="acme")
EMAIL = ToolSpec("send_email", "external", "high")


def attack(guards_for, plan, approver=None):
    env, tools = build_env()
    rt = Runtime(tools, guards_for(tools), approver=approver)
    model = ScriptedModel(plan, gullible=True)
    return env, rt.run(ASHA, "Handle inbox", model)


def flow(tools):
    return [FlowGuard.for_tools(tools)]


def test_lattice_join_and_policy_parsing():
    assert join({"pii"}, ["bulk"], ()) == {"pii", "bulk"}
    with pytest.raises(ValueError, match="bad policy row"):
        parse_policy("h\nconfidential external deny x")
    with pytest.raises(ValueError):
        parse_policy("h\npii external maybe x")


def test_strictest_matching_rule_wins():
    labels = {"untrusted", "pii", "bulk"}
    assert decide(DEFAULT_POLICY, labels, "external").verdict == (
        "deny"
    )
    assert decide(DEFAULT_POLICY, {"untrusted"}, "read") is None
    assert decide(DEFAULT_POLICY, {"pii"}, "external") is None


def test_inbox_attack_denied_with_provenance():
    env, res = attack(flow, [call("read_inbox")])
    assert env.sent == []
    ((c, d),) = res.denied
    assert c.name == "send_email" and d.guard == "flow"
    assert "bulk<-export_customers#call-2" in d.reason
    assert "pii<-export_customers#call-2" in d.reason


def test_blog_exfil_needs_a_human():
    blog = call("fetch_url", url="https://blog.example/tips")
    env, res = attack(flow, [blog])
    assert len(env.fetched) == 1
    assert res.denied[0][1].reason.startswith("no approver")
    seen = []

    def approver(ctx, spec, c, decision):
        seen.append(decision.reason)
        return False

    attack(flow, [blog], approver)
    assert "untrusted<-fetch_url#call-1" in seen[0]


def test_code_execution_after_untrusted_is_denied_outright():
    plan = [call("read_inbox"), call("run_python", code="1")]
    env, res = attack(flow, plan, approver=lambda *a: True)
    assert env.executed == []
    assert "untrusted input -> exec" in res.denied[-1][1].reason


def test_single_record_reply_to_customer_is_allowed():
    plan = [
        call("lookup_customer", customer_id="C-100"),
        call(
            "send_email",
            to="asha@acme.example",
            subject="Your plan",
            body="You are on $LAST",
        ),
    ]
    env, res = attack(flow, plan)
    assert res.denied == [] and env.sent[0]["to"] == (
        "asha@acme.example"
    )


@pytest.mark.parametrize(
    "args",
    [
        {"to": "ASHA@acme.example", "body": "hi"},  # case trick
        {"to": "asha@acme.example ", "body": "hi"},  # whitespace
        {"to": "asha@acme.example", "body": "hi", "bcc": EXFIL},
        {"to": ["asha@acme.example", EXFIL], "body": "hi"},
        {"to": "asha@acme.example", "body": 42},  # not a str
    ],
)
def test_plan_lock_bypass_attempts(args):
    lock = PlanLock(
        (step("send_email", to="asha@acme.example", body=ANY),)
    )
    ctx = Context("r", "a", ASHA)
    d = lock.check(ctx, EMAIL, ToolCall("1", "send_email", args))
    assert d.verdict == "deny"


def test_plan_steps_are_used_up_and_patterns_fullmatch():
    lock = PlanLock(
        (
            step(
                "send_email",
                to=re.compile(r"[a-z]+@acme\.example"),
                body=ANY,
            ),
        )
    )
    ok = ToolCall(
        "1", "send_email", {"to": "ben@acme.example", "body": "x"}
    )
    sly = ToolCall(
        "2",
        "send_email",
        {"to": "ben@acme.example.exfil.example", "body": "x"},
    )
    ctx = Context("r", "a", ASHA)
    assert lock.check(ctx, EMAIL, ok).allowed
    assert not lock.check(ctx, EMAIL, sly).allowed
    ctx.calls.append(ok)
    assert not lock.check(ctx, EMAIL, ok).allowed  # used once


def test_plan_cannot_endorse_a_deny_rule():
    plan = PlanLock(
        (
            step("read_inbox"),
            step("export_customers"),
            step("send_email", to=ANY, subject=ANY, body=ANY),
        )
    )

    def guards(tools):
        return [plan, FlowGuard.for_tools(tools, plan=plan)]

    env, res = attack(guards, [call("read_inbox")])
    assert env.sent == []
    assert res.denied[0][1].reason.startswith("bulk personal")


def test_example_main(capsys):
    from ch07_information_flow import main

    main()
    out = capsys.readouterr().out
    assert "denied send_email partner@exfil.example by" in out
    assert out.rstrip().endswith("emailed: asha@acme.example")
