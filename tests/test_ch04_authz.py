from __future__ import annotations

import pytest

import ch04_authorization as ch04
from ags.authz import (
    AuthzGuard,
    PolicyDecisionPoint,
    Rule,
    TenantGuard,
    cmp,
)
from ags.core import (
    Context,
    Principal,
    Runtime,
    ScriptedModel,
    ToolCall,
    ToolSpec,
    build_env,
    call,
)

ASHA = Principal(
    "asha", tenant="acme", roles=frozenset({"support"})
)
REFUND = ToolSpec("issue_refund", "write", "high")
CTX = Context("r", "support-agent", ASHA)


def refund(amount) -> ToolCall:
    return ToolCall("c", "issue_refund", {"amount": amount})


def test_default_deny_when_nothing_matches():
    e = PolicyDecisionPoint([]).explain(CTX, REFUND, refund(10))
    assert e.verdict == "deny" and e.rule is None
    assert "default deny" in str(e)


def test_deny_overrides_and_explain_lists_matches():
    pdp = PolicyDecisionPoint(
        [
            Rule("all-write", "allow", effects={"write"}),
            Rule(
                "big",
                "approve",
                when=(cmp("args.amount", ">", 5),),
            ),
            Rule("freeze", "deny", tools={"issue_refund"}),
        ]
    )
    e = pdp.explain(CTX, REFUND, refund(10))
    assert (e.verdict, e.rule.id) == ("deny", "freeze")
    assert e.matched == ("all-write", "big", "freeze")


def test_approve_beats_allow():
    pdp = ch04.PDP
    assert pdp.decide(CTX, REFUND, refund(150)).verdict == "allow"
    d = pdp.decide(CTX, REFUND, refund(900))
    assert d.verdict == "approve" and "refund-large" in d.reason


@pytest.mark.parametrize(
    "amount", ["150", True, float("nan"), float("inf"), -5, 0]
)
def test_amount_tricks_never_reach_allow(amount):
    d = ch04.PDP.decide(CTX, REFUND, refund(amount))
    assert d.verdict == "deny"


def test_missing_argument_fails_closed():
    call_ = ToolCall(
        "c", "issue_refund", {"customer_id": "C-100"}
    )
    e = ch04.PDP.explain(CTX, REFUND, call_)
    assert e.verdict == "deny" and "KeyError" in e.error


def test_roles_must_match():
    guest = Context("r", "a", Principal("eve", tenant="acme"))
    spec = ToolSpec("read_inbox", "read")
    read = ToolCall("c", "read_inbox", {})
    assert ch04.PDP.decide(guest, spec, read).verdict == "deny"
    assert ch04.PDP.decide(CTX, spec, read).verdict == "allow"


def test_tenant_guard_hides_foreign_and_unknown_ids():
    env, _ = build_env()
    guard = TenantGuard(
        lambda cid: env.customers.get(cid, {}).get("tenant")
    )
    spec = ToolSpec("lookup_customer", "read")

    def check(cid):
        c = ToolCall("c", "lookup_customer", {"customer_id": cid})
        return guard.check(CTX, spec, c)

    assert check("C-100").allowed
    for cid in (
        "C-200",
        "c-200",
        " C-100",
        "C-999",
        ["C-100"],
        None,
    ):
        d = check(cid)
        assert (
            d.verdict == "deny"
            and "not in tenant acme" in d.reason
        )
    no_id = ToolCall("c", "read_inbox", {})
    assert guard.check(CTX, spec, no_id).allowed


def test_runtime_approval_paths():
    def run(amount, approver):
        _, tools = build_env()
        rt = Runtime(
            tools, [AuthzGuard(ch04.PDP)], approver=approver
        )
        plan = [
            call(
                "issue_refund", customer_id="C-100", amount=amount
            )
        ]
        return rt.run(ASHA, "refund", ScriptedModel(plan)).denied

    assert run(900, lambda *a: True) == []
    [(_, refused)] = run(900, lambda *a: False)
    assert refused.reason.startswith("approval refused")
    [(_, nobody)] = run(900, None)
    assert nobody.reason.startswith("no approver")


def test_rule_validation():
    with pytest.raises(ValueError):
        Rule("r", "permit")
    with pytest.raises(ValueError):
        PolicyDecisionPoint(
            [Rule("r", "allow"), Rule("r", "deny")]
        )


def test_example_main(capsys):
    ch04.main()
    out = capsys.readouterr().out
    assert "refund-large, manager says yes" in out
    assert "'C-200' not in tenant acme" in out
    assert "emails sent: 0" in out
