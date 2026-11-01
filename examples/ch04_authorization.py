"""Chapter 4: least privilege with a policy decision point.

A support agent works under four rules and default deny.
Small refunds pass, large ones need a manager, a customer
from another tenant is invisible, bulk export is denied
outright, and the inbox attack finds no allowed path.
"""

from __future__ import annotations

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
    build_env,
    call,
)

SUPPORT = {"support"}
AMOUNT = "args.amount"
RULES = [
    Rule(
        "support-read",
        "allow",
        roles=SUPPORT,
        tools={"read_inbox", "read_doc", "lookup_customer"},
    ),
    Rule(
        "refund-small",
        "allow",
        roles=SUPPORT,
        tools={"issue_refund"},
        when=(cmp(AMOUNT, ">", 0), cmp(AMOUNT, "<=", 200)),
    ),
    Rule(
        "refund-large",
        "approve",
        roles=SUPPORT,
        tools={"issue_refund"},
        when=(cmp(AMOUNT, ">", 200),),
        reason="over 200 needs a manager",
    ),
    Rule(
        "no-bulk-export",
        "deny",
        roles=SUPPORT,
        tools={"export_customers"},
        reason="bulk export is not a support task",
    ),
]
ASHA = Principal("asha", tenant="acme", roles=frozenset(SUPPORT))
PDP = PolicyDecisionPoint(RULES)


def manager(ctx, spec, call, decision) -> bool:
    """Stand-in human: approves refunds up to 1000."""
    return call.args["amount"] <= 1000


def run(*plan, gullible=False):
    env, tools = build_env()

    def tenant_of(customer_id: str) -> str | None:
        return env.customers.get(customer_id, {}).get("tenant")

    guards = [TenantGuard(tenant_of), AuthzGuard(PDP)]
    rt = Runtime(tools, guards, approver=manager)
    model = ScriptedModel(list(plan), gullible=gullible)
    rt.run(ASHA, "Handle today's tickets", model)
    return env, rt


def label(c: ToolCall) -> str:
    arg = c.args.get("amount", c.args.get("customer_id", ""))
    return f"{c.name} {arg}"


def report(rt: Runtime) -> None:
    """Each call: verdict and the rule (or guard) behind it."""
    ctx = Context("report", rt.agent, ASHA)
    for e in rt.log.where(kind="tool_call"):
        c = ToolCall("", e.tool, e.detail["args"])
        ex = PDP.explain(ctx, rt.tools[e.tool].spec, c)
        why = ex.rule.id if ex.rule else "no rule: default deny"
        verdict = ex.verdict
        if e.guard == "tenant":
            verdict, why = "deny", e.reason
        elif verdict == "approve":
            yes = "yes" if e.verdict == "allow" else "no"
            why += f", manager says {yes}"
        print(f"  {label(c):<22}{verdict:<9}{why}")


def main() -> None:
    print("Policy: 4 rules + default deny; asha is support@acme")
    print(f"  {'call':<22}{'verdict':<9}deciding rule or guard")
    env, rt = run(
        call("lookup_customer", customer_id="C-100"),
        call("issue_refund", customer_id="C-100", amount=150),
        call("issue_refund", customer_id="C-100", amount=900),
        call("issue_refund", customer_id="C-101", amount=5000),
        call("lookup_customer", customer_id="C-200"),
        call("export_customers"),
        call("run_python", code="print(1)"),
    )
    report(rt)
    issued = [r["amount"] for r in env.refunds]
    print(f"  refunds issued: {issued}")
    print("Inbox attack under the same policy:")
    env, rt = run(call("read_inbox"), gullible=True)
    report(rt)
    print(f"  emails sent: {len(env.sent)}")


if __name__ == "__main__":
    main()
