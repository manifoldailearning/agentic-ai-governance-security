"""Chapter 16: a policy change, tested and replayed first.

Version 1 of the support-agent policy lets support staff
refund up to 200 without approval; version 2 lowers that to
100. Before shipping v2 we run its unit cases, bypass
attempts included, then replay the calls recorded under v1
to see exactly which past decisions v2 would change.
"""

from __future__ import annotations

from ags.core import (
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.policy import (
    Policy,
    compile_policy,
    impact,
    run_cases,
    support_policy,
)

ASHA = Principal(
    "asha", tenant="acme", roles=frozenset({"support"})
)
HISTORY = [
    ("C-100", 40),
    ("C-101", 120),
    ("C-100", 180),
    ("C-101", 450),
]


def case(name, tool, expect, roles=("support",), **extra):
    """A policy unit case; ``extra`` may set args and labels."""
    return dict(
        name=name,
        tool=tool,
        expect=expect,
        roles=list(roles),
        **extra,
    )


def amount(value) -> dict:
    return {"customer_id": "C-100", "amount": value}


REFUND = "issue_refund"
TAINTED = {"labels": ["untrusted"]}
NAN = float("nan")  # compares false both ways: a classic bypass
CASES = [
    case("refund 80", REFUND, "allow", args=amount(80)),
    case("refund 150", REFUND, "approve", args=amount(150)),
    case("amount as text", REFUND, "approve", args=amount("90")),
    case("NaN amount", REFUND, "approve", args=amount(NAN)),
    case("bulk export", "export_customers", "deny"),
    case("email when tainted", "send_email", "deny", **TAINTED),
    case("no role", "lookup_customer", "deny", roles=()),
]


def manager(ctx, spec, call, decision) -> bool:
    return True  # example approver: the on-call manager agrees


def record_history(guard) -> Runtime:
    _, tools = build_env()
    rt = Runtime(tools, [guard], approver=manager)
    lookup = call("lookup_customer", customer_id="C-100")
    rt.run(ASHA, "Look up C-100", ScriptedModel([lookup]))
    for customer, value in HISTORY:
        step = call(
            "issue_refund", customer_id=customer, amount=value
        )
        rt.run(ASHA, f"Refund {value}", ScriptedModel([step]))
    return rt


def main() -> None:
    v1 = compile_policy(support_policy("1", refund_limit=200))
    v2 = Policy.load(support_policy("2", refund_limit=100))
    rt = record_history(v1)
    print(
        f"Decision log under {v1.policy.tag}"
        f" (sha256 {v1.policy.digest[:12]}):"
    )
    for d in v1.decisions:
        what = f"{d.tool} {d.args.get('amount', '')}"
        print(f"  {d.run_id} {what:<20} {d.verdict:<8} {d.rule}")

    specs = {t.spec.name: t.spec for t in rt.tools.values()}
    results = run_cases(v2, CASES, specs)
    print(f"Unit cases for {v2.tag}:")
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        got = f"{r.got.verdict:<8}{r.got.rule}"
        print(f"  {mark} {r.name:<19} {got}")
    passed = sum(r.passed for r in results)
    print(f"  {passed}/{len(results)} passed")

    calls = rt.log.where(kind="tool_call")
    changes = impact(calls, v1.policy, v2, specs, {"asha": ASHA})
    print(f"Impact v1 -> v2 over {len(calls)} recorded calls:")
    for c in changes:
        e, value = c.event, c.event.detail["args"]["amount"]
        verdicts = f"{c.before.verdict} -> {c.after.verdict}"
        print(f"  {e.run_id} {e.tool} {value}: {verdicts}")
    need = sum(c.after.verdict == "approve" for c in changes)
    print(f"  {len(changes)} changed; {need} now need approval")


if __name__ == "__main__":
    main()
