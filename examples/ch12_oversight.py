"""Chapter 12: risk-tiered approvals in front of a real agent.

One approval queue serves two runs. Routine refunds go to an
auto-approver, a notable one to a person, a large one to two
people. Then a poisoned inbox makes the agent try to export
and email the customer list: the approver sees the untrusted
influence warning and refuses. Fatigue metrics close it out.
"""

from __future__ import annotations

from ags.core import (
    FakeClock,
    Principal,
    Runtime,
    ScriptedModel,
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

ASHA = Principal(
    "asha", tenant="acme", roles=frozenset({"support"})
)


def refunds(amounts: list[int]) -> ScriptedModel:
    steps = [call("lookup_customer", customer_id="C-100")]
    steps += [
        call("issue_refund", customer_id="C-100", amount=a)
        for a in amounts
    ]
    return ScriptedModel(steps)


def build() -> tuple:
    clock = FakeClock()
    policy = ApprovalPolicy()
    reviewers = [
        AutoReviewer(max_amount=100),
        ScriptedHuman("maria", lambda r: not r.untrusted, 45),
        ScriptedHuman("omar", seconds=4),  # approves everything
    ]
    queue = ApprovalQueue(policy, reviewers, clock, timeout=600)
    env, tools = build_env()
    runtime = Runtime(
        tools, [policy], approver=queue, clock=clock
    )
    return env, runtime, queue


def main() -> None:
    env, runtime, queue = build()
    runtime.run(ASHA, "Refund C-100", refunds([50, 150, 900]))
    attack = ScriptedModel([call("read_inbox")], gullible=True)
    runtime.run(ASHA, "Triage my support inbox", attack)
    print("lookup_customer, read_inbox: low tier, no approval\n")
    print(f"{'id':<8}{'call':<18}{'tier':<7}{'needs':<10}outcome")
    for r in queue.requests:
        what = r.tool + (f" {r.amount:g}" if r.amount else "")
        who = "+".join(v.reviewer for v in r.votes)
        if r.status != "approved":
            who = f"{r.status}: {who or 'nobody'}"
        print(
            f"{r.id:<8}{what:<18}{r.risk.tier:<7}"
            f"{r.risk.needs:<10}{who}"
        )
    print(f"\nWhat maria saw for {queue.requests[-1].id}:")
    for line in queue.requests[-1].summary:
        print("  " + line)
    print(
        f"\nrefunds: {[x['amount'] for x in env.refunds]}; "
        f"emails sent: {len(env.sent)}"
    )
    f = fatigue(queue.requests, fast=10)
    print(
        f"human votes {f.decisions}, approved "
        f"{f.approval_rate:.0%}, median {f.median_seconds:g}s"
    )
    print(f"rubber-stamp (<10s approvals): {f.rubber_stamps}")


if __name__ == "__main__":
    main()
