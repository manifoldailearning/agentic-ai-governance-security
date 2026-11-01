"""Chapter 17: a tamper-evident audit trail, and its evidence.

Three runs of the support agent seal every runtime event,
policy decision and human approval into one HMAC chain. We
then play the insider: lower a logged refund, delete an
entry, cut off the tail. Each edit is caught at the exact
entry. Finally the intact chain answers an auditor's
question about the refund and exports an evidence bundle.
"""

from __future__ import annotations

import copy
import tempfile
from dataclasses import replace

from ags.audit import (
    AuditEventLog,
    AuditLog,
    Entry,
    audited,
    bundle,
    evidence,
    verify,
    write_bundle,
)
from ags.core import (
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.policy import compile_policy, support_policy

KEY = b"example-audit-key-not-a-secret"  # EXAMPLE VALUE ONLY
KEYS = {"audit-k1": KEY}
ASHA = Principal(
    "asha", tenant="acme", roles=frozenset({"support"})
)
EMAIL = call(
    "send_email",
    to="ben@acme.example",
    subject="Plan",
    body="Basic",
)
LOOKUP = call("lookup_customer", customer_id="C-100")
REFUND = call("issue_refund", customer_id="C-100", amount=450)
RUNS = [  # (task, plan, does the model obey injected text?)
    ("Tell Ben his plan", [EMAIL], False),
    ("Refund C-100 for the outage", [LOOKUP, REFUND], False),
    ("Triage my support inbox", [call("read_inbox")], True),
]


def manager(ctx, spec, call, decision) -> bool:
    return True  # example approver: the manager says yes


def record(audit: AuditLog) -> None:
    """Events, policy decisions and approvals: one chain."""
    _, tools = build_env()
    policy = compile_policy(
        support_policy("1", 200), audit.append
    )
    rt = Runtime(
        tools,
        [policy],
        approver=audited(manager, audit, "manager:priya"),
        log=AuditEventLog(audit),
    )
    for task, plan, gullible in RUNS:
        rt.run(ASHA, task, ScriptedModel(plan, gullible=gullible))


def lower_refund(entry: Entry, amount: int) -> Entry:
    record = copy.deepcopy(entry.record)
    record["detail"]["args"]["amount"] = amount
    return replace(entry, record=record)


def main() -> None:
    audit = AuditLog(KEY, "audit-k1", anchor_every=5)
    record(audit)
    chain, anchors = audit.entries, audit.anchors
    print(f"Sealed {len(chain)} entries, anchors at", end=" ")
    print(", ".join(str(a.seq) for a in anchors))
    print(" ", verify(chain, KEYS, anchors))

    (refund,) = evidence(chain, tool="issue_refund")
    i = refund.seq
    edited = chain.copy()
    edited[i] = lower_refund(chain[i], 45)
    print(f"Insider lowers the refund in entry {i} to 45:")
    print(" ", verify(edited, KEYS, anchors))
    print("Insider deletes entry 6:")
    print(" ", verify(chain[:6] + chain[7:], KEYS, anchors))
    print("Insider cuts off the last 3 entries:")
    print(" ", verify(chain[:-3], KEYS, anchors))

    print("Auditor: who refunded C-100, and on what authority?")
    who = f"{refund.actor} for {refund.principal}@{refund.tenant}"
    amount = refund.args["amount"]
    print(f"  entry {i}, {refund.run_id}: {who}")
    print(f"  {refund.tool} C-100 {amount}: {refund.verdict}")
    print(f"  policy {refund.policy}")
    print(f"  {'; '.join(refund.approvals)}")

    result = verify(chain, KEYS, anchors)
    files = bundle(chain, result, [refund], anchors)
    with tempfile.TemporaryDirectory() as out:
        names = [p.name for p in write_bundle(files, out)]
    print("Evidence bundle:", ", ".join(names))


if __name__ == "__main__":
    main()
