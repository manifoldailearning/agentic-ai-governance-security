"""Chapter 11: purpose binding, consent and erasure.

A refund session declares its purpose. Customer lookups are
projected to id, plan and last four digits before the model
sees them, and tools outside the purpose are denied. Then a
marketing export honors consent, an erasure request reaches
every store, and a retention sweep respects a legal hold.
"""

from __future__ import annotations

from ags.core import (
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.privacy import (
    PURPOSES,
    ConsentRegistry,
    DataSubjectRequest,
    DictStore,
    EventStore,
    MinimizingTool,
    PurposeGuard,
    fulfil,
    retention_sweep,
)

ASHA = Principal(
    "asha", tenant="acme", roles=frozenset({"support"})
)
KEY = b"example-pseudonym-key-not-secret"  # example value
DAY = 86400.0


def refund_session():
    env, tools = build_env()
    refund = PURPOSES["refund"]
    bound = [
        MinimizingTool(t, refund)
        if t.spec.labels & {"pii"}
        else t
        for t in tools
    ]
    runtime = Runtime(bound, [PurposeGuard(refund)])
    model = ScriptedModel(
        [
            call("lookup_customer", customer_id="C-100"),
            call("issue_refund", customer_id="C-100", amount=30),
            call("export_customers"),  # curiosity, not purpose
        ]
    )
    task = "Refund the duplicate charge for C-100"
    return env, runtime, runtime.run(ASHA, task, model)


def show_refund(env, runtime, result) -> None:
    raw = env.lookup_customer("C-100")
    seen = runtime.tools["lookup_customer"].fn(
        customer_id="C-100"
    )
    print("Refund purpose: what lookup_customer returns")
    print("  raw      :", ", ".join(sorted(raw)))
    print("  minimized:", seen)
    labels = ", ".join(sorted(result.labels)) or "none (no pii)"
    print("  run labels:", labels)
    print("  refunds:", env.refunds)
    for _, d in result.denied:
        print(f"  denied by {d.guard}: {d.reason}")


def show_consent() -> None:
    env, tools = build_env()
    consent = ConsentRegistry()
    consent.grant("C-101", "marketing")
    export = {t.spec.name: t for t in tools}["export_customers"]
    rows = MinimizingTool(export, PURPOSES["marketing"], consent)
    print("\nMarketing export (consent: C-101 only)")
    for row in rows.fn():
        if "withheld" in row:
            print(f"  {row['id']}: withheld ({row['withheld']})")
        else:
            fields = ", ".join(f"{k}={v}" for k, v in row.items())
            print(f"  {fields}")


def show_erasure(runtime) -> None:
    env, _ = build_env()
    memory = {
        "m1": {"text": "C-100 prefers email", "owner": "asha"},
        "m2": {"text": "Write to asha@acme.example re: refund"},
        "m3": {"text": "C-1000 is a different customer"},
    }
    stores = [
        DictStore("customers", env.customers),
        DictStore("memory", memory),
        EventStore("events", runtime.log.events),
    ]
    ids = frozenset({"C-100", "asha@acme.example"})
    dsr = DataSubjectRequest("dsr-7", "erase", ids)
    print("\nErasure request dsr-7 for C-100 / asha@acme.example")
    for line in fulfil(dsr, stores, KEY).lines():
        print(f"  {line}")
    refund = runtime.log.where(kind="tool_call")[1]
    args = refund.detail["args"]
    print(
        f"  refund event now: customer_id={args['customer_id']}"
    )


def show_retention() -> None:
    notes = {f"t{i}": {"ts": i * 30 * DAY} for i in range(4)}
    held = frozenset({"t0"})
    gone = retention_sweep(notes, 100 * DAY, 60 * DAY, held)
    print(f"\nRetention 60d, day 100: deleted {gone}, t0 on hold")


def main() -> None:
    env, runtime, result = refund_session()
    show_refund(env, runtime, result)
    show_consent()
    show_erasure(runtime)
    show_retention()


if __name__ == "__main__":
    main()
