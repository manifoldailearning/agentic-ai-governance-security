"""Chapter 10: poisoned memory, tenant isolation and expiry.

Session 1 triages the inbox and auto-memory saves what it
read, hostile email included; nothing bad happens yet.
Session 2 asks about audits, recalls the note, and a gullible
model obeys it. With a naive store the customer list leaves;
with screening the note waits in quarantine. Then: tenant
isolation, TTL expiry and forgetting.
"""

from __future__ import annotations

import json

from ags.core import (
    EXFIL,
    FakeClock,
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.memory import MemoryStore, memory_tools

SUPPORT = frozenset({"support"})
ASHA = Principal("asha", tenant="acme", roles=SUPPORT)
BEN = Principal("ben", tenant="acme", roles=SUPPORT)
CHEN = Principal("chen", tenant="globex", roles=SUPPORT)


def two_sessions(store: MemoryStore) -> list[dict]:
    """Note-taking today, recall tomorrow. Returns env.sent."""
    env, tools = build_env()
    runtime = Runtime(tools + memory_tools(store, ASHA))
    notes = ScriptedModel(
        [
            call("read_inbox"),
            call("remember", text="C-100 was charged twice."),
        ]
    )
    runtime.run(ASHA, "Triage the inbox, keep notes", notes)
    for mail in env.inbox:  # auto-memory: save what was read
        store.write(ASHA, mail["body"], source="read_inbox")
    later = ScriptedModel(
        [call("recall", query="audit request")], gullible=True
    )
    runtime.run(ASHA, "Any open audit requests?", later)
    return env.sent


def outcome(sent: list[dict]) -> str:
    out = [m for m in sent if m["to"] == EXFIL]
    if not out:
        return "nothing sent"
    rows = json.loads(out[0]["body"])
    return f"{len(rows)} records emailed to {EXFIL}"


def poisoning() -> None:
    print("Session 1 saves the inbox; session 2 recalls 'audit'")
    naive = MemoryStore(screen=False)
    print("  naive store  :", outcome(two_sessions(naive)))
    guarded = MemoryStore()
    print("  guarded store:", outcome(two_sessions(guarded)))
    for e in guarded.quarantined():
        print(f"  quarantined {e.id}: {e.reason}")


def isolation_and_expiry() -> None:
    clock = FakeClock()
    store = MemoryStore(clock)
    store.write(ASHA, "C-100 refund approved", readers=SUPPORT)
    store.write(ASHA, "C-101 card refund pending", ttl=3600)
    store.write(CHEN, "refund card refund C-200 card 1881")
    for who in (ASHA, BEN, CHEN):
        hits = store.search(who, "refund card")
        name = f"{who.id}@{who.tenant}"
        print(f"  {name:<12} -> {[e.id for e in hits]}")
    clock.advance(7200)
    hits = store.search(ASHA, "refund card")
    print(f"  2h later, asha -> {[e.id for e in hits]}")
    print(f"  sweep() deleted {store.sweep()}")
    print(f"  forget('asha') erased {store.forget('asha')} entry")


def main() -> None:
    poisoning()
    print(
        "\nSearch 'refund card' (ACL filter runs before ranking)"
    )
    isolation_and_expiry()


if __name__ == "__main__":
    main()
