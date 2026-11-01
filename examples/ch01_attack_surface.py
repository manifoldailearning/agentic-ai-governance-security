"""Chapter 1: the attack surface of a tool-using agent.

The same agent, the same task, two inboxes. With no guards,
one email from a stranger is enough to make the agent export
every customer and mail the list to an attacker. With a
benign inbox the agent behaves. The code did not change;
only the data did. That is the agentic attack surface.
"""

from __future__ import annotations

import json

from ags.core import (
    EXFIL,
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)

ASHA = Principal(
    "asha", tenant="acme", roles=frozenset({"support"})
)
TASK = "Triage my support inbox"


def triage(benign: bool):
    """Run the inbox task with no guards at all."""
    env, tools = build_env()
    if benign:
        env.inbox = env.inbox[:1]  # drop the injected email
    model = ScriptedModel(
        [call("read_inbox")],
        answer="1 billing issue: C-100 charged twice.",
        gullible=True,
    )
    return env, Runtime(tools).run(ASHA, TASK, model)


def leaked(env) -> list[dict]:
    """Customer records that left via email to the attacker."""
    rows: list[dict] = []
    for mail in env.sent:
        if mail["to"] == EXFIL:
            rows += json.loads(mail["body"])
    return rows


def report(title: str, env, result) -> None:
    n = len(result.calls) + len(result.denied)
    print(f"== {title} ==")
    print("calls:  ", " -> ".join(c.name for c in result.calls))
    print("denied: ", f"{len(result.denied)} of {n} (no guards)")
    print("labels: ", ", ".join(sorted(result.labels)))
    print("answer: ", repr(result.output))
    for mail in env.sent:
        print(
            f"emailed: {mail['to']} subject={mail['subject']!r}"
        )
    if not env.sent:
        print("emailed: nothing")
    if rows := leaked(env):
        cards = sum(1 for r in rows if r.get("card"))
        tenants = ", ".join(sorted({r["tenant"] for r in rows}))
        print(
            f"leaked:  {len(rows)} records, {cards} card numbers"
        )
        print(f"         tenants {tenants} (asha is acme only)")


def main() -> None:
    print(f"Task: {TASK!r} as asha@acme, no guards\n")
    report("Inbox with an injected email", *triage(False))
    print()
    report("Same task, benign inbox", *triage(True))


if __name__ == "__main__":
    main()
