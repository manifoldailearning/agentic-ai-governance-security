"""Chapter 7: decide by what the agent has seen, not by text.

Three runs with the same gullible model. FlowGuard stops the
inbox attack because bulk personal data may not leave, and
the blog exfil because an external call after untrusted
input needs a human. Then a plan locked from the task alone
lets the legitimate reply to the customer through, while the
injected calls in the very same run are denied.
"""

from __future__ import annotations

import textwrap

from ags.core import (
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.flow import ANY, FlowGuard, PlanLock, step

ASHA = Principal("asha", tenant="acme")
REPLY = call(
    "send_email",
    to="asha@acme.example",
    subject="Re: double charge",
    body="We refunded the duplicate charge.",
)
PLAN = PlanLock(  # decided before any email is read
    (
        step("read_inbox"),
        step(
            "send_email",
            to=REPLY.args["to"],
            subject=ANY,
            body=ANY,
        ),
    )
)


def flow_only(tools):
    return [FlowGuard.for_tools(tools)]


def plan_locked(tools):
    return [PLAN, FlowGuard.for_tools(tools, plan=PLAN)]


def run(title: str, plan: list, guards) -> None:
    env, tools = build_env()
    model = ScriptedModel(list(plan), gullible=True)
    rt = Runtime(tools, guards(tools))
    res = rt.run(ASHA, "Handle my inbox", model)
    print(f"== {title}")
    print("  ran:", ", ".join(c.name for c in res.calls))
    for c, d in res.denied:
        dest = c.args.get("to") or c.args.get("url", "")
        what = f"{c.name} {dest[:32]}".strip()
        print(f"  denied {what} by {d.guard}")
        for line in textwrap.wrap(d.reason, 58):
            print(f"    {line}")
    sent = ", ".join(m["to"] for m in env.sent) or "nothing"
    print(f"  emailed: {sent}")


def main() -> None:
    inbox = [call("read_inbox")]
    run("inbox attack, FlowGuard", inbox, flow_only)
    blog = [call("fetch_url", url="https://blog.example/tips")]
    run("blog exfil, FlowGuard", blog, flow_only)
    run(
        "reply to Asha, plan locked", inbox + [REPLY], plan_locked
    )


if __name__ == "__main__":
    main()
