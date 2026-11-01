"""Chapter 8: narrow what a talked-into model can reach.

One gullible run fetches the injected blog page, then tries
the usual URL tricks and a malformed refund. The schema and
egress guards deny each one with a reason, and only the two
allowlisted pages are fetched. Then model-written code runs
in a limited child process: killed on timeout, starved of
memory and disk, and blind to the parent's environment (the
one variable it sees is the locale Python sets for itself).
"""

from __future__ import annotations

from ags.core import (
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.sandbox import (
    ArgSchemaGuard,
    EgressGuard,
    Field,
    run_sandboxed,
)

S = "https://status.example"
TRICKS = {
    f"{S}/today": "allowed",
    "http://status.example/today": "plain http",
    "https://status.example@exfil.example/": "userinfo trick",
    "https://2130706433/": "decimal IP",
    "https://0x7f.1/": "hex IP",
    f"{S}.exfil.example/": "suffix trick",
    "https://status.example:8443/": "odd port",
    f"{S}/?d=YXNoYUBhY21lLmV4YW1wbGUgNDExMQ==": "encoded data",
}
SCHEMAS = {
    "fetch_url": {"url": Field(max_len=2048)},
    "issue_refund": {
        "customer_id": Field(pattern=r"C-\d{3}"),
        "amount": Field(float),
    },
}
CODE = {
    "infinite loop": "while True: pass",
    "1 GB allocation": "b = bytearray(10**9)",
    "2 MB file write": "open('f', 'wb').write(b'x' * 2**21)",
    "read env vars": "import os; print(sorted(os.environ))",
}


def egress_demo() -> None:
    env, tools = build_env()
    allow = ("status.example", "blog.example")
    guards = [ArgSchemaGuard(SCHEMAS), EgressGuard(allow)]
    plan = [call("fetch_url", url="https://blog.example/tips")]
    plan += [call("fetch_url", url=u) for u in TRICKS]
    plan += [
        call(
            "issue_refund", customer_id="C-100,C-200", amount=50.0
        )
    ]
    model = ScriptedModel(plan, gullible=True)
    res = Runtime(tools, guards, max_steps=12).run(
        Principal("asha", tenant="acme"), "Check status", model
    )
    print(f"Egress allowlist: {', '.join(allow)}")
    for c, d in res.denied:
        what = TRICKS.get(c.args.get("url"), "injected $LAST")
        what = "id list" if c.name == "issue_refund" else what
        print(f"  {what:<16} {d.reason}")
    fetched = ", ".join(
        u.removeprefix("https://") for u in env.fetched
    )
    print(f"  fetched: {fetched}")


def sandbox_demo() -> None:
    print("run_sandboxed (a limited process, not a VM):")
    for what, code in CODE.items():
        r = run_sandboxed(code, timeout=1.0)
        last = (r.stderr.strip().splitlines() or [""])[-1]
        if r.timed_out:
            shown = f"killed at 1.0s timeout (exit {r.exit_code})"
        else:
            shown = (
                f"exit {r.exit_code} {last or r.stdout.strip()}"
            )
        print(f"  {what:<16} {shown[:45]}")


def main() -> None:
    egress_demo()
    sandbox_demo()


if __name__ == "__main__":
    main()
