"""Chapter 3: agent identity and delegated, scoped tokens.

Asha delegates two narrow scopes to the support agent. The
inbox attack then dies on scope, not on luck. A widened
exchange, a replay by another agent, a tampered token, a
revoked parent and an expired token are all refused.
"""

from __future__ import annotations

from dataclasses import replace

from ags.core import (
    FakeClock,
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.identity import (
    IdentityGuard,
    TokenError,
    TokenService,
    decode_claims,
    encode_claims,
    scope_for,
    with_token,
)

KEY = b"example-only-hmac-key-0123456789abcdef"  # example value
AUD = "support-api"
AGENT = "support-agent"
ASHA = Principal("asha", tenant="acme")
GRANT = {"tool:read_inbox", "tool:lookup_customer"}


def attempt(idp, token, *calls, gullible=False, agent=AGENT):
    """Run the agent with ``token``; return tool decisions."""
    env, tools = build_env()
    guard = IdentityGuard(idp, AUD)
    rt = Runtime(tools, [guard], clock=idp.clock, agent=agent)
    model = ScriptedModel(list(calls), gullible=gullible)
    rt.run(with_token(ASHA, token), "Triage my inbox", model)
    return env, rt.log.where(kind="tool_call")


def show(label: str, events) -> None:
    for e in events:
        denied = e.verdict == "deny"
        outcome = f"denied: {e.reason}" if denied else "allowed"
        print(f"  {label or e.tool:<17}{outcome}")


def tamper(token: str, scope: str) -> str:
    """Add a scope to the claims and keep the old signature."""
    payload, sig = token.split(".")
    claims = decode_claims(payload)
    forged = replace(claims, scopes=claims.scopes | {scope})
    return f"{encode_claims(forged)}.{sig}"


def refused(fn, *args) -> str:
    try:
        fn(*args)
    except TokenError as exc:
        return f"refused: {exc}"
    return "ACCEPTED"


def misuse(idp: TokenService, tok: str) -> None:
    print("Token service:")
    run_py = ["tool:run_python"]
    widened = GRANT | {"tool:send_email"}
    for label, fn, args in (
        ("consent", idp.issue, (AGENT, ASHA, run_py, AUD)),
        ("exchange", idp.exchange, (tok, widened)),
    ):
        print(f"  {label:<17}{refused(fn, *args)}")
    child = idp.exchange(tok, {"tool:read_inbox"}, 60)
    lookup = call("lookup_customer", customer_id="C-100")
    inbox = call("read_inbox")
    print("Identity guard:")
    show("child token", attempt(idp, child, lookup)[1])
    billing = attempt(idp, tok, lookup, agent="billing")
    show("other agent", billing[1])
    forged = tamper(tok, "tool:send_email")
    show("tampered token", attempt(idp, forged, inbox)[1])
    idp.revoke(decode_claims(tok.split(".")[0]).jti)
    show("parent revoked", attempt(idp, child, inbox)[1])
    fresh = idp.issue(AGENT, ASHA, GRANT, AUD)
    idp.clock.advance(301)
    show("after 301s", attempt(idp, fresh, inbox)[1])


def main() -> None:
    idp = TokenService(KEY, FakeClock(1000.0), ttl=300)
    ceiling = ("read_inbox", "lookup_customer", "send_email")
    idp.register_agent(AGENT, map(scope_for, ceiling))
    tok = idp.issue(AGENT, ASHA, GRANT, AUD)
    print(f"asha -> {AGENT}: {', '.join(sorted(GRANT))}")
    print(f"  aud={AUD}, ttl=300s, ceiling={len(ceiling)} tools")
    inbox = call("read_inbox")
    env, events = attempt(idp, tok, inbox, gullible=True)
    print("Inbox attack with the delegated token:")
    show("", events)
    print(f"  emails sent: {len(env.sent)}")
    misuse(idp, tok)


if __name__ == "__main__":
    main()
