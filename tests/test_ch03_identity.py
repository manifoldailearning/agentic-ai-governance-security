from __future__ import annotations

from dataclasses import replace

import pytest

import ch03_agent_identity as ch03
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
    with_token,
)

KEY = b"test-only-hmac-key-0123456789abcdef!"
ASHA = Principal("asha", tenant="acme")
INBOX = {"tool:read_inbox"}


@pytest.fixture
def idp() -> TokenService:
    svc = TokenService(KEY, FakeClock(100.0), ttl=60)
    svc.register_agent(
        "support-agent", INBOX | {"tool:send_email"}
    )
    return svc


def test_issue_and_verify_round_trip(idp):
    tok = idp.issue("support-agent", ASHA, INBOX, "api")
    c = idp.verify(tok, "api", "tool:read_inbox")
    assert (c.sub, c.obo, c.tenant) == (
        "support-agent",
        "asha",
        "acme",
    )
    assert c.exp == 160.0 and c.scopes == INBOX


def test_tampering_is_rejected(idp):
    tok = idp.issue("support-agent", ASHA, INBOX, "api")
    payload, sig = tok.split(".")
    wider = replace(
        decode_claims(payload), scopes={"tool:send_email"}
    )
    flipped = sig[:-1] + ("A" if sig[-1] != "A" else "B")
    other = TokenService(b"x" * 32, idp.clock)
    other.register_agent("support-agent", INBOX)
    for bad in (
        f"{encode_claims(wider)}.{sig}",  # edited claims
        f"{payload}.{flipped}",  # edited signature
        payload,  # signature stripped
        other.issue("support-agent", ASHA, INBOX, "api"),
    ):
        with pytest.raises(TokenError, match="bad signature"):
            idp.verify(bad, "api")


def test_expiry_is_exclusive_and_future_tokens_wait(idp):
    tok = idp.issue("support-agent", ASHA, INBOX, "api")
    idp.verify(tok, "api", now=159.9)
    with pytest.raises(TokenError, match="expired"):
        idp.verify(tok, "api", now=160.0)
    with pytest.raises(TokenError, match="not yet valid"):
        idp.verify(tok, "api", now=90.0)


def test_audience_and_exact_scope_required(idp):
    tok = idp.issue("support-agent", ASHA, INBOX, "api")
    with pytest.raises(TokenError, match="audience"):
        idp.verify(tok, "billing-api")
    for scope in ("tool:send_email", "TOOL:read_inbox", "tool:*"):
        with pytest.raises(TokenError, match="missing scope"):
            idp.verify(tok, "api", scope)


def test_exchange_only_downscopes(idp):
    both = INBOX | {"tool:send_email"}
    tok = idp.issue("support-agent", ASHA, both, "api", ttl=30)
    with pytest.raises(TokenError, match="cannot widen"):
        idp.exchange(tok, both | {"tool:run_python"})
    child = idp.exchange(tok, INBOX, ttl=600)
    c = idp.verify(child, "api")
    assert c.scopes == INBOX and c.exp == 130.0  # capped
    with pytest.raises(TokenError, match="cannot widen"):
        idp.exchange(child, both)


def test_revoking_a_parent_kills_its_children(idp):
    tok = idp.issue("support-agent", ASHA, INBOX, "api")
    grandchild = idp.exchange(idp.exchange(tok, INBOX), INBOX)
    idp.revoke(decode_claims(tok.split(".")[0]).jti)
    for t in (tok, grandchild):
        with pytest.raises(TokenError, match="revoked"):
            idp.verify(t, "api")


def test_agent_ceiling_and_key_length(idp):
    with pytest.raises(TokenError, match="unknown agent"):
        idp.issue("rogue-agent", ASHA, INBOX, "api")
    with pytest.raises(TokenError, match="ceiling"):
        idp.issue(
            "support-agent", ASHA, {"tool:run_python"}, "api"
        )
    with pytest.raises(ValueError):
        TokenService(b"short")


def test_guard_binds_token_to_agent_user_and_tenant(idp):
    tok = idp.issue("support-agent", ASHA, INBOX, "api")
    guard = IdentityGuard(idp, "api")

    def run(principal, agent="support-agent"):
        _, tools = build_env()
        rt = Runtime(tools, [guard], clock=idp.clock, agent=agent)
        model = ScriptedModel([call("read_inbox")])
        return rt.run(principal, "t", model).denied

    assert run(with_token(ASHA, tok)) == []
    bob = with_token(Principal("bob", tenant="acme"), tok)
    globex = with_token(replace(ASHA, tenant="globex"), tok)
    for wrong_holder in (bob, globex, ASHA):  # ASHA: no token
        assert run(wrong_holder)
    [(_, d)] = run(with_token(ASHA, tok), agent="billing-agent")
    assert d.guard == "identity" and "token is for" in d.reason


def test_example_main(capsys):
    ch03.main()
    out = capsys.readouterr().out
    assert "export_customers denied: missing scope" in out
    assert "emails sent: 0" in out
    assert "tampered token   denied: bad signature" in out


def test_non_positive_lifetime_is_rejected():
    import pytest

    from ags.core import FakeClock, Principal
    from ags.identity import TokenError, TokenService

    svc = TokenService(b"k" * 32, FakeClock())
    svc.register_agent("support-agent", ["tool:x"])
    for bad in (0, -5, float("nan")):
        with pytest.raises(TokenError):
            svc.issue(
                "support-agent",
                Principal("asha"),
                ["tool:x"],
                "support",
                ttl=bad,
            )


def test_with_token_exposes_jti_for_revocation():
    from ags.core import (
        Context,
        FakeClock,
        Principal,
        ToolCall,
        ToolSpec,
    )
    from ags.identity import TokenService, with_token
    from ags.respond.containment import TokenRevocation

    svc = TokenService(b"k" * 32, FakeClock())
    svc.register_agent("support-agent", ["tool:read_doc"])
    tok = svc.issue(
        "support-agent",
        Principal("asha"),
        ["tool:read_doc"],
        "support",
    )
    who = with_token(Principal("asha"), tok)
    guard = TokenRevocation()
    ctx = Context("run-1", "support-agent", who)
    spec, c = ToolSpec("read_doc", "read"), ToolCall("1", "x", {})
    assert guard.check(ctx, spec, c).allowed
    guard.revoked.add(who.attrs["jti"])
    assert guard.check(ctx, spec, c).verdict == "deny"
    assert "jti" not in with_token(Principal("b"), "junk").attrs
