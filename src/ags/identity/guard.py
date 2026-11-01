"""IdentityGuard: no valid delegation token, no tool call.

The runtime knows which agent is running and for whom. The
token must agree on agent, user and tenant, be live, be
meant for this audience and carry ``tool:<name>`` for the
exact tool being called. Anything else is denied.
"""

from __future__ import annotations

from dataclasses import replace

from ags.core.runtime import Context
from ags.core.types import Decision, Principal, ToolCall, ToolSpec
from ags.identity.tokens import (
    TokenError,
    TokenService,
    decode_claims,
)


def scope_for(tool: str) -> str:
    return f"tool:{tool}"


def with_token(user: Principal, token: str) -> Principal:
    """The user's principal carrying a delegation token.

    The token id is copied to ``jti`` so revocation switches
    (Chapter 15) can find it. Nothing is trusted here: the
    IdentityGuard still verifies the token on every call.
    """
    attrs = {**user.attrs, "token": token}
    try:
        attrs["jti"] = decode_claims(token.partition(".")[0]).jti
    except (ValueError, KeyError, TypeError):
        pass  # unreadable: no jti, so revocation fails closed
    return replace(user, attrs=attrs)


class IdentityGuard:
    name = "identity"

    def __init__(self, tokens: TokenService, audience: str):
        self.tokens = tokens
        self.audience = audience

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        token = ctx.principal.attrs.get("token")
        if not isinstance(token, str) or not token:
            return Decision(
                "deny", self.name, "no delegation token"
            )
        scope = scope_for(spec.name)
        try:
            c = self.tokens.verify(
                token, self.audience, scope, now=ctx.now
            )
        except TokenError as exc:
            return Decision("deny", self.name, str(exc))
        p = ctx.principal
        if (c.sub, c.obo, c.tenant) != (
            ctx.agent,
            p.id,
            p.tenant,
        ):
            why = f"token is for {c.sub}/{c.obo}@{c.tenant}"
            return Decision("deny", self.name, why)
        return Decision("allow", self.name, f"{c.jti} {scope}")
