"""Runtime guards for authorization and tenant isolation.

``AuthzGuard`` puts the policy decision point in front of
every tool call. ``TenantGuard`` checks the resource itself:
the customer a call names must belong to the caller's
tenant. Unknown and foreign ids get the same answer, so the
guard is not an oracle for which ids exist elsewhere.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from ags.authz.pdp import PolicyDecisionPoint
from ags.core.runtime import Context
from ags.core.types import Decision, ToolCall, ToolSpec


class AuthzGuard:
    name = "authz"

    def __init__(self, pdp: PolicyDecisionPoint) -> None:
        self.pdp = pdp

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        return self.pdp.decide(ctx, spec, call)


class TenantGuard:
    name = "tenant"

    def __init__(
        self,
        tenant_of: Callable[[str], str | None],
        args: Iterable[str] = ("customer_id",),
    ) -> None:
        self.tenant_of = tenant_of  # resource id -> tenant
        self.args = tuple(args)

    def check(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Decision:
        tenant = ctx.principal.tenant
        for arg in self.args:
            if arg not in call.args:
                continue
            rid = call.args[arg]
            owner = isinstance(rid, str) and self.tenant_of(rid)
            if owner != tenant:  # unknown or foreign: same reply
                why = f"{rid!r} not in tenant {tenant}"
                return Decision("deny", self.name, why)
        return Decision("allow", self.name)
