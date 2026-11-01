"""Agent identity and delegated access (chapter 3).

Agents get their own identities and act for users only
through short-lived, signed, narrowly scoped delegation
tokens that can be downscoped and revoked.
"""

from ags.identity.guard import (
    IdentityGuard,
    scope_for,
    with_token,
)
from ags.identity.tokens import (
    Claims,
    TokenError,
    TokenService,
    decode_claims,
    encode_claims,
)

__all__ = [
    "Claims",
    "IdentityGuard",
    "TokenError",
    "TokenService",
    "decode_claims",
    "encode_claims",
    "scope_for",
    "with_token",
]
