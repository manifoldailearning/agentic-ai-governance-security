"""Signed delegation tokens: an agent acting for a user.

An agent is not its user. A delegation token names both:
``sub`` is the agent, ``obo`` the user it acts for, bound
to a tenant, an audience, a short lifetime and narrow
scopes. Tokens are HMAC-SHA256 signed, the signature is
checked in constant time before any claim is trusted, and
exchange can only narrow a token, never widen it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace

from ags.core.clock import Clock, FakeClock
from ags.core.types import Principal

SKEW = 5.0  # seconds of clock skew tolerated on ``iat``


class TokenError(Exception):
    """A token that must not be honoured; the message says why."""


@dataclass(frozen=True)
class Claims:
    iss: str
    sub: str  # the agent identity
    obo: str  # the user it acts on behalf of
    tenant: str
    aud: str  # the resource server meant to accept it
    scopes: frozenset[str]
    iat: float
    exp: float
    jti: str  # unique id, the handle for revocation
    chain: tuple[str, ...] = ()  # jti of each ancestor


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _join(names: Iterable[str]) -> str:
    return ", ".join(sorted(names))


def encode_claims(c: Claims) -> str:
    body = asdict(c) | {"scopes": sorted(c.scopes)}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return _b64(raw.encode())


def decode_claims(payload: str) -> Claims:
    body = json.loads(_unb64(payload))
    body["scopes"] = frozenset(body["scopes"])
    body["chain"] = tuple(body["chain"])
    return Claims(**body)


class TokenService:
    """Issues, verifies, exchanges and revokes tokens."""

    def __init__(
        self,
        key: bytes,
        clock: Clock | None = None,
        issuer: str = "idp.example",
        ttl: float = 300.0,
    ) -> None:
        if len(key) < 32:
            raise ValueError("HMAC key needs >= 32 bytes")
        self._key = key
        self.clock = clock or FakeClock()
        self.issuer = issuer
        self.ttl = ttl
        self.ceilings: dict[str, frozenset[str]] = {}
        self.revoked: set[str] = set()
        self._issued = 0

    def register_agent(
        self, agent: str, ceiling: Iterable[str]
    ) -> None:
        """An agent identity with the most it may ever hold."""
        self.ceilings[agent] = frozenset(ceiling)

    def issue(
        self,
        agent: str,
        user: Principal,
        scopes: Iterable[str],
        aud: str,
        ttl: float | None = None,
    ) -> str:
        """The user consents to ``scopes`` for ``agent``."""
        if agent not in self.ceilings:
            raise TokenError(f"unknown agent {agent!r}")
        wanted = frozenset(scopes)
        if extra := wanted - self.ceilings[agent]:
            raise TokenError(
                f"over agent ceiling: {_join(extra)}"
            )
        now = self.clock.now()
        exp = now + self._lifetime(ttl)
        claims = Claims(
            iss=self.issuer,
            sub=agent,
            obo=user.id,
            tenant=user.tenant,
            aud=aud,
            scopes=wanted,
            iat=now,
            exp=exp,
            jti=self._next_jti(),
        )
        return self._sign(claims)

    def verify(
        self,
        token: str,
        aud: str,
        scope: str | None = None,
        now: float | None = None,
    ) -> Claims:
        claims = self._open(token)
        if claims.aud != aud:
            raise TokenError(f"wrong audience {claims.aud!r}")
        self._check_live(claims, now)
        if scope is not None and scope not in claims.scopes:
            raise TokenError(f"missing scope {scope}")
        return claims

    def _lifetime(self, ttl: float | None) -> float:
        life = self.ttl if ttl is None else ttl
        if not life > 0:  # also rejects NaN
            raise TokenError("token lifetime must be positive")
        return life

    def exchange(
        self,
        token: str,
        scopes: Iterable[str],
        ttl: float | None = None,
    ) -> str:
        """Downscope: never more scope or time than the parent."""
        parent = self._open(token)
        self._check_live(parent)
        wanted = frozenset(scopes)
        if extra := wanted - parent.scopes:
            raise TokenError(f"cannot widen: {_join(extra)}")
        now = self.clock.now()
        exp = now + self._lifetime(ttl)
        child = replace(
            parent,
            scopes=wanted,
            iat=now,
            exp=min(exp, parent.exp),
            jti=self._next_jti(),
            chain=(*parent.chain, parent.jti),
        )
        return self._sign(child)

    def revoke(self, jti: str) -> None:
        """Kills the token and every token exchanged from it."""
        self.revoked.add(jti)

    def _next_jti(self) -> str:
        self._issued += 1  # production: secrets.token_urlsafe()
        return f"tok-{self._issued:04d}"

    def _mac(self, payload: str) -> str:
        mac = hmac.new(
            self._key, payload.encode(), hashlib.sha256
        )
        return _b64(mac.digest())

    def _sign(self, claims: Claims) -> str:
        payload = encode_claims(claims)
        return f"{payload}.{self._mac(payload)}"

    def _open(self, token: str) -> Claims:
        """Signature first, in constant time; then parse."""
        payload, _, sig = str(token).partition(".")
        good = self._mac(payload).encode()
        if not hmac.compare_digest(good, sig.encode()):
            raise TokenError("bad signature")
        claims = decode_claims(payload)
        if claims.iss != self.issuer:
            raise TokenError(f"wrong issuer {claims.iss!r}")
        return claims

    def _check_live(
        self, c: Claims, now: float | None = None
    ) -> None:
        now = self.clock.now() if now is None else now
        if now >= c.exp:
            raise TokenError("token expired")
        if c.iat > now + SKEW:
            raise TokenError("token not yet valid")
        if self.revoked & {c.jti, *c.chain}:
            raise TokenError("token revoked")
