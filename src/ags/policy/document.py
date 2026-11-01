"""Policy as code: authorization rules as reviewable data.

Rules buried in code drift and cannot be reviewed by the
people who own the risk. A policy document is plain JSON:
versioned, diffable, tested in CI and replayed against
history before it ships. This module validates documents and
evaluates them; whatever it cannot evaluate fails closed.
"""

from __future__ import annotations

import hashlib
import json
import math
import operator
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from ags.core import Context, Decision, ToolCall, ToolSpec
from ags.core.types import EFFECTS

VERDICTS = ("allow", "approve", "deny")  # weakest -> strictest
ORDERED = {"<", "<=", ">", ">="}
OPS: dict[str, Callable[[Any, Any], bool]] = {
    "==": operator.eq,
    "!=": operator.ne,
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "in": lambda have, want: have in want,
    "not_in": lambda have, want: have not in want,
    "contains": lambda have, want: want in have,
}
ROOTS = ("args", "principal", "tool", "ctx")
RULE_KEYS = {"id", "verdict", "tools", "effects", "roles", "when"}
_MISSING = object()


class PolicyError(ValueError):
    """The document is malformed; it must not be deployed."""


class Unknown(Exception):
    """A condition that cannot be evaluated on this call."""


def validate(doc: Mapping[str, Any]) -> list[str]:
    """Every problem in the document; empty means valid."""
    errors = [
        f"missing {k!r}"
        for k in ("policy", "version", "rules")
        if k not in doc
    ]
    if doc.get("default", "deny") not in VERDICTS:
        errors.append(f"bad default {doc.get('default')!r}")
    seen: set[str] = set()
    rules = doc.get("rules", [])
    if not isinstance(rules, list):
        return [*errors, "rules must be a list"]
    for rule in rules:
        errors += _rule_errors(rule, seen)
    return errors


def _rule_errors(rule: Any, seen: set[str]) -> list[str]:
    if not isinstance(rule, dict) or "id" not in rule:
        return [f"rule without an id: {rule!r}"]
    rid = str(rule["id"])
    duplicate = rid in seen
    seen.add(rid)
    errors = [f"{rid}: duplicate id"] if duplicate else []
    errors += [
        f"{rid}: unknown key {k!r}"
        for k in sorted(set(rule) - RULE_KEYS)
    ]
    not_lists = [
        f"{rid}: {k} must be a list"  # "a" in "abc" is True
        for k in ("tools", "effects", "roles", "when")
        if not isinstance(rule.get(k, []), list)
    ]
    if not_lists:
        return errors + not_lists
    if rule.get("verdict") not in VERDICTS:
        errors.append(
            f"{rid}: bad verdict {rule.get('verdict')!r}"
        )
    errors += [
        f"{rid}: unknown effect {e!r}"
        for e in rule.get("effects", [])
        if e not in EFFECTS
    ]
    for cond in rule.get("when", []):
        ok = isinstance(cond, list) and len(cond) == 3
        if not (ok and _path_ok(cond[0]) and cond[1] in OPS):
            errors.append(f"{rid}: bad condition {cond!r}")
    return errors


def _path_ok(path: Any) -> bool:
    if not isinstance(path, str):
        return False
    root, *parts = path.split(".")
    return root in ROOTS and not any(
        p.startswith("_") for p in parts
    )


def resolve(
    path: str, ctx: Context, spec: ToolSpec, call: ToolCall
) -> Any:
    """``args.amount``, ``principal.tenant``, ``ctx.labels``..."""
    root, *parts = path.split(".")
    value: Any = {
        "args": call.args,
        "principal": ctx.principal,
        "tool": spec,
        "ctx": ctx,
    }[root]
    for part in parts:
        if isinstance(value, Mapping):
            value = value.get(part, _MISSING)
        else:
            value = getattr(value, part, _MISSING)
        if value is _MISSING:
            raise Unknown(f"no {path}")
    return value


def _number(x: Any) -> float:
    """Ordering needs real, finite numbers: no bools, no NaN."""
    if isinstance(x, bool) or not isinstance(x, int | float):
        raise Unknown(f"not a number: {x!r}")
    if not math.isfinite(x):
        raise Unknown(f"not finite: {x!r}")
    return x


def holds(
    cond: list, ctx: Context, spec: ToolSpec, call: ToolCall
) -> bool:
    path, op, want = cond
    have = resolve(path, ctx, spec, call)
    if op in ORDERED:
        have, want = _number(have), _number(want)
    try:
        return bool(OPS[op](have, want))
    except TypeError as exc:
        raise Unknown(f"{path} {op} {want!r}") from exc


def matches(
    rule: Mapping, ctx: Context, spec: ToolSpec, call: ToolCall
) -> bool:
    """Scope first; conditions that cannot be evaluated count
    as a match for deny/approve rules, never for allow."""
    roles = set(rule.get("roles", []))
    if spec.name not in rule.get("tools", [spec.name]):
        return False
    if spec.effect not in rule.get("effects", [spec.effect]):
        return False
    if roles and not roles & ctx.principal.roles:
        return False
    try:
        return all(
            holds(c, ctx, spec, call)
            for c in rule.get("when", [])
        )
    except Unknown:
        return rule["verdict"] != "allow"  # fail closed


@dataclass(frozen=True)
class Ruling:
    verdict: str
    rule: str  # matched rule id, or "default"
    policy: str  # name@vN

    def decision(self) -> Decision:
        why = f"{self.rule} [{self.policy}]"
        return Decision(self.verdict, "policy", why)


@dataclass(frozen=True)
class Policy:
    name: str
    version: str
    default: str
    rules: tuple[dict, ...]
    digest: str  # sha256 of the canonical document

    @classmethod
    def load(cls, doc: Mapping[str, Any]) -> Policy:
        """Validate and freeze a copy; later edits to ``doc``
        cannot change what was loaded."""
        try:
            text = json.dumps(
                doc, sort_keys=True, allow_nan=False
            )
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"not plain JSON: {exc}") from exc
        data = json.loads(text)
        if errors := validate(data):
            raise PolicyError("; ".join(errors))
        digest = hashlib.sha256(text.encode()).hexdigest()
        return cls(
            data["policy"],
            str(data["version"]),
            data.get("default", "deny"),
            tuple(data["rules"]),
            digest,
        )

    @property
    def tag(self) -> str:
        return f"{self.name}@v{self.version}"

    def evaluate(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> Ruling:
        """Strictest matching rule wins; no match -> default."""
        hits = [
            r for r in self.rules if matches(r, ctx, spec, call)
        ]
        if not hits:
            return Ruling(self.default, "default", self.tag)
        rule = max(
            hits, key=lambda r: VERDICTS.index(r["verdict"])
        )
        return Ruling(rule["verdict"], rule["id"], self.tag)


def support_policy(version: str, refund_limit: float) -> dict:
    """The book's support-agent policy as a JSON-ready dict."""
    return {
        "policy": "support-agent",
        "version": version,
        "default": "deny",
        "rules": [
            {
                "id": "reads",
                "effects": ["read"],
                "roles": ["support"],
                "verdict": "allow",
            },
            {
                "id": "no-bulk-export",
                "tools": ["export_customers"],
                "verdict": "deny",
            },
            {
                "id": "refund-small",
                "tools": ["issue_refund"],
                "roles": ["support"],
                "when": [["args.amount", "<=", refund_limit]],
                "verdict": "allow",
            },
            {
                "id": "refund-large",
                "tools": ["issue_refund"],
                "when": [["args.amount", ">", refund_limit]],
                "verdict": "approve",
            },
            {
                "id": "no-email-after-untrusted",
                "tools": ["send_email"],
                "when": [["ctx.labels", "contains", "untrusted"]],
                "verdict": "deny",
            },
            {
                "id": "email",
                "tools": ["send_email"],
                "roles": ["support"],
                "verdict": "approve",
            },
        ],
    }
