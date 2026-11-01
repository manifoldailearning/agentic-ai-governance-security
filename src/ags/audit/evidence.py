"""Audit evidence: answer an auditor's questions from the chain.

Auditors ask concrete questions. Who did what, for whom, under
which policy version, approved by whom? ``AuditEventLog`` and
``audited`` seal runtime events, policy decisions and human
approvals into one chain; ``evidence`` joins them per call,
and ``bundle`` packages the answers with the verification.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ags.audit.chain import (
    Anchor,
    AuditLog,
    Entry,
    Verification,
    canonical,
)
from ags.core import (
    Context,
    Decision,
    Event,
    EventLog,
    ToolCall,
    ToolSpec,
)
from ags.core.runtime import Approver


class AuditEventLog(EventLog):
    """An ``EventLog`` that also seals each event into a chain."""

    def __init__(self, audit: AuditLog) -> None:
        super().__init__()
        self.audit = audit

    def add(self, event: Event) -> Event:
        self.audit.append(event)
        return super().add(event)


def audited(
    approver: Approver, audit: AuditLog, who: str
) -> Approver:
    """Wrap an approver so every yes or no is sealed too."""

    def approve(
        ctx: Context, spec: ToolSpec, call: ToolCall, d: Decision
    ) -> bool:
        ok = bool(approver(ctx, spec, call, d))
        audit.append(
            {
                "kind": "approval",
                "ts": ctx.now,
                "run_id": ctx.run_id,
                "tool": spec.name,
                "args": call.args,
                "approver": who,
                "approved": ok,
                "reason": d.reason,
            }
        )
        return ok

    return approve


@dataclass(frozen=True)
class Finding:
    seq: int  # chain position of the tool call
    run_id: str
    actor: str  # the agent
    principal: str  # on whose behalf
    tenant: str
    tool: str
    args: dict[str, Any]
    verdict: str
    policy: str  # name@vN rule, or "-"
    approvals: tuple[str, ...]


def _call_key(r: Mapping[str, Any], args: Any) -> tuple:
    return (r["run_id"], r["tool"], canonical(args))


def evidence(
    entries: Iterable[Entry], **match: Any
) -> list[Finding]:
    """Tool calls matching ``match`` with their decision and
    approvals joined in. Verify the chain before trusting it."""
    policy: dict[tuple, str] = {}
    approvals: dict[tuple, list[str]] = defaultdict(list)
    found = []
    for entry in entries:
        r = entry.record
        if r.get("kind") == "policy_decision":
            tag = f"{r['policy']}@v{r['version']} {r['rule']}"
            policy[_call_key(r, r["args"])] = tag
        elif r.get("kind") == "approval":
            said = "approved" if r["approved"] else "refused"
            note = f"{r['approver']} {said} at t={r['ts']:g}"
            approvals[_call_key(r, r["args"])].append(note)
        elif r.get("kind") == "tool_call":
            args = r["detail"].get("args", {})
            key = _call_key(r, args)  # pop: pair each call once
            rule = policy.pop(key, "-")
            yes_no = tuple(approvals.pop(key, ()))
            if all(r.get(k) == v for k, v in match.items()):
                who = (r["run_id"], r["actor"], r["principal"])
                found.append(
                    Finding(
                        entry.seq,
                        *who,
                        r["tenant"],
                        r["tool"],
                        args,
                        r["verdict"],
                        rule,
                        yes_no,
                    )
                )
    return found


def bundle(
    entries: list[Entry],
    result: Verification,
    findings: Iterable[Finding],
    anchors: Iterable[Anchor] = (),
) -> dict[str, str]:
    """``evidence.json`` plus a Markdown summary bound to it."""
    findings = list(findings)
    data = {
        "verification": asdict(result),
        "key_ids": sorted({e.key_id for e in entries}),
        "anchors": [asdict(a) for a in anchors],
        "findings": [asdict(f) for f in findings],
        "entries": [asdict(e) for e in entries],
    }
    body = json.dumps(data, indent=1, sort_keys=True)
    digest = hashlib.sha256(body.encode()).hexdigest()
    return {
        "evidence.json": body,
        "summary.md": _summary(
            result, findings, digest, len(entries)
        ),
    }


COLUMNS = (
    "seq",
    "run",
    "agent",
    "for",
    "tool",
    "verdict",
    "policy",
    "approvals",
)


def _row(cells: Iterable[Any]) -> str:
    return "| " + " | ".join(map(str, cells)) + " |"


def _summary(
    result: Verification,
    findings: list[Finding],
    digest: str,
    n: int,
) -> str:
    lines = [
        "# Audit evidence summary",
        "",
        f"- Entries: {n}",
        f"- Chain verification: {result}",
        f"- evidence.json sha256: `{digest}`",
        "",
        _row(COLUMNS),
        _row("---" for _ in COLUMNS),
    ]
    for f in findings:
        who = f"{f.principal} ({f.tenant})"
        approvals = "; ".join(f.approvals) or "-"
        lines.append(
            _row(
                [
                    f.seq,
                    f.run_id,
                    f.actor,
                    who,
                    f.tool,
                    f.verdict,
                    f.policy,
                    approvals,
                ]
            )
        )
    return "\n".join(lines) + "\n"


def write_bundle(
    files: Mapping[str, str], directory: str | Path
) -> list[Path]:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    paths = [out / name for name in sorted(files)]
    for p in paths:
        p.write_text(files[p.name])
    return paths
