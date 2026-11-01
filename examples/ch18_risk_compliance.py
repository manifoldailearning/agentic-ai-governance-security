"""Chapter 18: tier a use case, keep a risk register, find gaps.

Run: python examples/ch18_risk_compliance.py
"""

from __future__ import annotations

import textwrap
from datetime import date

from ags.core import (
    EXFIL,
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.risk import (
    ILLUSTRATIVE,
    QUESTIONS,
    Risk,
    RiskRegister,
    assess,
    framework_gaps,
    infer_answers,
)

TODAY = date(2026, 11, 1)  # fixed review date for the example

USE_CASES = {  # autonomy data actions impact scale
    "doc-summarizer": "suggests internal none negligible team",
    "faq-bot": "suggests public none negligible public",
    "nudge-bot": "suggests personal none negligible public",
}
SUPPORT_AGENT = {  # data and actions are inferred from tools
    "autonomy": "approved",
    "impact": "financial",
    "scale": "customers",
}
RISKS = [  # id, title, likelihood, impact, owner, review by
    ("R1", "Injection leaks PII", None, 5, "ciso", "2027-01-15"),
    ("R2", "Refund over limit", 3, 4, "finance", "2026-10-01"),
    ("R3", "Cross-tenant lookup", 3, 5, "platform", "2027-02-01"),
    ("R4", "Tampered prompt", 2, 5, "platform", "2027-03-01"),
]  # None: likelihood measured by attacking the real runtime
IN_PLACE = [  # risk, control, claimed effectiveness
    ("R1", "flow-control", 0.8),
    ("R1", "injection-defense", 0.5),
    ("R1", "output-dlp", 0.5),
    ("R2", "human-approval", 0.6),
    ("R4", "inventory", 0.5),
]


def attack_succeeds() -> bool:
    """Evidence for likelihood: run the inbox attack unguarded."""
    env, tools = build_env()
    model = ScriptedModel([call("read_inbox")], gullible=True)
    asha = Principal("asha", tenant="acme")
    Runtime(tools).run(asha, "Triage my support inbox", model)
    return any(m["to"] == EXFIL for m in env.sent)


def tier_use_cases() -> list:
    cases = []
    for name, row in USE_CASES.items():
        answers = dict(zip(QUESTIONS, row.split(), strict=True))
        flags = {"covert_manipulation"} if "nudge" in name else ()
        cases.append(assess(name, answers, practices=flags))
    _, tools = build_env()
    inferred = infer_answers(t.spec for t in tools)
    cases.append(
        assess("support-agent", inferred | SUPPORT_AGENT)
    )
    return cases


def build_register() -> RiskRegister:
    reg = RiskRegister(appetite=6.0)
    measured = 5 if attack_succeeds() else 2
    for rid, title, odds, impact, owner, review in RISKS:
        odds = measured if odds is None else odds
        due = date.fromisoformat(review)
        reg.add(Risk(rid, title, odds, impact, owner, due))
    for rid, control, effectiveness in IN_PLACE:
        reg.mitigate(rid, control, effectiveness)
    return reg


def wrap(text: str) -> str:
    return textwrap.fill(
        text, 62, initial_indent="  ", subsequent_indent="    "
    )


def main() -> None:
    print("Use-case tiering")
    cases = tier_use_cases()
    for a in cases:
        why = a.drivers[0] if a.tier == "unacceptable" else ""
        line = f"  {a.use_case:14} {a.tier:12} {a.score:2}  {why}"
        print(line.rstrip())
    agent, reg = cases[-1], build_register()
    gaps = agent.gaps(reg.implemented())
    need, miss = len(agent.controls), len(gaps)
    print(f"support-agent: {miss} of {need} controls missing")
    print(wrap(", ".join(gaps)))
    print("Risk register: inherent -> residual (appetite 6)")
    for r in reg.risks.values():
        score = f"{r.inherent:2} -> {r.residual:4}"
        print(f"  {r.id} {r.title:22} {score}  {r.owner}")
    for issue, ids in reg.coverage(TODAY).items():
        print(f"  {issue + ':':15} {', '.join(ids) or '-'}")
    print(f"Framework gaps ({ILLUSTRATIVE})")
    for fw, areas in framework_gaps(reg.implemented()).items():
        print(wrap(f"{fw}: {', '.join(areas) or '-'}"))


if __name__ == "__main__":
    main()
