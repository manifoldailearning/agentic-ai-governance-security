"""Chapter 20: a launch review gate and a maturity scorecard.

The first review runs with the basic defenses and two
controls missing: the board sees exactly which evidence
fails. After the layered defenses and missing controls land,
the same review approves the launch. The team then scores
its practices to plan the next quarter.
"""

from ags.program import launch_review, score
from ags.risk import required_controls

ALL = set(required_controls("high"))


def show(title: str, controls: set[str], config: str) -> None:
    review = launch_review(controls, config)
    verdict = "APPROVED" if review.approved else "BLOCKED"
    print(f"{title}: {verdict}")
    for c in review.checks:
        mark = "ok  " if c.passed else "FAIL"
        print(f"  {mark} {c.name}")
        if not c.passed:
            print(f"       {c.evidence}")


def main() -> None:
    gaps = ALL - {"human-approval", "red-team"}
    show("Review 1 (basic defenses)", gaps, "basic")
    show("Review 2 (layered, all controls)", ALL, "layered")
    in_place = {
        "agent has its own identity",
        "scoped, expiring delegation",
        "default-deny tool authorization",
        "tool results labeled by trust",
        "information flow control",
        "egress allowlist",
        "outbound DLP on email and URLs",
        "risky actions need approval",
        "red-team suite in CI",
        "every decision logged",
        "threat model per agent",
        "policy as code with tests",
        "tamper-evident audit trail",
    }
    print("Maturity (level, next step):")
    for d in score(in_place):
        nxt = d.next_steps[0] if d.next_steps else "-"
        print(f"  {d.domain:<10} {d.level} {nxt}")


if __name__ == "__main__":
    main()
