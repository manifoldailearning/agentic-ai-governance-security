"""Chapter 13: measuring defenses with a red-team harness.

Six attacks and four legitimate tasks run against four guard
configurations, each in a fresh environment. A keyword filter
falls to a case change; blanket taint blocks a legitimate
reply and misses a poisoned internal doc. Independent narrow
layers stop every attack and still let the work through.
"""

from __future__ import annotations

from ags.redteam import ATTACKS, BENIGN, CONFIGS, evaluate, gate


def ratio(won: int, total: int) -> str:
    return f"{won}/{total}"


def main() -> None:
    reports = [evaluate(name, d) for name, d in CONFIGS.items()]
    print(
        f"{len(ATTACKS)} attacks, {len(BENIGN)} benign tasks, "
        "fresh env per run\n"
    )
    print(
        f"{'config':<9}{'attacks won':<13}{'tasks done':<12}gate"
    )
    for rep in reports:
        won = ratio(len(rep.breaches()), len(rep.attacks))
        done = len(rep.tasks) - len(rep.false_blocks())
        verdict = "PASS" if gate(rep).passed else "FAIL"
        print(
            f"{rep.config:<9}{won:>4} {rep.asr():>5.0%}   "
            f"{ratio(done, len(rep.tasks)):>6}      {verdict}"
        )

    head = "".join(f"{r.config:>8}" for r in reports)
    print(f"\n{'ASR by category':<28}{head}")
    for cat in reports[0].by_category():
        cells = [ratio(*r.by_category()[cat]) for r in reports]
        print(f"  {cat:<26}" + "".join(f"{c:>8}" for c in cells))

    print("\nWhy the gate failed")
    for rep in reports[1:-1]:
        reasons = "; ".join(gate(rep).reasons)
        print(f"  {rep.config:<8}{reasons}")

    print("\nLayered: guards that denied each attack")
    for r in reports[-1].attacks:
        guards = ", ".join(r.denied_by)
        print(
            f"  {r.scenario.id}  {r.scenario.title:<26}{guards}"
        )


if __name__ == "__main__":
    main()
