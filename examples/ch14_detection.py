"""Chapter 14: detecting attacks in the agent's event stream.

Five ordinary support tasks teach the detector what normal
looks like; five simulated attacks follow on the same agent.
Every row below comes from events the real runtime logged:
no alerts on normal work, and each attack caught with
evidence, even the ones the guard chain let through.
"""

from __future__ import annotations

from ags.detect import (
    ATTACKS,
    NORMAL,
    SequenceBaseline,
    default_rules,
    detect,
    effects_of,
    play,
    support_runtime,
)

SEV = {
    "low": "LOW",
    "medium": "MED",
    "high": "HIGH",
    "critical": "CRIT",
}


def main() -> None:
    env, rt = support_runtime()
    normal = play(rt, NORMAL)
    baseline = SequenceBaseline().fit(rt.log.events)
    attacks = play(rt, ATTACKS)

    def tenant_of(customer_id: str) -> str | None:
        return env.customers.get(customer_id, {}).get("tenant")

    rules = default_rules(
        effects_of(rt.tools.values()), tenant_of, baseline
    )
    alerts = detect(rt.log.events, rules)
    runs, events = len(normal) + len(attacks), len(rt.log.events)
    print(f"Stream: {runs} runs, {events} runtime events")
    print(f"Baseline: {len(baseline.counts)} distinct tool steps")
    normal_ids = {r.run_id for r in normal}
    noisy = [a for a in alerts if a.run_id in normal_ids]
    print(f"Normal runs: {len(noisy)} alerts")
    print(f"Attack runs: {len(alerts) - len(noisy)} alerts")
    for scenario, run in zip(ATTACKS, attacks, strict=True):
        print(
            f"{run.run_id} {scenario.name}: {len(run.calls)}"
            f" executed, {len(run.denied)} denied"
        )
        for a in alerts:
            if a.run_id == run.run_id:
                sev = SEV[a.severity]
                print(f"  {sev:<4} {a.rule:<25} {a.summary}")


if __name__ == "__main__":
    main()
