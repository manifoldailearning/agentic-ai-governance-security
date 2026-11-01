"""Chapter 6: measure a detector, then put it to work.

First the injection detector is scored on a labeled corpus,
misses included. Then the inbox attack runs twice: once with
raw tool results and once with ``read_inbox`` wrapped in a
``ScreenedTool``, which quarantines the injected email and
spotlights the rest before the model ever sees it.
"""

from __future__ import annotations

from ags.core import (
    EXFIL,
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.injection import (
    CORPUS,
    Detector,
    Quarantine,
    ScreenedTool,
    evaluate,
)

ASHA = Principal("asha", tenant="acme")


def corpus_report() -> None:
    m = evaluate(Detector(threshold=0.5))
    attacks = sum(s.attack for s in CORPUS)
    print(f"Corpus: {len(CORPUS)} samples, {attacks} attacks")
    print(f"  TP {m.tp}  FP {m.fp}  TN {m.tn}  FN {m.fn}")
    print(
        f"  precision {m.precision:.2f}  recall {m.recall:.2f}"
        f"  F1 {m.f1:.2f}"
    )
    for s in m.wrong:
        kind = "missed" if s.attack else "false+"
        print(f"  {kind}: {s.text[:44]}...")


def triage(screen: bool, vault: Quarantine) -> None:
    env, tools = build_env()
    if screen:
        tools = [
            ScreenedTool(t, quarantine=vault)
            if t.spec.name == "read_inbox"
            else t
            for t in tools
        ]
    model = ScriptedModel([call("read_inbox")], gullible=True)
    result = Runtime(tools).run(ASHA, "Triage my inbox", model)
    leaks = [m for m in env.sent if m["to"] == EXFIL]
    print("  calls: ", ", ".join(c.name for c in result.calls))
    print("  labels:", ", ".join(sorted(result.labels)))
    print(f"  emails to {EXFIL}: {len(leaks)}")


def main() -> None:
    corpus_report()
    print("\nInbox attack, raw tool results:")
    triage(False, Quarantine())
    print("\nInbox attack, read_inbox screened:")
    vault = Quarantine()
    triage(True, vault)
    for held in vault.items:
        signals = ", ".join(held.finding.signals)
        print(f"  held {held.id} from {held.source}: {signals}")
        print(f"    {held.text[:56]}...")
    _, tools = build_env()
    inbox = next(t for t in tools if t.spec.name == "read_inbox")
    first = ScreenedTool(inbox).fn()[0]
    print(f"  model sees: {first[:47]}...")


if __name__ == "__main__":
    main()
