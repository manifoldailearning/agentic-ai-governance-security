"""Command line for the security gate and red-team suite.

    ags assess [--config layered] [--gate]
    ags redteam
    ags threats

``assess --gate`` exits non-zero when the launch review
fails, so CI can block a release on missing evidence.
"""

from __future__ import annotations

import argparse
import sys

from ags.core import build_env
from ags.program import launch_review
from ags.redteam import CONFIGS, evaluate, gate
from ags.risk import required_controls
from ags.threat import from_specs, threat_register


def assess(args: argparse.Namespace) -> int:
    controls = set(required_controls("high"))
    if args.without:
        controls -= set(args.without.split(","))
    review = launch_review(controls, args.config)
    print(f"Launch review: {review.agent} ({review.config})")
    for c in review.checks:
        mark = "PASS" if c.passed else "FAIL"
        print(f"  {mark}  {c.name}")
        print(f"        {c.evidence}")
    verdict = "APPROVED" if review.approved else "BLOCKED"
    print(f"Decision: {verdict}")
    return 1 if args.gate and not review.approved else 0


def redteam(args: argparse.Namespace) -> int:
    print(f"{'config':<9}{'ASR':>5}  gate")
    for name, defense in CONFIGS.items():
        rep = evaluate(name, defense)
        ok = "PASS" if gate(rep).passed else "FAIL"
        print(f"{name:<9}{rep.asr():>5.0%}  {ok}")
    return 0


def threats(args: argparse.Namespace) -> int:
    _, tools = build_env()
    model = from_specs("support-agent", [t.spec for t in tools])
    for t in threat_register(model)[: args.top]:
        print(f"{t.id} {t.score:>2} {t.category:<20}{t.target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ags")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assess", help="launch review")
    a.add_argument(
        "--config", default="layered", choices=sorted(CONFIGS)
    )
    a.add_argument(
        "--without",
        default="",
        help="comma-separated controls to drop",
    )
    a.add_argument("--gate", action="store_true")
    a.set_defaults(fn=assess)
    sub.add_parser("redteam", help="red-team table").set_defaults(
        fn=redteam
    )
    t = sub.add_parser("threats", help="top threats")
    t.add_argument("--top", type=int, default=8)
    t.set_defaults(fn=threats)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
