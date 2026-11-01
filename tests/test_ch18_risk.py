from __future__ import annotations

from datetime import date

import pytest

from ags.core import build_env
from ags.risk import (
    CONTROLS,
    FRAMEWORKS,
    QUESTIONS,
    Risk,
    RiskRegister,
    areas_for,
    assess,
    band,
    framework_gaps,
    infer_answers,
    required_controls,
)

LOW = {q: next(iter(opts)) for q, opts in QUESTIONS.items()}


def test_typical_use_cases_land_in_expected_tiers():
    assert assess("summarizer", LOW).tier == "minimal"
    faq = assess("faq", LOW | {"scale": "public"})
    assert faq.tier == "limited"
    agent = assess(
        "support",
        LOW
        | {
            "data": "personal",
            "actions": "irreversible",
            "impact": "financial",
            "scale": "customers",
        },
    )
    assert agent.tier == "high"
    assert "actions=irreversible" in agent.drivers
    assert agent.controls == required_controls("high")


def test_one_severe_answer_is_not_averaged_away():
    safety = assess(
        "triage", LOW | {"impact": "rights_or_safety"}
    )
    assert safety.tier == "high" and safety.score == 3
    alone = LOW | {
        "autonomy": "acts_alone",
        "actions": "irreversible",
    }
    assert assess("ops", alone).tier == "high"


def test_red_line_cannot_be_dodged_by_case_or_spaces():
    a = assess("nudge", LOW, practices={"  Covert_Manipulation "})
    assert a.tier == "unacceptable"
    assert a.controls == ()
    assert (
        assess("ok", LOW, practices={"marketing"}).tier
        == "minimal"
    )


@pytest.mark.parametrize(
    "answers",
    [
        {k: v for k, v in LOW.items() if k != "scale"},
        LOW | {"data": "Public"},
        LOW | {"vibes": "good"},
    ],
)
def test_incomplete_or_unknown_answers_raise(answers):
    with pytest.raises(ValueError):
        assess("x", answers)


def test_answers_inferred_from_real_tools():
    _, tools = build_env()
    specs = [t.spec for t in tools]
    assert infer_answers(specs) == {
        "data": "personal",
        "actions": "irreversible",
    }
    docs = [s for s in specs if s.name == "read_doc"]
    assert infer_answers(docs) == {
        "data": "internal",
        "actions": "none",
    }


def test_catalog_and_mappings_are_consistent():
    tiers = required_controls("high")
    assert set(tiers) == set(
        CONTROLS
    )  # every control is required
    assert required_controls("minimal") == tiers[:2]
    assert required_controls("unacceptable") == ()
    for areas in FRAMEWORKS.values():
        for controls in areas.values():
            assert set(controls) <= set(CONTROLS)
    assert "NIST AI RMF: Manage" in areas_for("human-approval")


def test_residual_score_and_input_validation():
    reg = RiskRegister()
    r = reg.add(
        Risk("R1", "exfil", 5, 5, "ciso", date(2027, 1, 1))
    )
    reg.mitigate("R1", "flow-control", 0.8)
    reg.mitigate("R1", "output-dlp", 0.5)
    assert (r.inherent, r.residual) == (25, 2.5)
    assert band(r.inherent) == "critical" and band(2.5) == "low"
    with pytest.raises(ValueError):
        reg.mitigate("R1", "flow-control", 1.0)  # never perfect
    with pytest.raises(ValueError):
        reg.mitigate("R1", "magic-firewall", 0.5)
    with pytest.raises(ValueError):
        reg.add(Risk("R1", "dup", 1, 1, "x", date(2027, 1, 1)))
    with pytest.raises(ValueError):
        Risk("R2", "bad", 0, 6, "x", date(2027, 1, 1))


def test_coverage_and_framework_gaps():
    reg = RiskRegister(appetite=6.0)
    reg.add(Risk("R1", "a", 4, 4, "o", date(2026, 1, 1)))
    reg.add(Risk("R2", "b", 2, 2, "o", date(2027, 1, 1)))
    reg.mitigate("R2", "human-approval", 0.5)
    cov = reg.coverage(today=date(2026, 6, 1))
    assert cov == {
        "no controls": ["R1"],
        "above appetite": ["R1"],
        "review overdue": ["R1"],
    }
    gaps = framework_gaps(reg.implemented())
    assert "Human oversight" not in gaps["EU AI Act"]
    assert "Govern" in gaps["NIST AI RMF"]
    assert "| R1 | a | 4x4 | 16 (critical)" in reg.to_markdown()


def test_example_main(capsys):
    from ch18_risk_compliance import main

    main()
    out = capsys.readouterr().out
    assert "red line: covert_manipulation" in out
    assert "R1 Injection leaks PII    25 ->  1.2" in out
    assert "not legal advice" in out
