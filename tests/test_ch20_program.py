import pytest

from ags.cli import main as cli
from ags.program import (
    PRACTICES,
    launch_review,
    red_team_check,
    risk_check,
    score,
    threat_check,
)
from ags.risk import required_controls

ALL = set(required_controls("high"))


def test_full_controls_and_layered_defense_approve():
    review = launch_review(ALL, "layered")
    assert review.approved and review.blockers() == []


def test_weak_defense_blocks_with_evidence():
    review = launch_review(ALL, "basic")
    (blocker,) = review.blockers()
    assert blocker.name == "red team"
    assert "breached:" in blocker.evidence


def test_trifecta_needs_flow_control():
    assert not threat_check(set()).passed
    assert threat_check({"flow-control"}).passed


def test_missing_controls_are_named():
    check = risk_check(ALL - {"red-team"})
    assert not check.passed and "red-team" in check.evidence


def test_red_team_check_counts_false_blocks():
    # strict blocks a legitimate task, so it cannot pass
    assert not red_team_check("strict").passed


def test_maturity_has_no_gaps_and_rejects_unknowns():
    s = {d.domain: d for d in score({"egress allowlist"})}
    assert s["boundary"].level == 0
    full = score({p for _, _, p in PRACTICES})
    assert all(d.level == 3 for d in full)
    with pytest.raises(ValueError):
        score({"trust me"})


def test_cli_gate_exit_codes(capsys):
    assert cli(["assess", "--gate"]) == 0
    assert cli(["assess", "--config", "none", "--gate"]) == 1
    assert cli(["assess", "--config", "none"]) == 0
    assert "BLOCKED" in capsys.readouterr().out


def test_cli_redteam_and_threats(capsys):
    cli(["redteam"])
    cli(["threats", "--top", "2"])
    out = capsys.readouterr().out
    assert "layered" in out and "T-001" in out


def test_example_runs(capsys):
    from ch20_governance_program import main

    main()
    out = capsys.readouterr().out
    assert "Review 2 (layered, all controls): APPROVED" in out
