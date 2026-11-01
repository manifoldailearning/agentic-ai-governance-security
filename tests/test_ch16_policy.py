import pytest

from ags.core import (
    Context,
    Principal,
    Runtime,
    ScriptedModel,
    ToolCall,
    build_env,
    call,
)
from ags.policy import (
    Policy,
    PolicyError,
    compile_policy,
    impact,
    run_cases,
    support_policy,
    validate,
)

_, TOOLS = build_env()
SPECS = {t.spec.name: t.spec for t in TOOLS}
SUPPORT = Principal(
    "asha", tenant="acme", roles=frozenset({"support"})
)
V1 = Policy.load(support_policy("1", refund_limit=200))


def verdict(policy, tool, args=None, who=SUPPORT, labels=()):
    ctx = Context("t", "agent", who, set(labels))
    call = ToolCall("c", tool, args or {})
    return policy.evaluate(ctx, SPECS[tool], call).verdict


def refund(amount):
    return {"customer_id": "C-100", "amount": amount}


def test_validate_reports_typos_and_bad_rules():
    doc = support_policy("9", 200)
    doc["rules"] += [
        {
            "id": "x",
            "verdict": "allow",
            "whn": [["args.a", "<", 1]],
        },
        {"id": "x", "verdict": "permit"},
        {"id": "y", "verdict": "deny", "tools": "issue_refund"},
        {
            "id": "z",
            "verdict": "deny",
            "when": [["env.x", "~", 1]],
        },
    ]
    errors = validate(doc)
    assert "x: unknown key 'whn'" in errors
    assert "x: duplicate id" in errors
    assert "x: bad verdict 'permit'" in errors
    assert "y: tools must be a list" in errors
    assert any(e.startswith("z: bad condition") for e in errors)
    with pytest.raises(PolicyError):
        Policy.load(doc)


def test_strictest_matching_rule_wins_default_denies():
    assert verdict(V1, "lookup_customer") == "allow"
    assert verdict(V1, "export_customers") == "deny"  # reads+deny
    nobody = Principal("eve", tenant="acme")
    assert verdict(V1, "lookup_customer", who=nobody) == "deny"
    assert verdict(V1, "run_python") == "deny"  # no rule: default


@pytest.mark.parametrize(
    "amount", ["90", float("nan"), float("inf"), True, None]
)
def test_unevaluable_amounts_fail_closed(amount):
    assert (
        verdict(V1, "issue_refund", refund(amount)) == "approve"
    )


def test_missing_argument_fails_closed():
    assert verdict(
        V1, "issue_refund", {"customer_id": "C-1"}
    ) == ("approve")


def test_context_labels_drive_decisions():
    assert verdict(V1, "send_email") == "approve"
    tainted = verdict(V1, "send_email", labels={"untrusted"})
    assert tainted == "deny"


def test_load_freezes_a_copy_and_digest_tracks_content():
    doc = support_policy("1", 200)
    policy = Policy.load(doc)
    doc["rules"].clear()  # editing the source afterwards...
    assert (
        verdict(policy, "lookup_customer") == "allow"
    )  # ...no effect
    assert policy.digest == V1.digest
    same_version = Policy.load(support_policy("1", 999))
    assert same_version.digest != V1.digest
    with pytest.raises(PolicyError):
        Policy.load(
            {**support_policy("1", 200), "x": float("nan")}
        )


def test_guard_logs_each_decision_with_version():
    seen = []
    guard = compile_policy(support_policy("1", 200), seen.append)
    _, tools = build_env()
    rt = Runtime(tools, [guard])
    model = ScriptedModel([call("issue_refund", **refund(500))])
    res = rt.run(SUPPORT, "Refund 500", model)
    assert res.denied[0][1].reason == (
        "no approver: refund-large [support-agent@v1]"
    )
    (record,) = guard.decisions
    assert seen == [record]
    assert (record.rule, record.version) == ("refund-large", "1")
    assert record.digest == V1.digest


def test_run_cases_flags_wrong_expectations():
    cases = [
        {
            "name": "ok",
            "tool": "read_doc",
            "roles": ["support"],
            "expect": "allow",
        },
        {"name": "wrong", "tool": "read_doc", "expect": "allow"},
    ]
    results = run_cases(V1, cases, SPECS)
    assert [r.passed for r in results] == [True, False]
    assert results[1].got.rule == "default"


def test_impact_lists_only_changed_decisions():
    _, tools = build_env()
    guard = compile_policy(support_policy("1", 200))
    rt = Runtime(tools, [guard], approver=lambda *a: True)
    for amount in (50, 150, 300):
        step = call("issue_refund", **refund(amount))
        rt.run(SUPPORT, "refund", ScriptedModel([step]))
    v2 = Policy.load(support_policy("2", 100))
    calls = rt.log.where(kind="tool_call")
    changes = impact(calls, V1, v2, SPECS, {"asha": SUPPORT})
    assert [
        c.event.detail["args"]["amount"] for c in changes
    ] == [150]
    assert changes[0].after.rule == "refund-large"
    # without a directory roles are unknown and replay misleads
    blind = impact(calls, V1, v2, SPECS)
    assert [c.before.rule for c in blind] == ["default"]


def test_example_shows_impact(capsys):
    from ch16_policy_as_code import main

    main()
    out = capsys.readouterr().out
    assert "7/7 passed" in out
    assert "2 changed; 2 now need approval" in out
