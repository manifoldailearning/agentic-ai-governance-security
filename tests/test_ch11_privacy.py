from __future__ import annotations

from ags.core import (
    EventLog,
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.privacy import (
    PURPOSES,
    ConsentRegistry,
    DataSubjectRequest,
    DictStore,
    EventStore,
    MinimizingTool,
    PurposeGuard,
    fulfil,
    minimize,
    pseudonym,
    retention_sweep,
)

ASHA = Principal("asha", tenant="acme")
KEY = b"test-key"
REFUND = PURPOSES["refund"]


def tool(name: str):
    _, tools = build_env()
    return {t.spec.name: t for t in tools}[name]


def test_minimize_projects_and_derives():
    record = {"id": "C-1", "card": "4111 1111 1111 1234", "x": 1}
    assert minimize(record, REFUND) == {
        "id": "C-1",
        "last4": "1234",
    }
    assert minimize([record], REFUND) == [
        minimize(record, REFUND)
    ]
    assert minimize("plain text", REFUND) == "plain text"


def test_minimizing_tool_drops_pii_label_and_fields():
    wrapped = MinimizingTool(tool("lookup_customer"), REFUND)
    assert "pii" not in wrapped.spec.labels
    out = wrapped.fn(customer_id="C-101")
    assert out == {
        "id": "C-101",
        "last4": "4444",
        "plan": "basic",
    }
    support = MinimizingTool(
        tool("lookup_customer"), PURPOSES["support"]
    )
    assert "pii" in support.spec.labels


def test_consent_is_required_and_revocable():
    consent = ConsentRegistry()
    consent.grant("C-100", "marketing")
    export = MinimizingTool(
        tool("export_customers"), PURPOSES["marketing"], consent
    )
    shared = [r for r in export.fn() if "withheld" not in r]
    assert [r["id"] for r in shared] == ["C-100"]
    consent.withdraw("C-100", "marketing")
    assert all("withheld" in r for r in export.fn())


def test_purpose_guard_in_runtime():
    env, tools = build_env()
    rt = Runtime(tools, [PurposeGuard(REFUND)])
    model = ScriptedModel(
        [
            call(
                "send_email",
                to="x@acme.example",
                subject="s",
                body="b",
            )
        ]
    )
    result = rt.run(ASHA, "refund", model)
    assert env.sent == []
    assert result.denied[0][1].guard == "purpose"


def test_erase_reaches_every_store_and_spares_lookalikes():
    env, tools = build_env()
    log = EventLog()
    rt = Runtime(tools, log=log)
    rt.run(
        ASHA,
        "check c-100",
        ScriptedModel([call("read_doc", doc_id="pricing")]),
    )
    memory = {
        "a": {"t": "C-100 likes email"},
        "b": {"t": "C-1000"},
    }
    ids = frozenset({"C-100"})
    report = fulfil(
        DataSubjectRequest("r1", "erase", ids),
        [
            DictStore("customers", env.customers),
            DictStore("memory", memory),
            EventStore("events", log.events),
        ],
        KEY,
    )
    assert report.found == {
        "customers": 1,
        "memory": 1,
        "events": 1,
    }
    assert "C-100" not in env.customers and list(memory) == ["b"]
    token = pseudonym(DataSubjectRequest("r1", "erase", ids), KEY)
    assert log.events[0].detail["task"] == f"check {token}"


def test_export_changes_nothing():
    env, _ = build_env()
    ids = frozenset({"CHEN@GLOBEX.EXAMPLE"})  # case-insensitive
    store = DictStore("customers", env.customers)
    report = fulfil(
        DataSubjectRequest("r2", "export", ids), [store], KEY
    )
    assert [r["name"] for r in report.export["customers"]] == [
        "Chen Wei"
    ]
    assert report.actions == {} and len(env.customers) == 3


def test_pseudonym_is_keyed_and_stable():
    req = DataSubjectRequest("r", "erase", frozenset({"a", "B"}))
    same = DataSubjectRequest("s", "erase", frozenset({"b", "A"}))
    assert pseudonym(req, KEY) == pseudonym(same, KEY)
    assert pseudonym(req, KEY) != pseudonym(req, b"other-key")


def test_retention_sweep_respects_holds():
    rows = {
        "old": {"ts": 0},
        "held": {"ts": 0},
        "new": {"ts": 90},
    }
    gone = retention_sweep(rows, 100, 30, frozenset({"held"}))
    assert gone == ["old"] and sorted(rows) == ["held", "new"]


def test_example_main(capsys):
    import ch11_privacy

    ch11_privacy.main()
    out = capsys.readouterr().out
    assert "minimized: {'id': 'C-100', 'last4': '1111'" in out
    assert "events     3 found  pseudonymized" in out
