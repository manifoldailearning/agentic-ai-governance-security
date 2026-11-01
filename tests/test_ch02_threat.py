from __future__ import annotations

import ch02_threat_model as ch02
from ags.core import ToolSpec, build_env
from ags.threat import (
    Threat,
    from_specs,
    threat_register,
    to_markdown,
)
from ags.threat.model import zone_of


def specs(*drop: str) -> list[ToolSpec]:
    _, tools = build_env()
    return [t.spec for t in tools if t.spec.name not in drop]


def test_model_has_core_elements_and_tool_zones():
    m = from_specs("agent", specs())
    assert {"user", "agent", "llm"} <= set(m.elements)
    assert m.elements["read_inbox"].zone == "internet"
    assert m.elements["fetch_url"].zone == "internet"
    assert m.elements["lookup_customer"].zone == "internal"
    assert zone_of(ToolSpec("x", "external")) == "internet"


def test_trifecta_detected_with_all_three_legs():
    legs = ch02.trifecta(from_specs("agent", specs()))
    assert legs == {
        "untrusted": ["fetch_url", "read_inbox"],
        "sensitive": [
            "export_customers",
            "lookup_customer",
            "read_doc",
        ],
        "external": ["fetch_url", "send_email"],
    }


def test_removing_any_leg_breaks_the_trifecta():
    no_egress = from_specs("a", specs("send_email", "fetch_url"))
    no_untrusted = from_specs(
        "a", specs("read_inbox", "fetch_url")
    )
    for m in (no_egress, no_untrusted):
        assert ch02.trifecta(m) is None
        cats = {t.category for t in threat_register(m)}
        assert "Lethal trifecta" not in cats


def test_register_is_ranked_with_sequential_ids():
    threats = threat_register(from_specs("agent", specs()))
    scores = [t.score for t in threats]
    assert scores == sorted(scores, reverse=True)
    assert [t.id for t in threats[:3]] == [
        "T-001",
        "T-002",
        "T-003",
    ]
    assert threats[0].category == "Lethal trifecta"
    top = {
        t.category for t in threats if t.severity == "critical"
    }
    assert "Spoofing" not in top  # generic STRIDE ranks lower


def test_cross_tenant_only_for_shared_pii_elements():
    def targets(m):
        found = threat_register(m)
        return {t.target for t in found if "tenant" in t.category}

    stores = {"crm-db": ["lookup_customer"], "wiki": ["read_doc"]}
    m = from_specs("a", specs(), stores)
    assert targets(m) == {
        "lookup_customer",
        "export_customers",
        "crm-db",
    }
    assert not any(
        m.crosses(f) for f in m.flows if f.src == "wiki"
    )
    single = from_specs("a", specs(), stores, multi_tenant=False)
    assert targets(single) == set()


def test_read_only_internal_agent_has_no_agentic_threats():
    m = from_specs("faq", [ToolSpec("read_doc", "read", "low")])
    cats = {t.category for t in threat_register(m)}
    agentic = {
        "Prompt injection",
        "Tool misuse",
        "Excessive agency",
    }
    assert not cats & (agentic | {"Data exfiltration"})


def test_severity_bands():
    def sev(lk, im):
        return Threat("Spoofing", "x", "y", lk, im).severity

    assert [sev(5, 4), sev(3, 4), sev(2, 3), sev(1, 5)] == [
        "critical",
        "high",
        "medium",
        "low",
    ]


def test_markdown_register_has_a_row_per_threat():
    m = from_specs("agent", specs())
    threats = threat_register(m)
    md = to_markdown(m, threats)
    rows = [r for r in md.splitlines() if r.startswith("| T-")]
    assert len(rows) == len(threats)
    assert all(r.rstrip(" |").split(" | ")[-1] for r in rows)
    assert "ch07" in rows[0]


def test_example_main(capsys):
    ch02.main()
    out = capsys.readouterr().out
    assert "T-001 25 Lethal trifecta" in out
    assert "trifecta broken" in out
    assert "mailed 3 card numbers" in out
