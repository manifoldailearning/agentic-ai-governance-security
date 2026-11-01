from __future__ import annotations

import base64
import json

import pytest

import ch05_secrets as ch05
from ags.core import (
    Context,
    Principal,
    Runtime,
    ScriptedModel,
    Tool,
    ToolCall,
    ToolSpec,
    call,
)
from ags.secrets import (
    LeakScanner,
    SecretArgGuard,
    SecretBroker,
    SecretError,
    SecretRedactor,
    handle,
)

V1 = "tok_test_FirstExampleValue1"  # example values only
V2 = "tok_test_9xQ2mZ7rL4vK8pW3"
CTX = Context("r", "agent", Principal("asha", tenant="acme"))


@pytest.fixture
def broker() -> SecretBroker:
    b = SecretBroker()
    b.put("api", V1)
    b.rotate("api", V2)
    b.grant("api", "crm")
    return b


def echo_tool() -> Tool:
    return Tool(
        ToolSpec("crm", "read"), lambda key: f"used {key}"
    )


def test_resolve_only_for_granted_tools(broker):
    assert broker.resolve("crm", {"k": [handle("api")]}) == {
        "k": [V2]
    }
    with pytest.raises(SecretError, match="not granted"):
        broker.resolve("send_email", handle("api"))
    with pytest.raises(SecretError, match="unknown"):
        broker.resolve("crm", handle("nope"))


def test_rotation_and_vault_rules(broker):
    assert broker.current("api") == V2
    assert set(broker.known_values()) == {V1, V2}
    with pytest.raises(KeyError):
        broker.rotate("missing", V2)
    with pytest.raises(ValueError):
        broker.put("short", "abc")


def test_bound_tool_scrubs_its_result(broker):
    tool = broker.bind(echo_tool())
    assert tool.fn(key=handle("api")) == "used [api@v2]"


def test_event_log_holds_handles_never_values(broker):
    rt = Runtime([broker.bind(echo_tool())])
    plan = [call("crm", key=handle("api"))]
    rt.run(CTX.principal, "t", ScriptedModel(plan))
    log = json.dumps([e.to_dict() for e in rt.log.events])
    assert handle("api") in log and V2 not in log


def test_scanner_finds_encoded_and_cased_values(broker):
    scan = LeakScanner(broker.known_values)
    b64 = base64.urlsafe_b64encode(V2.encode()).decode()
    for text in (V1, f"x {V2.upper()} y", b64, V2.encode().hex()):
        kinds = {f.kind for f in scan.scan(text)}
        assert any(k.startswith("known:api@") for k in kinds)


def test_scanner_patterns_entropy_and_no_false_positives():
    scan = LeakScanner()
    hits = {
        "-----BEGIN RSA PRIVATE KEY-----": "pattern:private-key",
        "Bearer abcdefghij0123456789": "pattern:bearer",
        "password = hunter2hunter2": "pattern:key-assignment",
        "blob 9fK2xQ7mZ1vR8tL3wP6yB4nC": "entropy",
    }
    for text, kind in hits.items():
        assert any(
            f.kind.startswith(kind) for f in scan.scan(text)
        )
    benign = (
        "Asha Rao, asha@acme.example, C-100, refund_eligibility"
    )
    assert scan.scan(benign) == []


def test_redact_merges_overlapping_findings(broker):
    scan = LeakScanner(broker.known_values)
    out = scan.redact(f"key={V2} done")
    assert V2 not in out and out.endswith(" done")
    assert out.count("[REDACTED") == 1


def test_arg_guard_handles_values_and_smuggling(broker):
    guard = SecretArgGuard(
        LeakScanner(broker.known_values), broker
    )
    crm, mail = (
        ToolSpec("crm", "read"),
        ToolSpec("send_email", "external"),
    )

    def verdict(spec, **args):
        return guard.check(
            CTX, spec, ToolCall("c", spec.name, args)
        )

    assert verdict(crm, key=handle("api")).allowed
    assert not verdict(mail, body=handle("api")).allowed
    assert not verdict(
        mail, body=handle(V2)
    ).allowed  # name smuggling
    nested = verdict(mail, body={"parts": ["hi", V1]})
    assert "body.parts[1] carries known:api@v1" in nested.reason


def test_redactor_rewrites_final_answer(broker):
    scan = LeakScanner(broker.known_values)
    rt = Runtime([], output_guards=[SecretRedactor(scan)])
    model = ScriptedModel([], answer=f"the key is {V2}")
    out = rt.run(CTX.principal, "t", model).output
    assert out == "the key is [REDACTED:known:api@v2]"
    [event] = rt.log.where(kind="output", guard="secret-redact")
    assert event.reason.startswith("redacted known:api@v2")
    assert V2 not in json.dumps(event.to_dict())


def test_example_main(capsys):
    ch05.main()
    out = capsys.readouterr().out
    assert "handle crm_api not granted to send_email" in out
    assert "emails sent: 0, keys in log: 0" in out
    assert "keys in log: 1" in out
