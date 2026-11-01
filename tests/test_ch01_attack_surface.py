from __future__ import annotations

import ch01_attack_surface as ch01
from ags.core import EXFIL


def test_injected_inbox_exfiltrates_every_customer():
    env, result = ch01.triage(benign=False)
    assert [c.name for c in result.calls] == [
        "read_inbox",
        "export_customers",
        "send_email",
    ]
    rows = ch01.leaked(env)
    assert len(rows) == 3
    assert {r["tenant"] for r in rows} == {"acme", "globex"}


def test_run_accumulates_labels_of_everything_seen():
    _, result = ch01.triage(benign=False)
    assert result.labels == {"untrusted", "pii", "bulk"}


def test_attack_looks_like_success_to_the_user():
    _, result = ch01.triage(benign=False)
    assert result.status == "completed"
    assert result.denied == []
    assert "EXFIL" not in result.output


def test_benign_inbox_sends_nothing():
    env, result = ch01.triage(benign=True)
    assert [c.name for c in result.calls] == ["read_inbox"]
    assert env.sent == [] and ch01.leaked(env) == []


def test_leaked_ignores_mail_to_legitimate_recipients():
    env, _ = ch01.triage(benign=True)
    env.sent.append({"to": "asha@acme.example", "body": "[]"})
    assert ch01.leaked(env) == []
    env.sent.append({"to": EXFIL, "body": '[{"tenant": "x"}]'})
    assert len(ch01.leaked(env)) == 1


def test_example_main(capsys):
    ch01.main()
    out = capsys.readouterr().out
    assert "leaked:  3 records, 3 card numbers" in out
    assert "emailed: nothing" in out
