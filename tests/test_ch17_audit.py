import copy
import json
from dataclasses import replace

import pytest

from ags.audit import (
    AuditEventLog,
    AuditLog,
    audited,
    bundle,
    canonical,
    evidence,
    load,
    save,
    verify,
    write_bundle,
)
from ags.core import (
    Principal,
    Runtime,
    ScriptedModel,
    build_env,
    call,
)
from ags.policy import compile_policy, support_policy

KEY = b"test-key-example-only"
KEYS = {"k1": KEY}


def chain(n=10, anchor_every=0):
    log = AuditLog(KEY, "k1", anchor_every)
    for i in range(n):
        log.append({"kind": "note", "i": i, "who": "asha"})
    return log


def test_clean_chain_verifies():
    log = chain(10, anchor_every=5)
    result = verify(log.entries, KEYS, log.anchors)
    assert result.ok and result.checked == 10
    assert [a.seq for a in log.anchors] == [4, 9]


def test_altered_content_is_pinpointed():
    entries = chain().entries
    record = copy.deepcopy(entries[4].record) | {"who": "mallory"}
    entries[4] = replace(entries[4], record=record)
    result = verify(entries, KEYS)
    assert (result.bad_index, result.problem) == (
        4,
        "content altered",
    )


@pytest.mark.parametrize(
    "edit, index",
    [
        (lambda e: e[:3] + e[4:], 3),  # delete
        (lambda e: [e[0], e[2], e[1], *e[3:]], 1),  # swap
        (lambda e: e[2:], 0),  # cut the head
    ],
)
def test_deleted_or_moved_entries_break_the_chain(edit, index):
    result = verify(edit(chain().entries), KEYS)
    assert result.bad_index == index
    assert result.problem.startswith("chain broken")


def test_anchors_catch_truncation_and_rewrite_with_key():
    log = chain(10, anchor_every=5)
    assert not verify(
        log.entries[:8], KEYS
    ).bad_index  # no anchors
    cut = verify(log.entries[:8], KEYS, log.anchors)
    assert cut.problem.startswith("truncated")
    forged = AuditLog(KEY, "k1")  # insider holding the key
    for e in log.entries:
        forged.append(e.record | {"who": "mallory"})
    rewrite = verify(forged.entries, KEYS, log.anchors)
    assert (rewrite.bad_index, rewrite.problem) == (
        4,
        "anchor mismatch: log rewritten",
    )


def test_keys_rotate_and_unknown_or_wrong_keys_fail():
    log = chain(3)
    log.rotate(b"second-example-key", "k2")
    log.append({"kind": "note", "i": 3})
    both = {"k1": KEY, "k2": b"second-example-key"}
    assert verify(log.entries, both).ok
    assert (
        verify(log.entries, KEYS).problem == "unknown key id 'k2'"
    )
    wrong = {"k1": b"guess", "k2": b"guess"}
    assert verify(log.entries, wrong).bad_index == 0


def test_canonical_form_and_private_copies():
    assert (
        canonical({"b": 1, "a": "é"})
        == '{"a":"é","b":1}'.encode()
    )
    with pytest.raises(ValueError):
        canonical({"x": float("nan")})
    log = AuditLog(KEY, "k1")
    source = {"kind": "note", "args": {"amount": 450}}
    log.append(source)
    source["args"]["amount"] = 45  # caller mutates afterwards
    assert verify(log.entries, KEYS).ok
    assert log.entries[0].record["args"]["amount"] == 450


def test_jsonl_round_trip_and_text_tamper(tmp_path):
    path = tmp_path / "audit.jsonl"
    save(chain(5).entries, path)
    assert verify(load(path), KEYS).ok
    lines = path.read_text().splitlines()
    row = json.loads(lines[2])
    row["record"]["i"] = float("nan")  # not even valid JSON now
    lines[2] = json.dumps(row)
    path.write_text("\n".join(lines))
    assert verify(load(path), KEYS).bad_index == 2


def test_evidence_joins_policy_and_approval(tmp_path):
    log = AuditLog(KEY, "k1")
    _, tools = build_env()
    rt = Runtime(
        tools,
        [compile_policy(support_policy("3", 100), log.append)],
        approver=audited(lambda *a: False, log, "lead:ravi"),
        log=AuditEventLog(log),
    )
    who = Principal(
        "asha", tenant="acme", roles=frozenset({"support"})
    )
    step = call("issue_refund", customer_id="C-101", amount=300)
    rt.run(who, "refund", ScriptedModel([step, step]))
    found = evidence(log.entries, tool="issue_refund")
    assert len(found) == 2 and all(
        f.verdict == "deny" for f in found
    )
    assert found[0].policy == "support-agent@v3 refund-large"
    assert found[1].approvals == ("lead:ravi refused at t=1",)
    files = bundle(log.entries, verify(log.entries, KEYS), found)
    assert "PASS: 8 entries verified" in files["summary.md"]
    paths = write_bundle(files, tmp_path)
    data = json.loads(paths[0].read_text())
    assert data["key_ids"] == ["k1"] and len(data["entries"]) == 8
    assert KEY.decode() not in paths[0].read_text()


def test_example_catches_each_tamper(capsys):
    from ch17_audit_evidence import main

    main()
    out = capsys.readouterr().out
    assert "FAIL at entry 10: content altered" in out
    assert "manager:priya approved" in out
