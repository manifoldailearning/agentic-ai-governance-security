import time

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
from ags.sandbox import (
    ArgSchemaGuard,
    EgressGuard,
    Field,
    PathGuard,
    run_sandboxed,
)

CTX = Context("r", "a", Principal("asha"))
FETCH = ToolSpec("fetch_url", "external")
EGRESS = EgressGuard(("status.example", "*.docs.example"))
REFUND = {
    "issue_refund": {
        "customer_id": Field(pattern=r"C-\d{3}"),
        "amount": Field(float),
        "note": Field(required=False, max_len=20),
    }
}


def check(guard, name, **args):
    spec = ToolSpec(name, "write")
    return guard.check(CTX, spec, ToolCall("1", name, args))


@pytest.mark.parametrize(
    "args, why",
    [
        ({"customer_id": "C-100", "amount": "50"}, "expected"),
        ({"customer_id": "C-100", "amount": True}, "expected"),
        ({"customer_id": "C-100\n", "amount": 5.0}, "match"),
        ({"customer_id": "c-100", "amount": 5.0}, "match"),
        ({"customer_id": "C-100"}, "amount: required"),
        (
            {"customer_id": "C-1", "amount": 1.0, "x": 1},
            "unexpected",
        ),
        (
            {
                "customer_id": "C-100",
                "amount": 1,
                "note": "n" * 21,
            },
            "longer",
        ),
    ],
)
def test_schema_rejects_malformed_args(args, why):
    d = check(ArgSchemaGuard(REFUND), "issue_refund", **args)
    assert d.verdict == "deny" and why in d.reason


def test_schema_accepts_valid_args_and_denies_unknown_tools():
    guard = ArgSchemaGuard(REFUND)
    ok = check(
        guard, "issue_refund", customer_id="C-100", amount=5
    )
    assert ok.allowed  # an int is a fine float
    assert "no schema" in check(guard, "run_python").reason


@pytest.mark.parametrize(
    "url",
    [
        "http://status.example/",
        "https://status.example@exfil.example/",
        "https://status.example%40exfil.example/",
        "https://status.example\\@exfil.example/",
        "https://127.0.0.1/",
        "https://2130706433/",
        "https://0x7f000001/",
        "https://0177.0.0.1/",
        "https://[::ffff:127.0.0.1]/",
        "https://status.example.exfil.example/",
        "https://evilstatus.example/",
        "https://docs.example/",
        "https://st\u0430tus.example/",  # Cyrillic a
        "https://status.example:8443/",
        "https://status.example/?d=$LAST",
        'https://status.example/?d={"card": "4111"}',
        "https://status.example/?d=" + "ab" * 40,
        "https://status.example/?d=YXNoYUBhY21lLmV4YW1wbGU%3D",
        "javascript:alert(1)",
    ],
)
def test_egress_bypass_attempts_are_denied(url):
    d = EGRESS.check(
        CTX, FETCH, ToolCall("1", "fetch_url", {"url": url})
    )
    assert d.verdict == "deny", url


@pytest.mark.parametrize(
    "url",
    [
        "https://status.example/today",
        "https://STATUS.example./today",
        "https://api.docs.example/v1?page=2&lang=en",
        "https://status.example/?q=refund+policy",
    ],
)
def test_egress_allows_clean_urls(url):
    assert EGRESS.problem(url) is None


def test_blog_injection_exfil_denied_in_runtime():
    env, tools = build_env()
    guard = EgressGuard(("blog.example",))
    blog = call("fetch_url", url="https://blog.example/tips")
    model = ScriptedModel([blog], gullible=True)
    res = Runtime(tools, [guard]).run(Principal("a"), "t", model)
    assert env.fetched == ["https://blog.example/tips"]
    assert res.denied[0][1].reason.startswith("raw data")


def test_path_guard_confines_paths(tmp_path):
    root, other = tmp_path / "work", tmp_path / "shared"
    root.mkdir()
    other.mkdir()
    (root / "link").symlink_to("/etc")
    guard = PathGuard((root, other))
    bad = [
        "../../etc/passwd",
        "/etc/passwd",
        "link/passwd",
        "..%2f..%2fetc",
        "a\\..\\..\\x",
        "a\0b",
        "../work2",
    ]
    for raw in bad:
        assert check(guard, "read_file", path=raw).verdict == (
            "deny"
        ), raw
    assert check(guard, "read_file", path="notes/a.txt").allowed
    assert check(
        guard, "read_file", path=str(other / "x")
    ).allowed
    assert not check(guard, "read_file", path=["x"]).allowed


def test_sandbox_runs_code_in_an_empty_temp_world():
    r = run_sandboxed(
        "import os, sys; print(sorted(os.environ), os.getcwd(),"
        " sys.flags.isolated)"
    )
    assert r.exit_code == 0 and not r.timed_out
    env, cwd, isolated = r.stdout.rsplit(" ", 2)
    assert env == "['LC_CTYPE']" and isolated.strip() == "1"
    assert "sbx-" in cwd


def test_sandbox_timeout_kills_the_whole_process_group():
    start = time.monotonic()
    r = run_sandboxed(
        "import os, time\nos.fork()\ntime.sleep(30)", timeout=0.5
    )
    assert r.timed_out and r.exit_code == -9
    assert time.monotonic() - start < 5  # grandchild died too


def test_sandbox_memory_and_file_limits():
    mem = run_sandboxed("b = bytearray(10**9)", memory_mb=128)
    assert mem.exit_code == 1 and "MemoryError" in mem.stderr
    big = run_sandboxed("open('f', 'wb').write(b'x' * 2**21)")
    assert "File too large" in big.stderr
    out = run_sandboxed("print('x' * 50)", max_output=10)
    assert out.stdout == "x" * 10


def test_example_main(capsys):
    from ch08_sandboxing import main

    main()
    out = capsys.readouterr().out
    assert "userinfo trick   userinfo before the host" in out
    assert (
        "fetched: blog.example/tips, status.example/today" in out
    )
    assert "killed at 1.0s timeout (exit -9)" in out


def test_path_is_screened_like_the_query():
    import base64

    from ags.sandbox import EgressGuard

    guard = EgressGuard(("status.example",))
    blob = base64.b64encode(bytes(range(200))).decode()
    assert guard.problem(f"https://status.example/{blob}")
    chunk = blob[:40].replace("/", "_").replace("+", "-")
    why = guard.problem(f"https://status.example/{chunk}/x")
    assert why == "high-entropy path segment"
    assert guard.problem("https://status.example/today") is None
