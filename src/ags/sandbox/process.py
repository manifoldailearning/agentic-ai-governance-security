"""Run model-written code in a separate, limited process.

The child gets isolated-mode Python, an empty environment
(no inherited secrets), a throwaway working directory, a
wall-clock timeout and kernel limits on CPU, memory, file
size, open files and core dumps. This is NOT isolation: the
child shares the kernel, can read what this user can read,
and can open network connections. Run it inside a container
or microVM with no network; these limits still belong there.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass

MB = 1024 * 1024


@dataclass(frozen=True)
class SandboxResult:
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool


def limiter(cpu: int, memory_mb: int, file_mb: int) -> Callable:
    """Runs in the child, after fork, before exec."""

    def apply() -> None:
        import resource

        for limit, value in [
            (resource.RLIMIT_CPU, cpu),
            (resource.RLIMIT_AS, memory_mb * MB),
            (resource.RLIMIT_FSIZE, file_mb * MB),
            (resource.RLIMIT_NOFILE, 64),
            (resource.RLIMIT_CORE, 0),
        ]:
            resource.setrlimit(limit, (value, value))

    return apply


def run_sandboxed(
    code: str,
    timeout: float = 2.0,
    cpu: int = 2,
    memory_mb: int = 256,
    file_mb: int = 1,
    max_output: int = 10_000,
) -> SandboxResult:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("limits are only enforced on Linux")
    with tempfile.TemporaryDirectory(prefix="sbx-") as cwd:
        proc = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", code],
            cwd=cwd,
            env={},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=True,  # own process group
            preexec_fn=limiter(cpu, memory_mb, file_mb),
        )
        try:
            out, err = proc.communicate(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)  # and children
            out, err = proc.communicate()
            timed_out = True
    n = max_output
    return SandboxResult(
        out[:n], err[:n], proc.returncode, timed_out
    )
