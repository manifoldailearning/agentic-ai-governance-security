"""Chapter 8: sandboxing tools, arguments and egress.

Assume the model has been talked into something. Arguments
are validated against a schema, file paths are confined,
outbound URLs are allowlisted and inspected, and generated
code runs in a limited child process. Each layer is narrow
and bypassable alone; together they shrink what goes wrong.
"""

from ags.sandbox.args import ArgSchemaGuard, Field, PathGuard
from ags.sandbox.egress import EgressGuard, entropy, host_allowed
from ags.sandbox.process import SandboxResult, run_sandboxed

__all__ = [
    "ArgSchemaGuard",
    "EgressGuard",
    "Field",
    "PathGuard",
    "SandboxResult",
    "entropy",
    "host_allowed",
    "run_sandboxed",
]
