"""Control catalog with an illustrative mapping to frameworks.

Risk and compliance teams describe the same control in
several vocabularies. The catalog names each control once,
points at the chapter that builds it, and maps it to areas
of well-known frameworks. The mapping is illustrative, kept
at the level of functions and areas, and is not legal advice.
"""

from __future__ import annotations

from collections.abc import Iterable

CONTROLS = {  # id: (what it does, chapter that builds it)
    "inventory": ("AI bill of materials and inventory", 19),
    "usage-policy": ("Acceptable-use and tool policy", 16),
    "transparency": ("Users know they deal with an agent", 18),
    "event-logging": ("Security event logging", 14),
    "output-dlp": ("Mask or block sensitive output", 9),
    "least-privilege": ("Scoped identity and authorization", 4),
    "injection-defense": ("Screen untrusted content", 6),
    "flow-control": ("Block untrusted-to-external flows", 7),
    "human-approval": ("Risk-tiered human approval", 12),
    "red-team": ("Adversarial testing gate", 13),
    "audit-trail": ("Tamper-evident audit evidence", 17),
    "incident-response": ("Detect, contain, investigate", 15),
}

ILLUSTRATIVE = "illustrative mapping, not legal advice"

FRAMEWORKS: dict[str, dict[str, tuple[str, ...]]] = {
    "NIST AI RMF": {
        "Govern": ("usage-policy", "inventory", "audit-trail"),
        "Map": ("inventory", "transparency"),
        "Measure": ("red-team", "event-logging"),
        "Manage": (
            "least-privilege",
            "flow-control",
            "human-approval",
            "incident-response",
        ),
    },
    "ISO/IEC 42001": {
        "Leadership and policy": ("usage-policy",),
        "Planning and risk": ("inventory", "red-team"),
        "Operation": ("least-privilege", "flow-control"),
        "Performance evaluation": (
            "event-logging",
            "audit-trail",
        ),
        "Improvement": ("incident-response",),
    },
    "EU AI Act": {
        "Risk management": ("red-team", "flow-control"),
        "Record-keeping": ("event-logging", "audit-trail"),
        "Transparency": ("transparency",),
        "Human oversight": ("human-approval",),
        "Robustness and security": (
            "injection-defense",
            "least-privilege",
        ),
    },
    "OWASP Top 10 for LLM Applications": {
        "Prompt injection": ("injection-defense", "flow-control"),
        "Sensitive information disclosure": ("output-dlp",),
        "Excessive agency": ("least-privilege", "human-approval"),
        "Supply chain": ("inventory",),
    },
}


def areas_for(control: str) -> list[str]:
    """Every framework area a control contributes to."""
    return [
        f"{fw}: {area}"
        for fw, areas in FRAMEWORKS.items()
        for area, controls in areas.items()
        if control in controls
    ]


def framework_gaps(
    implemented: Iterable[str],
) -> dict[str, list[str]]:
    """Framework areas that no implemented control touches."""
    done = set(implemented)
    return {
        fw: [a for a, cs in areas.items() if not done & set(cs)]
        for fw, areas in FRAMEWORKS.items()
    }
