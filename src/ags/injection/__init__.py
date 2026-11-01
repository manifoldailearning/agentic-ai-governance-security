"""Chapter 6: detecting and containing prompt injection.

Normalize and score untrusted text, measure the detector on
a labeled corpus, spotlight what passes and quarantine what
does not. Detection reduces risk; it is not a security
boundary. Pair it with the flow, egress and DLP controls.
"""

from ags.injection.corpus import CORPUS, Metrics, Sample, evaluate
from ags.injection.detect import Detector, Finding, normalize
from ags.injection.screen import (
    SPOTLIGHT_PROMPT,
    Held,
    Quarantine,
    ScreenedTool,
    spotlight,
)

__all__ = [
    "CORPUS",
    "SPOTLIGHT_PROMPT",
    "Detector",
    "Finding",
    "Held",
    "Metrics",
    "Quarantine",
    "Sample",
    "ScreenedTool",
    "evaluate",
    "normalize",
    "spotlight",
]
