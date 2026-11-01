"""Risk tiering, risk register and control catalog (chapter 18).

Decide how much governance a use case needs, record its
risks with owners and residual scores, and show which
controls and framework areas are still uncovered. Framework
mappings are illustrative and are not legal advice.
"""

from ags.risk.controls import (
    CONTROLS,
    FRAMEWORKS,
    ILLUSTRATIVE,
    areas_for,
    framework_gaps,
)
from ags.risk.register import Risk, RiskRegister, band
from ags.risk.tiering import (
    QUESTIONS,
    RED_LINES,
    TIERS,
    Assessment,
    assess,
    infer_answers,
    required_controls,
    score_answers,
    tier_for,
)

__all__ = [
    "CONTROLS",
    "FRAMEWORKS",
    "ILLUSTRATIVE",
    "QUESTIONS",
    "RED_LINES",
    "TIERS",
    "Assessment",
    "Risk",
    "RiskRegister",
    "areas_for",
    "assess",
    "band",
    "framework_gaps",
    "infer_answers",
    "required_controls",
    "score_answers",
    "tier_for",
]
