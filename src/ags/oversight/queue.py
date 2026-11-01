"""Approval queues, reviewers and approval-fatigue metrics.

An approval step is a control only if reviewers see why a
call is risky, decide in time and do not rubber-stamp.
``ApprovalQueue`` is a runtime approver: it files a request
with a context summary, collects votes until the policy's
quorum is met, fails closed on a refusal or a timeout, and
keeps the history that fatigue metrics are computed from.
"""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol

from ags.core import Clock, Context, Decision, ToolCall, ToolSpec
from ags.oversight.policy import (
    TIERS,
    ApprovalPolicy,
    Risk,
    amount_of,
    summarize,
)


@dataclass(frozen=True)
class Vote:
    reviewer: str
    approve: bool
    seconds: float  # time from request to decision
    human: bool = True


@dataclass
class ApprovalRequest:
    id: str
    run_id: str
    requester: str
    tool: str
    amount: float
    risk: Risk
    summary: list[str]
    untrusted: bool
    votes: list[Vote] = field(default_factory=list)
    status: str = "pending"  # approved | refused | timed_out

    def approvers(self) -> list[str]:
        return [v.reviewer for v in self.votes if v.approve]


class Reviewer(Protocol):
    name: str
    human: bool

    def review(self, request: ApprovalRequest) -> Vote | None: ...


@dataclass
class ScriptedHuman:
    """A reviewer with a fixed decision rule and pace."""

    name: str
    approves: Callable[[ApprovalRequest], bool] = lambda r: True
    seconds: float = 60.0
    human: bool = True

    def review(self, request: ApprovalRequest) -> Vote:
        ok = self.approves(request)
        return Vote(self.name, ok, self.seconds)


@dataclass
class AutoReviewer:
    """Approves routine requests by rule; abstains otherwise."""

    max_tier: str = "medium"
    max_amount: float = 100.0
    name: str = "auto-rules"
    human: bool = False

    def review(self, request: ApprovalRequest) -> Vote | None:
        tier_ok = TIERS.index(request.risk.tier) <= TIERS.index(
            self.max_tier
        )
        routine = request.amount <= self.max_amount
        if tier_ok and routine and not request.untrusted:
            return Vote(self.name, True, 0.0, human=False)
        return None  # escalate to people


class ApprovalQueue:
    def __init__(
        self,
        policy: ApprovalPolicy,
        reviewers: Iterable[Reviewer],
        clock: Clock,
        timeout: float = 900.0,
    ) -> None:
        self.policy = policy
        self.reviewers = list(reviewers)
        self.clock = clock
        self.timeout = timeout
        self.requests: list[ApprovalRequest] = []

    def __call__(
        self,
        ctx: Context,
        spec: ToolSpec,
        call: ToolCall,
        decision: Decision,
    ) -> bool:
        """The ``Approver`` hook the runtime calls."""
        request = self.submit(ctx, spec, call)
        return self.decide(request) == "approved"

    def submit(
        self, ctx: Context, spec: ToolSpec, call: ToolCall
    ) -> ApprovalRequest:
        risk = self.policy.assess(ctx, spec, call)
        request = ApprovalRequest(
            f"apr-{len(self.requests) + 1:03d}",
            ctx.run_id,
            ctx.principal.id,
            spec.name,
            amount_of(call),
            risk,
            summarize(ctx, spec, call, risk),
            "untrusted" in ctx.labels,
        )
        self.requests.append(request)
        return request

    def decide(self, request: ApprovalRequest) -> str:
        """Collect votes until quorum; any refusal vetoes."""
        quorum = max(request.risk.quorum, 1)
        waited = 0.0
        for reviewer in self._eligible(request, quorum):
            vote = reviewer.review(request)
            if vote is None:
                continue
            if waited + vote.seconds > self.timeout:
                self.clock.sleep(self.timeout - waited)
                break
            waited += vote.seconds
            self.clock.sleep(vote.seconds)
            request.votes.append(vote)
            if not vote.approve:
                request.status = "refused"
                return request.status
            if len(request.approvers()) >= quorum:
                request.status = "approved"
                return request.status
        request.status = "timed_out"  # fail closed
        return request.status

    def _eligible(
        self, request: ApprovalRequest, quorum: int
    ) -> list[Reviewer]:
        """No self-approval; four-eyes means two people."""
        seen: set[str] = set()
        out = []
        for r in self.reviewers:
            if r.name == request.requester or r.name in seen:
                continue
            if quorum > 1 and not r.human:
                continue
            seen.add(r.name)
            out.append(r)
        return out


@dataclass(frozen=True)
class Fatigue:
    decisions: int
    approval_rate: float
    median_seconds: float
    rubber_stamps: dict[str, int]


def fatigue(
    requests: Iterable[ApprovalRequest], fast: float = 10.0
) -> Fatigue:
    """Human approval health: rate, pace, too-fast approvals."""
    votes = [v for r in requests for v in r.votes if v.human]
    if not votes:
        return Fatigue(0, 0.0, 0.0, {})
    approved = [v for v in votes if v.approve]
    stamps = Counter(
        v.reviewer for v in approved if v.seconds < fast
    )
    return Fatigue(
        len(votes),
        len(approved) / len(votes),
        statistics.median(v.seconds for v in votes),
        dict(stamps),
    )
