from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from .decision import Decision
from .request import ActionRequest


class ApprovalStatus(StrEnum):
    """Possible outcomes of an approval request."""

    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(slots=True)
class ApprovalRequest:
    """Represents a request for human (or automated) approval.

    Created when the policy engine returns ``REQUIRE_APPROVAL`` and an
    :class:`ApprovalHandler` is registered on the :class:`~guardian_angel.core.guard.GuardianAngel`
    instance.
    """

    request_id: str
    action_request: ActionRequest
    decision: Decision
    requested_at: datetime
    approvers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ApprovalResponse:
    """The result returned by an :class:`ApprovalHandler` after processing an approval request."""

    request_id: str
    status: ApprovalStatus
    approved_by: str | None = None
    reason: str | None = None
    conditions: dict[str, Any] = field(default_factory=dict)
    responded_at: datetime | None = None


@runtime_checkable
class ApprovalHandler(Protocol):
    """Protocol for pluggable approval backends.

    Implement this protocol to integrate with any approval workflow (Slack,
    email, GitHub issues, a database queue, etc.).

    Example::

        class MyApprovalHandler:
            def submit(self, request: ApprovalRequest) -> ApprovalResponse:
                # send notification, wait for response, return outcome
                ...

        guard = GuardianAngel(rules=[...], approval_handler=MyApprovalHandler())
    """

    def submit(self, request: ApprovalRequest) -> ApprovalResponse: ...
