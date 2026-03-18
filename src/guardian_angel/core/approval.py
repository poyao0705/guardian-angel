from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from .decision import Decision
from .request import ActionRequest


class ApprovalStatus(StrEnum):
    """Possible outcomes of an approval request."""

    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(slots=True)
class ApprovalRequest:
    """Represents a pending approval request.

    Created when the policy engine returns ``REQUIRE_APPROVAL``.  The guard
    raises :class:`~guardian_angel.core.exceptions.ApprovalRequiredError`
    carrying a :class:`~guardian_angel.core.decision.Decision`; calling code
    can build an ``ApprovalRequest`` from the decision context if it needs
    to integrate with an external approval workflow.
    """

    action_request: ActionRequest
    decision: Decision
    requested_at: datetime
    approvers: list[str] = field(default_factory=list)
    approval_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass(slots=True)
class ApprovalResponse:
    """The result of an external approval workflow.

    This dataclass is provided as a convenience for integrations that
    implement their own approval backends.  ``GuardianAngel`` itself does
    **not** consume or produce ``ApprovalResponse`` instances.
    """

    approval_id: str
    status: ApprovalStatus
    approved_by: str | None = None
    reason: str | None = None
    conditions: dict[str, Any] = field(default_factory=dict)
    responded_at: datetime | None = None
