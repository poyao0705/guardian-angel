from __future__ import annotations

import functools
import uuid
from datetime import datetime, timezone

from .approval import ApprovalRequest, ApprovalStatus
from .decision import DecisionStatus
from .exceptions import ApprovalRequiredError, PolicyDeniedError
from .request import ActionRequest


def make_tool_decorator(guard, name: str):
    """Return a decorator that enforces policy on the wrapped function."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attributes = kwargs.get("attributes") or {}
            request_id = kwargs.get("request_id")

            request = ActionRequest(
                tool=name,
                attributes=attributes,
                request_id=request_id,
            )

            decision = guard.authorize(request)

            if decision.status == DecisionStatus.DENY:
                raise PolicyDeniedError(decision)
            if decision.status == DecisionStatus.REQUIRE_APPROVAL:
                if guard.approval_handler is None:
                    raise ApprovalRequiredError(decision)

                resolved_request_id = request_id or str(uuid.uuid4())
                approval_request = ApprovalRequest(
                    request_id=resolved_request_id,
                    action_request=request,
                    decision=decision,
                    requested_at=datetime.now(tz=timezone.utc),
                )
                response = guard.approval_handler.submit(approval_request)

                if response.status == ApprovalStatus.APPROVED:
                    return func(*args, **kwargs)
                raise PolicyDeniedError(decision)

            return func(*args, **kwargs)

        return wrapper

    return decorator