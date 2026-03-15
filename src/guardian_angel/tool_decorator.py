from __future__ import annotations

import functools

from .decision import DENY, REQUIRE_APPROVAL
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

            if decision.status == DENY:
                raise PolicyDeniedError(decision)
            if decision.status == REQUIRE_APPROVAL:
                raise ApprovalRequiredError(decision)

            return func(*args, **kwargs)

        return wrapper

    return decorator