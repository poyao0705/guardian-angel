from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .approval import ApprovalHandler, ApprovalRequest, ApprovalStatus
from .decision import DecisionStatus
from .exceptions import ApprovalRequiredError, PolicyDeniedError
from .policy_engine import PolicyEngine, PolicyEvaluator
from .request import ActionRequest
from .rule import Rule
from .tool_decorator import make_tool_decorator
from .yaml_loader import load_policy_file


class GuardianAngel:
    """Main entry point for the GuardianAngel SDK.

    Usage::

        guard = GuardianAngel(rules=[...])
        decision = guard.authorize(request)

    Or with a custom evaluator::

        guard = GuardianAngel(engine=MyCustomEvaluator())
        decision = guard.authorize(request)

    Or with an approval handler::

        guard = GuardianAngel(rules=[...], approval_handler=MyApprovalHandler())
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        *,
        engine: PolicyEvaluator | None = None,
        approval_handler: ApprovalHandler | None = None,
    ):
        if engine is not None and rules is not None:
            raise ValueError("Specify either 'rules' or 'engine', not both")

        if engine is not None:
            self.engine: PolicyEvaluator = engine
        else:
            self.engine = PolicyEngine(rules or [])

        self.approval_handler = approval_handler

    @classmethod
    def from_yaml(
        cls,
        path: str,
        *,
        approval_handler: ApprovalHandler | None = None,
    ) -> GuardianAngel:
        """Create a GuardianAngel instance from a YAML policy file."""

        rules = load_policy_file(path)
        return cls(rules=rules, approval_handler=approval_handler)

    def authorize(self, request):
        """Evaluate an ActionRequest against loaded rules and return a Decision."""

        return self.engine.evaluate(request)

    def request_approval(self, action_request: ActionRequest):
        """Evaluate *action_request* and, if approval is required, delegate to the handler.

        Behavior:

        - ``REQUIRE_APPROVAL`` + handler set → creates an :class:`~guardian_angel.core.approval.ApprovalRequest`
          and calls ``approval_handler.submit()``, returning the :class:`~guardian_angel.core.approval.ApprovalResponse`.
        - ``REQUIRE_APPROVAL`` + no handler → raises :class:`~guardian_angel.core.exceptions.ApprovalRequiredError`.
        - ``ALLOW`` → raises :class:`ValueError` (no approval needed).
        - ``DENY`` → raises :class:`~guardian_angel.core.exceptions.PolicyDeniedError`.
        """

        decision = self.authorize(action_request)

        if decision.status == DecisionStatus.ALLOW:
            raise ValueError(
                "Action is already allowed by policy; no approval needed."
            )

        if decision.status == DecisionStatus.DENY:
            raise PolicyDeniedError(decision)

        # decision.status == REQUIRE_APPROVAL
        if self.approval_handler is None:
            raise ApprovalRequiredError(decision)

        request_id = action_request.request_id or str(uuid.uuid4())
        approval_request = ApprovalRequest(
            request_id=request_id,
            action_request=action_request,
            decision=decision,
            requested_at=datetime.now(tz=timezone.utc),
        )
        return self.approval_handler.submit(approval_request)

    def tool(self, name: str):
        """Decorator that wraps a function with policy enforcement.

        Usage::

            @guard.tool(name="resource.delete")
            def delete_resource(resource_id, *, attributes=None):
                ...
        """

        return make_tool_decorator(self, name)