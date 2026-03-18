from __future__ import annotations

import inspect

from .config import GuardConfig
from .decision import DecisionStatus
from .exceptions import ApprovalRequiredError, PolicyDeniedError
from .policy_engine import PolicyEngine, PolicyEvaluator
from .policy_loader import load_json_policy_file, load_yaml_policy_file
from .request import ActionRequest, GuardContext
from .rule import Rule


class GuardianAngel:
    """Main entry point for the GuardianAngel SDK.

    Usage::

        guard = GuardianAngel(rules=[...])
        decision = guard.authorize(request)

    Or with a custom evaluator::

        guard = GuardianAngel(engine=MyCustomEvaluator())
        decision = guard.authorize(request)

    When a rule matches with ``REQUIRE_APPROVAL``, :meth:`invoke` /
    :meth:`ainvoke` raise :class:`~guardian_angel.core.exceptions.ApprovalRequiredError`
    so the calling framework can handle the approval workflow in whatever
    way is native to it (LangGraph interrupt, CrewAI human input, webhook, etc.).
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        *,
        engine: PolicyEvaluator | None = None,
        config: GuardConfig | None = None,
    ):
        if engine is not None and rules is not None:
            raise ValueError("Specify either 'rules' or 'engine', not both")

        self.config = config or GuardConfig()

        if engine is not None:
            self.engine: PolicyEvaluator = engine
        else:
            self.engine = PolicyEngine(rules or [], config=self.config)

    @classmethod
    def from_yaml(
        cls,
        path: str,
        *,
        config: GuardConfig | None = None,
    ) -> GuardianAngel:
        """Create a GuardianAngel instance from a YAML policy file."""

        rules = load_yaml_policy_file(path)
        return cls(rules=rules, config=config)

    @classmethod
    def from_json(
        cls,
        path: str,
        *,
        config: GuardConfig | None = None,
    ) -> GuardianAngel:
        """Create a GuardianAngel instance from a JSON policy file."""

        rules = load_json_policy_file(path)
        return cls(rules=rules, config=config)

    def authorize(self, request):
        """Evaluate an ActionRequest against loaded rules and return a Decision."""

        return self.engine.evaluate(request)

    # ------------------------------------------------------------------
    # invoke / ainvoke – call any function under policy
    # ------------------------------------------------------------------

    def _resolve_tool_name(self, fn, guard_ctx: GuardContext | None) -> str:
        if guard_ctx is not None and guard_ctx.tool is not None:
            return guard_ctx.tool
        return getattr(fn, "__name__", str(fn))

    def _build_invoke_request(
        self, fn, guard_ctx: GuardContext | None,
    ) -> ActionRequest:
        name = self._resolve_tool_name(fn, guard_ctx)
        return ActionRequest(
            tool=name,
            attributes=guard_ctx.attributes if guard_ctx else {},
            request_id=guard_ctx.request_id if guard_ctx else None,
        )

    def invoke(self, fn, /, *args, guard_ctx: GuardContext | None = None, **kwargs):
        """Call *fn* under policy enforcement without decorating it.

        Usage::

            result = guard.invoke(
                update_resource,
                "doc-777",
                guard_ctx=GuardContext(
                    tool="resource.update",
                    attributes={"resource.environment": "prod"},
                ),
            )

        The *guard_ctx* is **not** forwarded to *fn*; the function receives
        only ``*args`` and ``**kwargs``.

        Raises :class:`~guardian_angel.core.exceptions.PolicyDeniedError` when
        the policy denies the action, and
        :class:`~guardian_angel.core.exceptions.ApprovalRequiredError` when the
        policy requires approval.
        """
        request = self._build_invoke_request(fn, guard_ctx)
        decision = self.authorize(request)

        if decision.status == DecisionStatus.DENY:
            raise PolicyDeniedError(decision)

        if decision.status == DecisionStatus.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(decision)

        return fn(*args, **kwargs)

    async def ainvoke(
        self, fn, /, *args, guard_ctx: GuardContext | None = None, **kwargs,
    ):
        """Async version of :meth:`invoke`.

        If *fn* is a coroutine function it is awaited; otherwise it is called
        synchronously.
        """
        request = self._build_invoke_request(fn, guard_ctx)
        decision = self.authorize(request)

        if decision.status == DecisionStatus.DENY:
            raise PolicyDeniedError(decision)

        if decision.status == DecisionStatus.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(decision)

        if inspect.iscoroutinefunction(fn):
            return await fn(*args, **kwargs)
        return fn(*args, **kwargs)