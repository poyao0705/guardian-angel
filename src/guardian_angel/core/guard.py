from __future__ import annotations

from .policy_engine import PolicyEngine, PolicyEvaluator
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
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        *,
        engine: PolicyEvaluator | None = None,
    ):
        if engine is not None and rules is not None:
            raise ValueError("Specify either 'rules' or 'engine', not both")

        if engine is not None:
            self.engine: PolicyEvaluator = engine
        else:
            self.engine = PolicyEngine(rules or [])

    @classmethod
    def from_yaml(cls, path: str) -> GuardianAngel:
        """Create a GuardianAngel instance from a YAML policy file."""

        rules = load_policy_file(path)
        return cls(rules=rules)

    def authorize(self, request):
        """Evaluate an ActionRequest against loaded rules and return a Decision."""

        return self.engine.evaluate(request)

    def tool(self, name: str):
        """Decorator that wraps a function with policy enforcement.

        Usage::

            @guard.tool(name="resource.delete")
            def delete_resource(resource_id, *, attributes=None):
                ...
        """

        return make_tool_decorator(self, name)