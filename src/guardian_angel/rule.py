from __future__ import annotations

from typing import Any

from guardian_angel.decision import DecisionStatus
from .evaluator import evaluate_predicate, resolve_key
from .predicates import AllOf, AnyOf, Condition, Not, Operator, Predicate
from .request import ActionRequest

# Re-export predicate types so callers can do `from guardian_angel.rule import Condition, ...`
__all__ = ["Rule", "Condition", "AllOf", "AnyOf", "Not", "Predicate", "Operator"]


class Rule:
    """A single policy rule.

    Matches when the request tool equals ``tool``, all ``attributes`` match,
    and (if present) the ``when`` predicate evaluates to ``True``.
    """

    def __init__(
        self,
        name: str,
        tool: str,
        decision: DecisionStatus,
        attributes: dict[str, Any] | None = None,
        when: Predicate | None = None,
    ):
        self.name = name
        self.tool = tool
        self.decision = decision
        self.attributes = attributes or {}
        self.when = when

    def matches(self, request: ActionRequest) -> bool:
        if self.tool != request.tool:
            return False

        for key, value in self.attributes.items():
            if resolve_key(request, key) != value:
                return False

        if self.when is None:
            return True

        return evaluate_predicate(request, self.when)

    def __repr__(self) -> str:
        return f"Rule(name={self.name!r}, tool={self.tool!r}, decision={self.decision!r})"
