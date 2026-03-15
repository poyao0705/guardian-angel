from __future__ import annotations

from .request import ActionRequest


class Rule:
    """Internal runtime rule representation for policy evaluation.

    Evaluation uses exact matching on tool and all key/value pairs in
    attributes.
    """

    def __init__(
        self,
        name: str,
        tool: str,
        decision: str,
        attributes: dict | None = None,
    ):
        self.name = name
        self.tool = tool
        self.decision = decision
        self.attributes = attributes or {}

    def matches(self, request: ActionRequest) -> bool:
        if self.tool != request.tool:
            return False

        for key, value in self.attributes.items():
            if request.attributes.get(key) != value:
                return False

        return True

    def __repr__(self) -> str:
        return f"Rule(name={self.name!r}, tool={self.tool!r}, decision={self.decision!r})"
