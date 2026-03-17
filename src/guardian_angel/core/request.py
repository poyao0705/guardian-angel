from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ActionRequest:
    """Canonical input for policy evaluation.

    Keep the top-level surface intentionally small. Additional metadata should
    be stored in ``attributes`` using dotted namespaces such as
    ``subject.role`` or ``context.risk_level``.
    """

    tool: str
    attributes: dict[str, Any] = field(default_factory=dict)
    request_id: str | None = None