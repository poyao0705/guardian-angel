from enum import StrEnum
from dataclasses import dataclass


class DecisionStatus(StrEnum):
    """Enumeration of possible decision statuses."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class Decision:
    """Result of a policy evaluation."""

    status: DecisionStatus
    reason: str | None = None
    rule_name: str | None = None