"""Basic usage: create rules manually, authorize a request, inspect the decision."""

from guardian_angel import (
    ALLOW,
    DENY,
    REQUIRE_APPROVAL,
    ActionRequest,
    GuardianAngel,
    Rule,
)

# Define rules in code
rules = [
    Rule(
        name="deny_high_risk_delete",
        tool="resource.delete",
        decision=DENY,
        attributes={"context.risk_level": "high"},
    ),
    Rule(
        name="require_external_tenant_approval",
        tool="resource.update",
        decision=REQUIRE_APPROVAL,
        attributes={
            "subject.tenant_id": "external",
            "resource.environment": "prod",
        },
    ),
]

guard = GuardianAngel(rules=rules)

# Evaluate requests
requests = [
    ActionRequest(
        tool="resource.delete",
        request_id="req-001",
        attributes={
            "context.risk_level": "high",
            "subject.role": "developer",
        },
    ),
    ActionRequest(
        tool="resource.update",
        request_id="req-002",
        attributes={
            "subject.tenant_id": "external",
            "resource.environment": "prod",
            "agent.trust_level": "low",
        },
    ),
    ActionRequest(
        tool="resource.update",
        request_id="req-003",
        attributes={
            "subject.tenant_id": "internal",
            "resource.environment": "prod",
        },
    ),
    ActionRequest(
        tool="resource.read",
        request_id="req-004",
        attributes={"subject.role": "viewer"},
    ),
]

for req in requests:
    decision = guard.authorize(req)
    print(f"Tool: {req.tool:<25} Decision: {decision.status:<20} Reason: {decision.reason}")
