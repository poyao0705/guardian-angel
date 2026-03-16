"""Use the @guard.tool() decorator with YAML predicates."""

import os

from guardian_angel import ApprovalRequiredError, GuardianAngel, PolicyDeniedError

# Load policy from YAML
policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
guard = GuardianAngel.from_yaml(policy_path)


@guard.tool(name="resource.delete")
def delete_resource(
    resource_id: str,
    *,
    attributes: dict | None = None,
    request_id: str | None = None,
):
    return {
        "deleted": True,
        "resource_id": resource_id,
        "request_id": request_id,
        "attributes": attributes or {},
    }


@guard.tool(name="resource.update")
def update_resource(
    resource_id: str,
    *,
    attributes: dict | None = None,
    request_id: str | None = None,
):
    return {
        "updated": True,
        "resource_id": resource_id,
        "request_id": request_id,
        "attributes": attributes or {},
    }


# 1. Denied by a plain condition using value_from.
print("1. Cross-tenant delete (condition + value_from -> deny):")
try:
    delete_resource(
        "doc-123",
        request_id="req-101",
        attributes={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "globex",
            "resource.environment": "prod",
            "context.risk_level": "low",
            "subject.role": "admin",
            "agent.trust_level": "high",
        },
    )
except PolicyDeniedError as e:
    print(f"   Denied: {e}\n")

# 2. Denied by nested all/any/not logic.
print("2. Risky prod delete (all + any + not -> deny):")
try:
    delete_resource(
        "doc-456",
        request_id="req-102",
        attributes={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "acme",
            "resource.environment": "prod",
            "context.risk_level": "high",
            "subject.role": "developer",
            "agent.trust_level": "medium",
        },
    )
except PolicyDeniedError as e:
    print(f"   Denied: {e}\n")

# 3. Allowed because the not-clause fails.
print("3. Safe prod delete (not clause blocks the deny rule, so allow):")
result = delete_resource(
    "doc-789",
    request_id="req-103",
    attributes={
        "subject.tenant_id": "acme",
        "resource.tenant_id": "acme",
        "resource.environment": "prod",
        "context.risk_level": "low",
        "subject.role": "admin",
        "agent.trust_level": "high",
    },
)
print(f"   Result: {result}\n")

# 4. Require approval from the YAML policy.
print("4. Prod update requiring approval (all + any + not -> require_approval):")
try:
    update_resource(
        "doc-999",
        request_id="req-104",
        attributes={
            "resource.environment": "prod",
            "context.change_type": "permissions",
            "context.risk_score": 5,
            "subject.role": "developer",
        },
    )
except ApprovalRequiredError as e:
    print(f"   Approval required: {e}")
