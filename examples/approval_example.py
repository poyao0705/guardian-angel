"""Approval workflow: GuardianAngel raises ApprovalRequiredError for REQUIRE_APPROVAL rules.

The calling code (your framework, webhook handler, etc.) decides *how* to
handle the approval — block on user input, raise an interrupt, send a Slack
message, etc.  GuardianAngel only signals that approval is needed.
"""

import os

from guardian_angel import (
    ActionRequest,
    ApprovalRequiredError,
    DecisionStatus,
    GuardConfig,
    GuardContext,
    GuardianAngel,
    PolicyDeniedError,
)

# ---------------------------------------------------------------------------
# 1. Load policy & create guard
# ---------------------------------------------------------------------------

policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
guard = GuardianAngel.from_yaml(
    policy_path,
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
    ),
)

# ---------------------------------------------------------------------------
# 2. authorize() returns a Decision — caller inspects it
# ---------------------------------------------------------------------------

print("=== authorize() examples ===\n")

req = ActionRequest(
    tool="resource.update",
    request_id="req-301",
    attributes={
        "resource.environment": "prod",
        "context.change_type": "permissions",
        "context.risk_score": 5,
        "subject.role": "developer",
    },
)

decision = guard.authorize(req)
print(f"1. Decision for resource.update: status={decision.status} rule={decision.rule_name}\n")

# Denied request
decision = guard.authorize(
    ActionRequest(
        tool="resource.delete",
        request_id="req-302",
        attributes={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "globex",
        },
    )
)
print(f"2. Decision for cross-tenant delete: status={decision.status}\n")

# Allowed request
decision = guard.authorize(
    ActionRequest(tool="resource.read", request_id="req-303")
)
print(f"3. Decision for resource.read: status={decision.status}\n")


# ---------------------------------------------------------------------------
# 3. invoke() raises ApprovalRequiredError when approval is needed
# ---------------------------------------------------------------------------

print("=== guard.invoke() examples ===\n")


def update_resource(resource_id):
    return {"updated": True, "resource_id": resource_id}


approval_attrs = {
    "resource.environment": "prod",
    "context.change_type": "schema",
    "context.risk_score": 8,
    "subject.role": "developer",
}

approval_ctx = GuardContext(
    tool="resource.update",
    request_id="req-304",
    attributes=approval_attrs,
)

print("4. Require-approval → ApprovalRequiredError:")
try:
    guard.invoke(update_resource, "doc-1", guard_ctx=approval_ctx)
except ApprovalRequiredError as e:
    print(f"   ApprovalRequiredError: {e}")
    print(f"   rule={e.decision.rule_name}")
    # Here your framework would pause and request human approval.
    print()

print("5. Denied → PolicyDeniedError:")
try:
    guard.invoke(
        update_resource,
        "doc-2",
        guard_ctx=GuardContext(
            tool="resource.delete",
            request_id="req-305",
            attributes={
                "subject.tenant_id": "acme",
                "resource.tenant_id": "globex",
            },
        ),
    )
except PolicyDeniedError as e:
    print(f"   PolicyDeniedError: {e}\n")

print("6. Allowed → function executes:")
result = guard.invoke(update_resource, "doc-3")
print(f"   Result: {result}\n")
