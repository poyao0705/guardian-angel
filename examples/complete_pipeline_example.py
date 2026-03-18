"""Complete pipeline: YAML policy load, GuardConfig, authorization, and approval."""

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


policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")

guard = GuardianAngel.from_yaml(
    policy_path,
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
        protected_tools=frozenset({"resource.archive"}),
        protected_no_match_decision=DecisionStatus.REQUIRE_APPROVAL,
        required_fields=("resource.environment",),
    ),
)


def print_decision(label: str, request: ActionRequest) -> None:
    decision = guard.authorize(request)
    print(label)
    print(
        "   "
        f"status={decision.status} "
        f"source={decision.source} "
        f"rule={decision.rule_name} "
        f"reason={decision.reason}"
    )
    print()


print("=== 1. Load YAML policy + GuardConfig ===\n")
print(f"policy={policy_path}")
print(
    "config="
    "default_allow + deny_on_eval_error + "
    "protected_resource_archive_requires_approval_on_no_match"
)
print()


print("=== 2. Authorize requests directly ===\n")

print_decision(
    "safe read request (no rule match -> default allow):",
    ActionRequest(
        tool="resource.read",
        request_id="req-pipeline-001",
        attributes={"resource.environment": "prod"},
    ),
)

print_decision(
    "protected no-match request (resource.archive -> require approval):",
    ActionRequest(
        tool="resource.archive",
        request_id="req-pipeline-002",
        attributes={"resource.environment": "prod"},
    ),
)

print_decision(
    "matched deny rule (cross-tenant delete):",
    ActionRequest(
        tool="resource.delete",
        request_id="req-pipeline-003",
        attributes={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "globex",
            "resource.environment": "prod",
        },
    ),
)


print("=== 3. Require-approval rule triggers ApprovalRequiredError ===\n")

approval_request = ActionRequest(
    tool="resource.update",
    request_id="req-pipeline-004",
    attributes={
        "resource.environment": "prod",
        "context.change_type": "permissions",
        "context.risk_score": 5,
        "subject.role": "developer",
    },
)

decision = guard.authorize(approval_request)
print(
    "authorize result: "
    f"status={decision.status} "
    f"rule={decision.rule_name}"
)
print()


print("=== 4. Use guard.invoke() to call a plain function under policy ===\n")


def update_resource(resource_id: str):
    return {"updated": True, "resource_id": resource_id}


try:
    tool_result = guard.invoke(
        update_resource,
        "doc-777",
        guard_ctx=GuardContext(
            tool="resource.update",
            request_id="req-pipeline-005",
            attributes={
                "resource.environment": "prod",
                "context.change_type": "schema",
                "context.risk_score": 8,
                "subject.role": "developer",
            },
        ),
    )
    print(f"invoke result: {tool_result}")
except ApprovalRequiredError as exc:
    print(f"invoke raised ApprovalRequiredError: {exc}")
print()


print("=== 5. Denial still blocks execution ===\n")


def delete_resource(resource_id: str):
    return {"deleted": True, "resource_id": resource_id}


try:
    guard.invoke(
        delete_resource,
        "doc-888",
        guard_ctx=GuardContext(
            tool="resource.delete",
            request_id="req-pipeline-006",
            attributes={
                "subject.tenant_id": "acme",
                "resource.tenant_id": "globex",
                "resource.environment": "prod",
            },
        ),
    )
except PolicyDeniedError as exc:
    print(f"blocked delete: {exc}")