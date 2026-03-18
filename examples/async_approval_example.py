"""Async approval workflow: ainvoke() raises ApprovalRequiredError for REQUIRE_APPROVAL rules."""

import asyncio
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
# Load policy & create guard
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
# Async examples
# ---------------------------------------------------------------------------


async def main():
    print("=== guard.ainvoke() examples ===\n")

    async def update_resource(resource_id):
        await asyncio.sleep(0.01)
        return {"updated": True, "resource_id": resource_id}

    approval_attrs = {
        "resource.environment": "prod",
        "context.change_type": "schema",
        "context.risk_score": 8,
        "subject.role": "developer",
    }

    approval_ctx = GuardContext(
        tool="resource.update",
        request_id="req-async-1",
        attributes=approval_attrs,
    )

    # 1. Require-approval raises
    print("1. Require-approval → ApprovalRequiredError:")
    try:
        await guard.ainvoke(update_resource, "doc-1", guard_ctx=approval_ctx)
    except ApprovalRequiredError as e:
        print(f"   ApprovalRequiredError: {e}")
        print(f"   rule={e.decision.rule_name}\n")

    # 2. Denied request
    print("2. Denied request → PolicyDeniedError:")
    try:
        await guard.ainvoke(
            update_resource,
            "doc-2",
            guard_ctx=GuardContext(
                tool="resource.delete",
                request_id="req-async-2",
                attributes={
                    "subject.tenant_id": "acme",
                    "resource.tenant_id": "globex",
                },
            ),
        )
    except PolicyDeniedError as e:
        print(f"   PolicyDeniedError: {e}\n")

    # 3. Allowed request executes
    print("3. Allowed request → function executes:")
    result = await guard.ainvoke(update_resource, "doc-3")
    print(f"   Result: {result}\n")


if __name__ == "__main__":
    asyncio.run(main())
