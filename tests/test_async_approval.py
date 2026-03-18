from __future__ import annotations

import pytest

from guardian_angel import (
    ApprovalRequiredError,
    DecisionStatus,
    GuardContext,
    GuardianAngel,
    PolicyDeniedError,
    Rule,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_approval_rules():
    return [Rule(name="approve_deploy", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)]


# ---------------------------------------------------------------------------
# guard.ainvoke() raises ApprovalRequiredError
# ---------------------------------------------------------------------------


class TestAInvokeWithApproval:
    @pytest.mark.asyncio
    async def test_require_approval_raises(self):
        guard = GuardianAngel(rules=_require_approval_rules())

        async def deploy(target):
            return f"deployed {target}"

        with pytest.raises(ApprovalRequiredError) as exc_info:
            await guard.ainvoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy"))
        assert exc_info.value.decision.status == DecisionStatus.REQUIRE_APPROVAL

    @pytest.mark.asyncio
    async def test_deny_raises_policy_denied_error(self):
        guard = GuardianAngel(
            rules=[Rule(name="r", tool="nuke", decision=DecisionStatus.DENY)]
        )

        async def nuke():
            return "boom"

        with pytest.raises(PolicyDeniedError):
            await guard.ainvoke(nuke, guard_ctx=GuardContext(tool="nuke"))

    @pytest.mark.asyncio
    async def test_allow_executes_async_function(self):
        guard = GuardianAngel(rules=[])

        async def read_resource(resource_id):
            return f"read {resource_id}"

        result = await guard.ainvoke(read_resource, "res-1")
        assert result == "read res-1"

    @pytest.mark.asyncio
    async def test_allow_executes_sync_function(self):
        guard = GuardianAngel(rules=[])

        def read_resource(resource_id):
            return f"read {resource_id}"

        result = await guard.ainvoke(read_resource, "res-1")
        assert result == "read res-1"

    @pytest.mark.asyncio
    async def test_decision_carries_rule_name(self):
        guard = GuardianAngel(rules=_require_approval_rules())

        async def deploy(target):
            return f"deployed {target}"

        with pytest.raises(ApprovalRequiredError) as exc_info:
            await guard.ainvoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy"))
        assert exc_info.value.decision.rule_name == "approve_deploy"

    @pytest.mark.asyncio
    async def test_protected_tool_no_match_requires_approval(self):
        from guardian_angel import GuardConfig

        guard = GuardianAngel(
            rules=[],
            config=GuardConfig(
                protected_tools=frozenset({"deploy"}),
                protected_no_match_decision=DecisionStatus.REQUIRE_APPROVAL,
            ),
        )

        async def deploy(target):
            return f"deployed {target}"

        with pytest.raises(ApprovalRequiredError):
            await guard.ainvoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy"))
