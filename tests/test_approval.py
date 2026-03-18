from __future__ import annotations

from datetime import datetime, timezone

import pytest

from guardian_angel import (
    ActionRequest,
    ApprovalRequest,
    ApprovalRequiredError,
    ApprovalResponse,
    ApprovalStatus,
    DecisionStatus,
    GuardContext,
    GuardianAngel,
    PolicyDeniedError,
    Rule,
)
from guardian_angel.core.decision import Decision

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_approval_guard(*extra_rules):
    return GuardianAngel(
        rules=[
            Rule(
                name="approve_deploy",
                tool="deploy",
                decision=DecisionStatus.REQUIRE_APPROVAL,
            ),
            *extra_rules,
        ]
    )


# ---------------------------------------------------------------------------
# ApprovalStatus
# ---------------------------------------------------------------------------


class TestApprovalStatus:
    def test_values(self):
        assert ApprovalStatus.APPROVED == "approved"
        assert ApprovalStatus.REJECTED == "rejected"
        assert ApprovalStatus.EXPIRED == "expired"

    def test_is_str(self):
        assert isinstance(ApprovalStatus.APPROVED, str)


# ---------------------------------------------------------------------------
# ApprovalRequest dataclass
# ---------------------------------------------------------------------------


class TestApprovalRequest:
    def _make(self, **kwargs):
        defaults = dict(
            action_request=ActionRequest(tool="deploy"),
            decision=Decision(status=DecisionStatus.REQUIRE_APPROVAL),
            requested_at=datetime.now(tz=timezone.utc),
            approval_id="approval-1",
        )
        defaults.update(kwargs)
        return ApprovalRequest(**defaults)

    def test_construction(self):
        req = self._make()
        assert req.approval_id == "approval-1"
        assert req.action_request.tool == "deploy"
        assert req.decision.status == DecisionStatus.REQUIRE_APPROVAL
        assert isinstance(req.requested_at, datetime)

    def test_approval_id_defaults_to_uuid(self):
        req = ApprovalRequest(
            action_request=ActionRequest(tool="deploy"),
            decision=Decision(status=DecisionStatus.REQUIRE_APPROVAL),
            requested_at=datetime.now(tz=timezone.utc),
        )
        assert req.approval_id

    def test_approvers_default_empty(self):
        req = self._make()
        assert req.approvers == []

    def test_approvers_custom(self):
        req = self._make(approvers=["alice", "bob"])
        assert req.approvers == ["alice", "bob"]


# ---------------------------------------------------------------------------
# ApprovalResponse dataclass
# ---------------------------------------------------------------------------


class TestApprovalResponse:
    def test_required_fields(self):
        resp = ApprovalResponse(approval_id="approval-1", status=ApprovalStatus.APPROVED)
        assert resp.approval_id == "approval-1"
        assert resp.status == ApprovalStatus.APPROVED

    def test_defaults(self):
        resp = ApprovalResponse(approval_id="approval-1", status=ApprovalStatus.APPROVED)
        assert resp.approved_by is None
        assert resp.reason is None
        assert resp.conditions == {}
        assert resp.responded_at is None

    def test_all_fields(self):
        now = datetime.now(tz=timezone.utc)
        resp = ApprovalResponse(
            approval_id="approval-2",
            status=ApprovalStatus.REJECTED,
            approved_by="alice",
            reason="too risky",
            conditions={"require_review": True},
            responded_at=now,
        )
        assert resp.approved_by == "alice"
        assert resp.reason == "too risky"
        assert resp.conditions == {"require_review": True}
        assert resp.responded_at == now


# ---------------------------------------------------------------------------
# GuardianAngel raises ApprovalRequiredError on REQUIRE_APPROVAL
# ---------------------------------------------------------------------------


class TestApprovalRequiredRaised:
    def test_authorize_returns_require_approval_decision(self):
        guard = _require_approval_guard()
        decision = guard.authorize(ActionRequest(tool="deploy"))
        assert decision.status == DecisionStatus.REQUIRE_APPROVAL

    def test_invoke_raises_approval_required_error(self):
        guard = _require_approval_guard()
        with pytest.raises(ApprovalRequiredError) as exc_info:
            guard.invoke(lambda: None, guard_ctx=GuardContext(tool="deploy"))
        assert exc_info.value.decision.status == DecisionStatus.REQUIRE_APPROVAL

    def test_invoke_deny_still_raises_policy_denied(self):
        guard = GuardianAngel(
            rules=[Rule(name="r", tool="nuke", decision=DecisionStatus.DENY)]
        )
        with pytest.raises(PolicyDeniedError) as exc_info:
            guard.invoke(lambda: None, guard_ctx=GuardContext(tool="nuke"))
        assert exc_info.value.decision.status == DecisionStatus.DENY

    def test_invoke_allow_executes_function(self):
        guard = GuardianAngel(rules=[])

        def read():
            return "ok"

        assert guard.invoke(read) == "ok"

    def test_decision_carries_rule_name(self):
        guard = _require_approval_guard()
        with pytest.raises(ApprovalRequiredError) as exc_info:
            guard.invoke(lambda: None, guard_ctx=GuardContext(tool="deploy"))
        assert exc_info.value.decision.rule_name == "approve_deploy"


# ---------------------------------------------------------------------------
# from_yaml classmethod
# ---------------------------------------------------------------------------


class TestFromYaml:
    def test_from_yaml_creates_guard(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text(
            "rules:\n"
            "  - name: approve_deploy\n"
            "    tool: deploy\n"
            "    decision: require_approval\n"
        )
        guard = GuardianAngel.from_yaml(str(policy))
        decision = guard.authorize(ActionRequest(tool="deploy"))
        assert decision.status == DecisionStatus.REQUIRE_APPROVAL

    def test_from_yaml_allow_by_default(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text("rules: []\n")
        guard = GuardianAngel.from_yaml(str(policy))
        decision = guard.authorize(ActionRequest(tool="anything"))
        assert decision.status == DecisionStatus.ALLOW


# ---------------------------------------------------------------------------
# guard.invoke() integration
# ---------------------------------------------------------------------------


class TestInvokeWithApproval:
    def test_require_approval_raises(self):
        guard = _require_approval_guard()

        def deploy(target):
            return f"deployed {target}"

        with pytest.raises(ApprovalRequiredError):
            guard.invoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy"))

    def test_deny_raises_policy_denied_error(self):
        guard = GuardianAngel(
            rules=[
                Rule(name="r", tool="deploy", decision=DecisionStatus.DENY),
            ],
        )

        def deploy(target):
            return "deployed"

        with pytest.raises(PolicyDeniedError):
            guard.invoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy"))

    def test_allow_executes_function(self):
        guard = GuardianAngel(rules=[])

        def deploy(target):
            return f"deployed {target}"

        result = guard.invoke(deploy, "prod")
        assert result == "deployed prod"

    def test_handler_receives_correct_request_id(self):
        guard = _require_approval_guard()

        def deploy(target):
            return "deployed"

        with pytest.raises(ApprovalRequiredError) as exc_info:
            guard.invoke(
                deploy, "prod",
                guard_ctx=GuardContext(tool="deploy", request_id="tool-req-1"),
            )
        assert exc_info.value.decision.status == DecisionStatus.REQUIRE_APPROVAL
