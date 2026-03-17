from guardian_angel import (
    DecisionStatus,
    ActionRequest,
    Decision,
    GuardianAngel,
    PolicyEvaluator,
    Rule,
)
from guardian_angel.core.policy_engine import PolicyEngine

import pytest


class TestRuleMatching:
    def test_exact_tool_match(self):
        rule = Rule(name="r1", tool="github.merge_pr", decision=DecisionStatus.DENY)
        request = ActionRequest(tool="github.merge_pr")
        assert rule.matches(request)

    def test_tool_mismatch(self):
        rule = Rule(name="r1", tool="github.merge_pr", decision=DecisionStatus.DENY)
        request = ActionRequest(tool="github.delete_branch")
        assert not rule.matches(request)

    def test_attribute_match(self):
        rule = Rule(
            name="r1",
            tool="deploy",
            decision=DecisionStatus.DENY,
            attributes={"resource.environment": "prod"},
        )
        request = ActionRequest(
            tool="deploy",
            attributes={"resource.environment": "prod"},
        )
        assert rule.matches(request)

    def test_attribute_mismatch(self):
        rule = Rule(
            name="r1",
            tool="deploy",
            decision=DecisionStatus.DENY,
            attributes={"resource.environment": "prod"},
        )
        request = ActionRequest(
            tool="deploy",
            attributes={"resource.environment": "staging"},
        )
        assert not rule.matches(request)

    def test_attribute_missing_from_request(self):
        rule = Rule(
            name="r1",
            tool="deploy",
            decision=DecisionStatus.DENY,
            attributes={"resource.environment": "prod"},
        )
        request = ActionRequest(tool="deploy")
        assert not rule.matches(request)

    def test_extra_request_attributes_still_match(self):
        rule = Rule(
            name="r1",
            tool="deploy",
            decision=DecisionStatus.DENY,
            attributes={"resource.environment": "prod"},
        )
        request = ActionRequest(
            tool="deploy",
            attributes={
                "resource.environment": "prod",
                "resource.region": "us-east-1",
            },
        )
        assert rule.matches(request)

    def test_request_id_is_reserved_but_not_used_for_matching(self):
        rule = Rule(
            name="r1",
            tool="deploy",
            decision=DecisionStatus.DENY,
            attributes={"context.risk_level": "high"},
        )
        request = ActionRequest(
            tool="deploy",
            attributes={"context.risk_level": "high"},
            request_id="req-123",
        )
        assert rule.matches(request)


class TestPolicyEngine:
    def test_exact_match_returns_decision(self):
        engine = PolicyEngine(
            rules=[Rule(name="block", tool="deploy", decision=DecisionStatus.DENY)]
        )
        decision = engine.evaluate(ActionRequest(tool="deploy"))
        assert decision.status == DecisionStatus.DENY
        assert decision.rule_name == "block"

    def test_no_match_defaults_to_allow(self):
        engine = PolicyEngine(
            rules=[Rule(name="block", tool="deploy", decision=DecisionStatus.DENY)]
        )
        decision = engine.evaluate(ActionRequest(tool="read"))
        assert decision.status == DecisionStatus.ALLOW
        assert decision.rule_name is None

    def test_empty_rules_defaults_to_allow(self):
        engine = PolicyEngine(rules=[])
        decision = engine.evaluate(ActionRequest(tool="anything"))
        assert decision.status == DecisionStatus.ALLOW

    def test_first_match_wins(self):
        engine = PolicyEngine(
            rules=[
                Rule(name="deny_first", tool="deploy", decision=DecisionStatus.DENY),
                Rule(name="allow_second", tool="deploy", decision=DecisionStatus.ALLOW),
            ]
        )
        decision = engine.evaluate(ActionRequest(tool="deploy"))
        assert decision.status == DecisionStatus.DENY
        assert decision.rule_name == "deny_first"

    def test_first_match_wins_reversed(self):
        engine = PolicyEngine(
            rules=[
                Rule(name="allow_first", tool="deploy", decision=DecisionStatus.ALLOW),
                Rule(name="deny_second", tool="deploy", decision=DecisionStatus.DENY),
            ]
        )
        decision = engine.evaluate(ActionRequest(tool="deploy"))
        assert decision.status == DecisionStatus.ALLOW
        assert decision.rule_name == "allow_first"

    def test_require_approval_decision(self):
        engine = PolicyEngine(
            rules=[
                Rule(
                    name="approve_prod",
                    tool="deploy",
                    decision=DecisionStatus.REQUIRE_APPROVAL,
                    attributes={"resource.environment": "prod"},
                )
            ]
        )
        decision = engine.evaluate(
            ActionRequest(
                tool="deploy",
                attributes={"resource.environment": "prod"},
            )
        )
        assert decision.status == DecisionStatus.REQUIRE_APPROVAL
        assert decision.rule_name == "approve_prod"

    def test_rule_name_populated_in_decision(self):
        engine = PolicyEngine(
            rules=[Rule(name="my_rule", tool="x", decision=DecisionStatus.DENY)]
        )
        decision = engine.evaluate(ActionRequest(tool="x"))
        assert decision.rule_name == "my_rule"
        assert "my_rule" in decision.reason


class TestCustomEvaluator:
    def test_custom_engine_is_used(self):
        class AlwaysDeny:
            def evaluate(self, request: ActionRequest) -> Decision:
                return Decision(status=DecisionStatus.DENY, reason="custom deny")

        guard = GuardianAngel(engine=AlwaysDeny())
        decision = guard.authorize(ActionRequest(tool="anything"))
        assert decision.status == DecisionStatus.DENY
        assert decision.reason == "custom deny"

    def test_custom_engine_satisfies_protocol(self):
        class MyEngine:
            def evaluate(self, request: ActionRequest) -> Decision:
                return Decision(status=DecisionStatus.ALLOW, reason="ok")

        assert isinstance(MyEngine(), PolicyEvaluator)

    def test_rules_and_engine_raises(self):
        class Dummy:
            def evaluate(self, request: ActionRequest) -> Decision:
                return Decision(status=DecisionStatus.ALLOW, reason="ok")

        with pytest.raises(ValueError, match="not both"):
            GuardianAngel(
                rules=[Rule(name="r", tool="x", decision=DecisionStatus.DENY)],
                engine=Dummy(),
            )

    def test_decorator_works_with_custom_engine(self):
        class DenyAll:
            def evaluate(self, request: ActionRequest) -> Decision:
                return Decision(status=DecisionStatus.DENY, reason="nope")

        guard = GuardianAngel(engine=DenyAll())

        @guard.tool(name="my_tool")
        def my_func():
            return "ok"

        from guardian_angel import PolicyDeniedError

        with pytest.raises(PolicyDeniedError):
            my_func()
