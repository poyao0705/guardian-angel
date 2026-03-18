import json
import os
import tempfile

import pytest

from guardian_angel import InvalidPolicyError, Rule
from guardian_angel.core.policy_loader import load_json_policy, load_json_policy_file


def _write_json(data: dict | list) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps(data).encode())
    os.close(fd)
    return path


VALID_POLICY = {
    "rules": [
        {
            "name": "deny_prod_delete",
            "tool": "github.delete_branch",
            "attributes": {"resource.environment": "prod"},
            "decision": "deny",
        },
        {
            "name": "require_high_risk_merge",
            "tool": "github.merge_pr",
            "attributes": {"context.risk_level": "high"},
            "decision": "require_approval",
        },
    ]
}


class TestLoadJsonPolicyFile:
    def test_valid_json_loads_rules(self):
        path = _write_json(VALID_POLICY)
        try:
            rules = load_json_policy_file(path)
            assert len(rules) == 2
            assert isinstance(rules[0], Rule)
            assert rules[0].name == "deny_prod_delete"
            assert rules[1].name == "require_high_risk_merge"
        finally:
            os.unlink(path)

    def test_minimal_rule(self):
        data = {"rules": [{"name": "block_all", "tool": "deploy", "decision": "deny"}]}
        path = _write_json(data)
        try:
            rules = load_json_policy_file(path)
            assert len(rules) == 1
            assert rules[0].attributes == {}
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        with pytest.raises(InvalidPolicyError, match="Policy file not found"):
            load_json_policy_file("/nonexistent/policy.json")

    def test_malformed_json_raises(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.write(fd, b"{bad json")
        os.close(fd)
        try:
            with pytest.raises(InvalidPolicyError, match="Malformed JSON"):
                load_json_policy_file(path)
        finally:
            os.unlink(path)

    def test_missing_rules_key_raises(self):
        path = _write_json({"policies": []})
        try:
            with pytest.raises(InvalidPolicyError, match="top-level 'rules' key"):
                load_json_policy_file(path)
        finally:
            os.unlink(path)


class TestLoadJsonPolicy:
    def test_valid_json_string(self):
        rules = load_json_policy(json.dumps(VALID_POLICY))
        assert len(rules) == 2
        assert rules[0].name == "deny_prod_delete"

    def test_malformed_json_string_raises(self):
        with pytest.raises(InvalidPolicyError, match="Malformed JSON"):
            load_json_policy("{bad")

    def test_missing_rules_key_raises(self):
        with pytest.raises(InvalidPolicyError, match="top-level 'rules' key"):
            load_json_policy(json.dumps({"policies": []}))

    def test_when_condition(self):
        data = {
            "rules": [
                {
                    "name": "block_prod",
                    "tool": "resource.delete",
                    "decision": "deny",
                    "when": {"key": "resource.environment", "op": "eq", "value": "prod"},
                }
            ]
        }
        rules = load_json_policy(json.dumps(data))
        assert rules[0].when is not None
        assert rules[0].when.key == "resource.environment"


class TestGuardianAngelFromJson:
    def test_from_json_creates_guard(self):
        from guardian_angel import GuardianAngel

        path = _write_json(VALID_POLICY)
        try:
            guard = GuardianAngel.from_json(path)
            assert guard is not None
        finally:
            os.unlink(path)
