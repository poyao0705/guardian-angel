from __future__ import annotations

import json

from guardian_angel import ActionRequest, GuardianAngel


def load_request(path: str) -> ActionRequest:
    """Load an action request from a JSON file."""

    with open(path, encoding="utf-8") as file:
        data = json.load(file)

    return ActionRequest(**data)


def evaluate_request(policy_path: str, request: ActionRequest):
    """Evaluate a YAML policy file against an already-loaded action request."""

    guard = GuardianAngel.from_yaml(policy_path)
    return guard.authorize(request)


def evaluate_files(policy_path: str, request_path: str):
    """Evaluate a YAML policy file against a JSON action request file."""

    request = load_request(request_path)
    return evaluate_request(policy_path, request)