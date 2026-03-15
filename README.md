# GuardianAngel

**A lightweight Python SDK for governing AI agent tool execution.**

GuardianAngel intercepts agent actions, evaluates policy, and decides whether they should be **allowed**, **denied**, or **require approval** — before the tool runs.

The request model is intentionally small: one reserved tool identifier, one generic metadata bag, and an optional request ID.

## Why

Autonomous AI agents can call tools — merge PRs, delete branches, send messages, deploy services. GuardianAngel gives you deterministic, policy-based control over what agents are allowed to do.

## Install

```bash
pip install guardian-angel
```

## Quickstart

```python
from guardian_angel import GuardianAngel, ActionRequest, Rule, DENY

guard = GuardianAngel(rules=[
  Rule(
    name="block_sensitive_action",
    tool="resource.delete",
    decision=DENY,
    attributes={"context.risk_level": "high"},
  ),
])

decision = guard.authorize(
  ActionRequest(
    tool="resource.delete",
    request_id="req-123",
    attributes={"context.risk_level": "high"},
  )
)

print(decision.status)
# deny
```

## YAML Policy

Define rules in a YAML file:

```yaml
# policy.yaml
rules:
  - name: block_sensitive_action
    tool: resource.delete
    attributes:
      context.risk_level: high
    decision: deny
```

Load and evaluate:

```python
from guardian_angel import GuardianAngel, ActionRequest

guard = GuardianAngel.from_yaml("policy.yaml")
decision = guard.authorize(
  ActionRequest(
    tool="resource.delete",
    attributes={"context.risk_level": "high"},
  )
)
print(decision.status)  # "deny"
```

## Request Shape

```python
from typing import Any
from dataclasses import dataclass, field


@dataclass(slots=True)
class ActionRequest:
  tool: str
  attributes: dict[str, Any] = field(default_factory=dict)
  request_id: str | None = None
```

Keep all rule-specific metadata in `attributes`. GuardianAngel reserves only:

- `tool`: the normalized tool identifier you enforce policy against.
- `request_id`: an optional caller-supplied ID for tracing or correlation.
- `attributes`: a generic metadata bag used for rule matching.

## Attribute Conventions

Use dotted namespaces inside `attributes` so policy keys stay portable across teams and adapters.

Recommended prefixes:

- `subject.*`: who requested the operation.
- `agent.*`: the agent or automation identity.
- `resource.*`: the target resource.
- `context.*`: runtime context such as risk, source, or environment.

Example:

```python
request = ActionRequest(
  tool="resource.delete",
  request_id="req-42",
  attributes={
    "subject.role": "developer",
    "subject.tenant_id": "acme",
    "agent.trust_level": "low",
    "resource.environment": "prod",
    "context.risk_level": "high",
  },
)
```

Corresponding rule:

```yaml
rules:
  - name: block_untrusted_prod_delete
    tool: resource.delete
    attributes:
      agent.trust_level: low
      resource.environment: prod
      context.risk_level: high
    decision: deny
```

Avoid ad hoc keys like `user_role`, `role`, `requester_role`, and `caller_role` for the same concept. Namespacing is what keeps policies reusable.

## Tool Decorator

Wrap Python functions to enforce policy automatically:

```python
guard = GuardianAngel.from_yaml("policy.yaml")

@guard.tool(name="resource.delete")
def delete_resource(
  resource_id: str,
  *,
  attributes: dict | None = None,
  request_id: str | None = None,
):
  return {"deleted": True, "resource_id": resource_id}

# This raises PolicyDeniedError if policy blocks it.
# Otherwise the function executes normally.
delete_resource(
  "doc-123",
  request_id="req-777",
  attributes={"context.risk_level": "high"},
)
```

## How It Works

```
Agent tool call
      ↓
ActionRequest
      ↓
GuardianAngel.authorize(request)
      ↓
Decision (allow / deny / require_approval)
```

Rules are evaluated **top to bottom, first match wins**. If no rule matches, the default decision is **allow**.

## Roadmap

- **v0.1** — Local policy evaluation, YAML rules, decorator *(current)*
- **v0.2** — Stronger validation, policy linting, documented adapter conventions
- **v0.3** — `guardian-angel simulate` CLI, policy testing
- **v0.4** — Lightweight framework adapters (LangGraph, OpenAI, CrewAI)
- **v0.5+** — Remote policy sources, audit sinks, approval stores

## License

MIT
