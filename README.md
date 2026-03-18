# Guardian Angel

**A lightweight Python SDK for governing AI agent tool execution.**

Guardian Angel intercepts agent actions, evaluates policy, and returns **allow**, **deny**, or **require_approval** — before the tool runs.

## Install

```bash
pip install guardian-angel

# optional CLI
pip install guardian-angel[cli]
```

## Quickstart

```yaml
# policy.yaml
rules:
  - name: block_risky_delete
    tool: resource.delete
    decision: deny
    all:
      - key: resource.environment
        op: eq
        value: prod
      - key: context.risk_level
        op: eq
        value: high
```

```json
// policy.json
{
  "rules": [
    {
      "name": "block_risky_delete",
      "tool": "resource.delete",
      "decision": "deny",
      "all": [
        { "key": "resource.environment", "op": "eq", "value": "prod" },
        { "key": "context.risk_level", "op": "eq", "value": "high" }
      ]
    }
  ]
}
```

```python
from guardian_angel import ActionRequest, DecisionStatus, GuardConfig, GuardianAngel

# From YAML
guard = GuardianAngel.from_yaml(
    "policy.yaml",
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
    ),
)

# Or from JSON
guard = GuardianAngel.from_json(
    "policy.json",
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
    ),
)

decision = guard.authorize(
    ActionRequest(
        tool="resource.delete",
        attributes={
            "resource.environment": "prod",
            "context.risk_level": "high",
        },
    )
)
print(decision.status)  # "deny"
```

First matching rule wins. No match uses `default_decision`, which defaults to **allow**.

## CLI

```bash
guardian-angel evaluate policy.yaml request.json
guardian-angel evaluate policy.yaml request.json --explain
guardian-angel --verbose evaluate policy.yaml request.json
guardian-angel --version
```

`--explain` prints the matched rule and reason. `--verbose` adds input context.

## Features

- **Predicate rules** — `when`, `all`, `any`, `not` with operators (`eq`, `ne`, `in`, `not_in`, `contains`, `gt`, `gte`, `lt`, `lte`, …)
- **Explicit failure semantics** — configurable default/no-match behavior, evaluation-error behavior, protected tools, and required request fields
- **Cross-field comparison** — `value_from` to compare one attribute against another
- **Approval signal** — rules returning `require_approval` raise `ApprovalRequiredError`, letting the calling framework handle human-in-the-loop approval in whatever way is native to it (LangGraph interrupt, CrewAI human input, webhook, etc.)
- **Tool invocation** — `guard.invoke()` (sync) and `guard.ainvoke()` (async) for policy enforcement on any function without decorators
- **YAML, JSON, or Python** — define rules in files (`from_yaml`, `from_json`) or construct `Rule` objects in code
- **CLI** — evaluate policies from the command line with colored output

See [`examples/`](examples/) for more.
For YAML policies see [`examples/yaml_policy_example.py`](examples/yaml_policy_example.py); for JSON see [`examples/json_policy_example.py`](examples/json_policy_example.py).
If you want one end-to-end reference that wires everything together, start with [`examples/complete_pipeline_example.py`](examples/complete_pipeline_example.py).

## How It Works

```
Agent tool call → ActionRequest → GuardianAngel.authorize() → Decision
                                                                 ├─ allow → execute
                                                                 ├─ deny  → PolicyDeniedError
                                                                 └─ require_approval → ApprovalRequiredError
```

## Safety Modes

Guardian Angel separates:

- no rule matched
- policy evaluation failed

```python
from guardian_angel import DecisionStatus, GuardConfig, GuardianAngel

# Global allow, but protected tools require approval when no rule matches.
guard = GuardianAngel(
    rules=rules,
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
        protected_tool_prefixes=("github.", "filesystem."),
        protected_no_match_decision=DecisionStatus.REQUIRE_APPROVAL,
    ),
)

# Full fail-closed mode.
fail_closed_guard = GuardianAngel(
    rules=rules,
    config=GuardConfig(default_decision=DecisionStatus.DENY),
)
```

## Operator Semantics

- Missing keys do not match ordinary comparisons such as `eq`, `gt`, `in`, or `contains`.
- Use `exists` and `not_exists` when presence itself matters.
- Type mismatches are converted into deterministic evaluation errors.
- Critical request fields can be required globally with `GuardConfig(required_fields=(...))`.

## Approval Signal

When a rule returns `require_approval`, Guardian Angel raises `ApprovalRequiredError` with the full `Decision` attached. It does **not** handle the approval workflow itself — the calling framework (LangGraph interrupt, CrewAI human input, webhook, Slack bot, etc.) decides how to obtain human approval.

```python
from guardian_angel import ApprovalRequiredError

try:
    result = guard.invoke(
        update_resource,
        "doc-1",
        guard_ctx=GuardContext(
            tool="resource.update",
            attributes={"resource.environment": "prod", "subject.role": "developer"},
        ),
    )
except ApprovalRequiredError as exc:
    print(f"Approval needed: {exc.decision}")
    # Hand off to your framework's approval mechanism
```

See [`examples/approval_example.py`](examples/approval_example.py) (sync) and [`examples/async_approval_example.py`](examples/async_approval_example.py) (async) for full working examples.

## `guard.invoke()` / `guard.ainvoke()`

`invoke` and `ainvoke` call any function under policy enforcement without decorating it.
Policy context is passed via `guard_ctx`; the function itself stays completely clean:

```python
from guardian_angel import GuardContext

def update_resource(resource_id):
    return {"updated": True, "resource_id": resource_id}

# Sync
result = guard.invoke(
    update_resource,
    "doc-1",
    guard_ctx=GuardContext(
        tool="resource.update",
        attributes={"resource.environment": "prod", "subject.role": "developer"},
        request_id="req-1",
    ),
)

# Async — works with both sync and async functions
async def update_resource_async(resource_id):
    return {"updated": True, "resource_id": resource_id}

result = await guard.ainvoke(
    update_resource_async,
    "doc-1",
    guard_ctx=GuardContext(
        tool="resource.update",
        attributes={"resource.environment": "prod"},
    ),
)
```

If `guard_ctx.tool` is not set, the function's `__name__` is used as the policy tool name.

## CLI Validation

The CLI now validates request payloads before evaluation.

- Exit code `2`: invalid request input
- Exit code `3`: invalid policy input

## Roadmap

- **v0.1** — Local policy evaluation, YAML rules, decorator
- **v0.2** — Stronger validation, policy linting
- **v0.3** — CLI with `evaluate`, `--explain`, `--verbose`
- **v0.4** — Approval signal via `ApprovalRequiredError` *(current)*
- **v0.5** — Framework adapters (LangGraph, OpenAI, CrewAI)

## License

MIT
