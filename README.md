# GuardianAngel

**A lightweight Python SDK for governing AI agent tool execution.**

GuardianAngel intercepts agent actions, evaluates policy, and decides whether they should be **allowed**, **denied**, or **require approval** — before the tool runs.

## Install

```bash
pip install guardian-angel
```

## Quickstart

Define rules in YAML:

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

Enforce them in Python:

```python
from guardian_angel import GuardianAngel, ActionRequest

guard = GuardianAngel.from_yaml("policy.yaml")

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

Rules are evaluated top to bottom, first match wins. If no rule matches, the default decision is **allow**.

## Features

- **Attribute matching** — exact match on `attributes` fields.
- **Predicate rules** — `when`, `all`, `any`, `not` with operators (`eq`, `ne`, `in`, `not_in`, `contains`, `gt`, `gte`, `lt`, `lte`, …).
- **Cross-field comparison** — `value_from` to compare one request field against another.
- **Tool decorator** — `@guard.tool(name="resource.delete")` to enforce policy automatically on Python functions.
- **YAML or Python** — define rules in YAML files or construct `Rule` objects in code.

See [`examples/`](examples/) for more.

## How It Works

```
Agent tool call
      ↓
ActionRequest(tool, attributes, request_id?)
      ↓
GuardianAngel.authorize(request)
      ↓
Decision (allow / deny / require_approval)
```

## Roadmap

- **v0.1** — Local policy evaluation, YAML rules, decorator *(current)*
- **v0.2** — Stronger validation, policy linting, documented adapter conventions
- **v0.3** — `guardian-angel simulate` CLI, policy testing
- **v0.4** — Lightweight framework adapters (LangGraph, OpenAI, CrewAI)
- **v0.5+** — Remote policy sources, audit sinks, approval stores

## License

MIT
