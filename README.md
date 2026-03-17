# GuardianAngel

**A lightweight Python SDK for governing AI agent tool execution.**

GuardianAngel intercepts agent actions, evaluates policy, and returns **allow**, **deny**, or **require_approval** — before the tool runs.

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

First matching rule wins. No match → **allow**.

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
- **Cross-field comparison** — `value_from` to compare one attribute against another
- **Tool decorator** — `@guard.tool(name="...")` for automatic policy enforcement
- **YAML or Python** — define rules in files or construct `Rule` objects in code
- **CLI** — evaluate policies from the command line with colored output

See [`examples/`](examples/) for more.

## How It Works

```
Agent tool call → ActionRequest → GuardianAngel.authorize() → Decision
```

## Roadmap

- **v0.1** — Local policy evaluation, YAML rules, decorator
- **v0.2** — Stronger validation, policy linting
- **v0.3** — CLI with `evaluate`, `--explain`, `--verbose` *(current)*
- **v0.4** — Framework adapters (LangGraph, OpenAI, CrewAI)
- **v0.5+** — Remote policy sources, audit sinks, approval stores

## License

MIT
