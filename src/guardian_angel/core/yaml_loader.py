from __future__ import annotations

import dataclasses

import yaml

from .decision import DecisionStatus
from .exceptions import InvalidPolicyError
from .predicates import AllOf, AnyOf, Condition, Not, Predicate
from .rule import Rule

_REQUIRED_RULE_FIELDS = ("name", "tool", "decision")
_PREDICATE_FIELDS = {"when", "all", "any", "unless", "not"}
_ALLOWED_RULE_FIELDS = {*_REQUIRED_RULE_FIELDS, "attributes", *_PREDICATE_FIELDS}
_CONDITION_FIELDS = {f.name for f in dataclasses.fields(Condition)}


def load_policy_file(path: str) -> list[Rule]:
    """Load a YAML policy file and return a list of Rule objects.

    Raises InvalidPolicyError on missing/malformed content.
    """

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError as exc:
        raise InvalidPolicyError(f"Policy file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise InvalidPolicyError(f"Malformed YAML in {path}: {exc}") from exc

    return _parse_rules(data)


def _parse_rules(data) -> list[Rule]:
    """Validate parsed YAML data and convert to Rule objects."""

    if not isinstance(data, dict) or "rules" not in data:
        raise InvalidPolicyError("Policy file must contain a top-level 'rules' key")

    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        raise InvalidPolicyError("'rules' must be a list")

    return _build_rules(raw_rules)


def _build_rules(raw_rules: list) -> list[Rule]:
    return [_build_rule(i, entry) for i, entry in enumerate(raw_rules)]


def _build_rule(index: int, entry) -> Rule:
    _validate_rule_structure(index, entry)

    name = _require_non_empty_string(entry, "name", index)
    tool = _require_non_empty_string(entry, "tool", index)
    decision = _parse_decision(entry["decision"], index)
    attributes = entry.get("attributes", {})

    if not isinstance(attributes, dict):
        raise InvalidPolicyError(
            f"Rule at index {index}: 'attributes' must be a mapping"
        )

    return Rule(
        name=name,
        tool=tool,
        decision=decision,
        attributes=attributes,
        when=_parse_rule_predicate(entry, index),
    )


def _validate_rule_structure(index: int, entry) -> None:
    if not isinstance(entry, dict):
        raise InvalidPolicyError(f"Rule at index {index} must be a mapping")

    for field in _REQUIRED_RULE_FIELDS:
        if field not in entry:
            raise InvalidPolicyError(
                f"Rule at index {index} is missing required field '{field}'"
            )

    unknown_fields = sorted(set(entry) - _ALLOWED_RULE_FIELDS)
    if unknown_fields:
        raise InvalidPolicyError(
            f"Rule at index {index} contains unsupported field(s) {unknown_fields!r}. "
            "Use namespaced keys under 'attributes' instead."
        )


def _require_non_empty_string(entry: dict, field: str, index: int) -> str:
    value = entry[field]
    if not isinstance(value, str) or not value.strip():
        raise InvalidPolicyError(
            f"Rule at index {index}: '{field}' must be a non-empty string"
        )
    return value


def _parse_decision(raw_value, index: int) -> DecisionStatus:
    try:
        return DecisionStatus(raw_value)
    except ValueError:
        raise InvalidPolicyError(
            f"Rule at index {index}: 'decision' must be one of "
            f"{sorted(s.value for s in DecisionStatus)!r}, got {raw_value!r}"
        )


def _parse_rule_predicate(entry: dict, index: int) -> Predicate | None:
    predicate_fields = [field for field in _PREDICATE_FIELDS if field in entry]
    if not predicate_fields:
        return None
    if len(predicate_fields) > 1:
        raise InvalidPolicyError(
            f"Rule at index {index} must use only one predicate field from "
            f"{sorted(_PREDICATE_FIELDS)!r}"
        )

    field = predicate_fields[0]
    return _parse_predicate(entry[field], field=field, context=f"Rule at index {index}")


def _parse_predicate(raw_predicate, *, field: str, context: str) -> Predicate:
    if field == "when":
        if not isinstance(raw_predicate, dict):
            raise InvalidPolicyError(f"{context}: 'when' must be a mapping")
        if any(key in raw_predicate for key in ("all", "any", "not", "unless")):
            return _parse_nested_predicate(raw_predicate, context=f"{context} 'when'")
        return _parse_condition(raw_predicate, context=f"{context} 'when'")

    if field == "all":
        return AllOf(items=_parse_predicate_list(raw_predicate, field="all", context=context))
    if field == "any":
        return AnyOf(items=_parse_predicate_list(raw_predicate, field="any", context=context))
    if field in {"not", "unless"}:
        return Not(item=_parse_inline_predicate(raw_predicate, context=f"{context} '{field}'"))

    raise InvalidPolicyError(f"{context}: unsupported predicate field {field!r}")


def _parse_nested_predicate(raw_predicate: dict, *, context: str) -> Predicate:
    predicate_fields = [field for field in ("all", "any", "not", "unless") if field in raw_predicate]
    if len(predicate_fields) != 1:
        raise InvalidPolicyError(
            f"{context}: nested predicate must contain exactly one of ['all', 'any', 'not', 'unless']"
        )

    field = predicate_fields[0]
    return _parse_predicate(raw_predicate[field], field=field, context=context)


def _parse_predicate_list(raw_items, *, field: str, context: str) -> tuple[Predicate, ...]:
    if not isinstance(raw_items, list) or not raw_items:
        raise InvalidPolicyError(f"{context}: '{field}' must be a non-empty list")

    return tuple(
        _parse_inline_predicate(item, context=f"{context} '{field}'[{index}]")
        for index, item in enumerate(raw_items)
    )


def _parse_inline_predicate(raw_predicate, *, context: str) -> Predicate:
    if not isinstance(raw_predicate, dict):
        raise InvalidPolicyError(f"{context}: predicate must be a mapping")

    if any(field in raw_predicate for field in ("all", "any", "not", "unless")):
        return _parse_nested_predicate(raw_predicate, context=context)

    return _parse_condition(raw_predicate, context=context)


def _parse_condition(raw_condition: dict, *, context: str) -> Condition:
    if not isinstance(raw_condition, dict):
        raise InvalidPolicyError(f"{context}: condition must be a mapping")

    unknown_fields = sorted(set(raw_condition) - _CONDITION_FIELDS)
    if unknown_fields:
        raise InvalidPolicyError(
            f"{context}: condition contains unsupported field(s) {unknown_fields!r}"
        )

    missing_fields = [field for field in ("key", "op") if field not in raw_condition]
    if missing_fields:
        raise InvalidPolicyError(
            f"{context}: condition is missing required field(s) {missing_fields!r}"
        )

    has_value = "value" in raw_condition
    has_value_from = "value_from" in raw_condition
    if has_value == has_value_from:
        raise InvalidPolicyError(
            f"{context}: condition must specify exactly one of 'value' or 'value_from'"
        )

    return Condition(
        key=raw_condition["key"],
        op=raw_condition["op"],
        value=raw_condition.get("value"),
        value_from=raw_condition.get("value_from"),
    )