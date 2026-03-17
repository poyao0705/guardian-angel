from __future__ import annotations

import operator
from typing import Any

from .predicates import AllOf, AnyOf, Condition, Not, Predicate
from .request import ActionRequest

_CONDITION_OPERATORS = {
    "eq": operator.eq,
    "ne": operator.ne,
    "in": lambda actual, expected: actual in expected,
    "not_in": lambda actual, expected: actual not in expected,
    "contains": lambda actual, expected: expected in actual,
    "not_contains": lambda actual, expected: expected not in actual,
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
}


def resolve_key(request: ActionRequest, key: str) -> Any:
    """Read a value from the request by key.

    The reserved keys ``tool`` and ``request_id`` map to the corresponding
    top-level fields; everything else is looked up in ``attributes``.
    """

    if key == "tool":
        return request.tool
    if key == "request_id":
        return request.request_id
    return request.attributes.get(key)


def evaluate_condition(request: ActionRequest, condition: Condition) -> bool:
    """Apply a single condition's operator against resolved request values."""

    actual = resolve_key(request, condition.key)
    expected = (
        resolve_key(request, condition.value_from)
        if condition.value_from is not None
        else condition.value
    )

    try:
        return _CONDITION_OPERATORS[condition.op](actual, expected)
    except KeyError as exc:
        raise ValueError(f"Unsupported operator: {condition.op}") from exc


def evaluate_predicate(request: ActionRequest, predicate: Predicate) -> bool:
    """Recursively evaluate a predicate tree against the request."""

    if isinstance(predicate, Condition):
        return evaluate_condition(request, predicate)
    if isinstance(predicate, AllOf):
        return all(evaluate_predicate(request, item) for item in predicate.items)
    if isinstance(predicate, AnyOf):
        return any(evaluate_predicate(request, item) for item in predicate.items)
    if isinstance(predicate, Not):
        return not evaluate_predicate(request, predicate.item)

    raise TypeError(f"Unsupported predicate type: {type(predicate)!r}")