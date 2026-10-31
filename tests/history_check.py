"""Strict OpenAI chat-history validation shared by loop tests.

Mirrors the provider's own sequencing rules: the first message is
the system prompt; every ``tool`` message answers a ``tool_calls``
entry of the nearest preceding assistant message (same id); ids are
never orphaned or duplicated; roles follow the
system -> user -> assistant -> tool order. Raises AssertionError
naming the first defect. The rule-proposal loop's strict stand-in
transport maps that to the provider's HTTP 400; the analysis tests
run the same check over captured histories.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def validate_openai_history(messages: Sequence[Any]) -> None:
    """Assert one request's message history is provider-well-formed."""
    if not isinstance(messages, (list, tuple)) or not messages:
        raise AssertionError("history must be a non-empty list")
    first = messages[0]
    if not isinstance(first, Mapping) or first.get("role") != "system":
        raise AssertionError("history[0] must be the system message")
    if not isinstance(first.get("content"), str):
        raise AssertionError("history[0] system message needs string content")
    announced: dict[str, int] = {}
    answered: set[str] = set()
    open_tools: set[str] = set()
    previous_role = "system"
    previous_had_tools = False
    for index in range(1, len(messages)):
        message = messages[index]
        if not isinstance(message, Mapping):
            raise AssertionError(f"history[{index}] must be a mapping")
        role = message.get("role")
        if role not in ("user", "assistant", "tool"):
            raise AssertionError(f"history[{index}] has unknown role {role!r}")
        if previous_role == "system" and role != "user":
            raise AssertionError(f"history[{index}]: {role} cannot follow system")
        if previous_role == "user" and role != "assistant":
            raise AssertionError(f"history[{index}]: {role} cannot follow user")
        if previous_role == "assistant" and previous_had_tools and role != "tool":
            raise AssertionError(
                f"history[{index}]: assistant tool_calls must be followed by tool"
            )
        if previous_role == "assistant" and not previous_had_tools and role != "user":
            raise AssertionError(
                f"history[{index}]: {role} cannot follow a final assistant answer"
            )
        if role == "assistant":
            calls = message.get("tool_calls") or []
            if not isinstance(calls, list):
                raise AssertionError(f"history[{index}] tool_calls must be a list")
            current: set[str] = set()
            for call in calls:
                if not isinstance(call, Mapping):
                    raise AssertionError(
                        f"history[{index}] tool call must be a mapping"
                    )
                call_id = call.get("id")
                function = call.get("function")
                if not isinstance(call_id, str) or not call_id:
                    raise AssertionError(
                        f"history[{index}] tool call needs a string id"
                    )
                if call_id in announced:
                    raise AssertionError(
                        f"history[{index}] duplicates tool_call_id {call_id!r}"
                    )
                if not isinstance(function, Mapping):
                    raise AssertionError(
                        f"history[{index}] tool call needs a function object"
                    )
                if not isinstance(function.get("name"), str) or not function.get(
                    "name"
                ):
                    raise AssertionError(f"history[{index}] tool call needs a name")
                if not isinstance(function.get("arguments"), str):
                    raise AssertionError(
                        f"history[{index}] tool call needs string arguments"
                    )
                announced[call_id] = index
                current.add(call_id)
            open_tools = current
            previous_had_tools = bool(current)
        elif role == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or not call_id:
                raise AssertionError(f"history[{index}] tool message needs an id")
            if not isinstance(message.get("content"), str):
                raise AssertionError(f"history[{index}] tool message needs content")
            if call_id not in open_tools:
                raise AssertionError(
                    f"history[{index}] tool_call_id {call_id!r} has no matching"
                    " assistant message"
                )
            if call_id in answered:
                raise AssertionError(
                    f"history[{index}] duplicates answer for {call_id!r}"
                )
            answered.add(call_id)
        else:
            if not isinstance(message.get("content"), str):
                raise AssertionError(f"history[{index}] user message needs content")
        previous_role = role
    dangling = sorted(set(announced) - answered)
    if dangling:
        raise AssertionError(
            f"assistant tool_calls never answered: {', '.join(dangling)}"
        )
