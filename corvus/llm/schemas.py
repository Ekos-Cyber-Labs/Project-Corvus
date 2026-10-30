"""Triage response schema: the condensed incident Glimmer produces.

One structured call per incident, no tools. Every field is bounded
in length and count so a runaway completion fails schema validation
instead of filling the database. ``language`` exists because the
shared semantics validator requires the output language to match the
request; triage always condenses in English unless asked otherwise.

Grounding is enforced by :meth:`CondensedIncident.semantic_errors`,
which :func:`corvus.llm.call.validate_semantics` runs after the
generic checks: every entity value must literally appear in the
evidence payload given to the model (an invented host is a failed
attempt), and every cited ``event_uid`` must belong to the incident
(covered generically by the nested ``event_uid`` walk in
:mod:`corvus.llm.call`).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CondensedEntity",
    "CondensedIncident",
    "KeyEvent",
    "TimelineEntry",
]

#: Entity kinds the triage output may cite. Fixed set: anything else
#: is a schema failure, never a silent pass.
EntityKind = Literal["host", "user", "ip", "process", "file"]


class CondensedEntity(BaseModel):
    """One typed entity cited by the condensed incident."""

    model_config = ConfigDict(extra="forbid")

    type: EntityKind
    value: str = Field(min_length=1, max_length=512)


class KeyEvent(BaseModel):
    """One incident event plus the one-line reason it matters."""

    model_config = ConfigDict(extra="forbid")

    event_uid: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=280)


class TimelineEntry(BaseModel):
    """One ordered timeline row anchored to an incident event."""

    model_config = ConfigDict(extra="forbid")

    time: str = Field(min_length=1, max_length=64)
    event_uid: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=280)


def _string_leaves(value: Any) -> Iterator[str]:
    """Yield the string leaves of a structured payload, unescaped.

    Mapping keys are not evidence and are never yielded; neither are
    booleans or nulls. Plain ints and floats yield their decimal
    text so a numeric leaf still grounds a matching value.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _string_leaves(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _string_leaves(item)
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, (int, float)):
        yield str(value)


class CondensedIncident(BaseModel):
    """The condensed incident Glimmer returns for one cluster."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=2000)
    entities: list[CondensedEntity] = Field(default_factory=list, max_length=30)
    key_events: list[KeyEvent] = Field(default_factory=list, max_length=40)
    timeline: list[TimelineEntry] = Field(default_factory=list, max_length=60)
    visibility_gaps: list[str] = Field(default_factory=list, max_length=20)
    uncertainties: list[str] = Field(default_factory=list, max_length=20)
    language: Literal["en", "es"] = "en"

    @classmethod
    def semantic_errors(
        cls, parsed: Mapping[str, Any], context: Any
    ) -> list[dict[str, str]]:
        """Ground every entity value in the evidence payload.

        Returns one ``invented_entity`` item per entity value that
        does not literally occur in a string leaf of
        ``context.payload`` (the raw incident payload handed to the
        model, before masking). Comparison is case-sensitive against
        the original unescaped text — a JSON serialization would
        escape backslashes and quotes and reject honest Windows
        paths. Mapping keys are not evidence. A missing payload
        yields no items: the generic validators still apply, and
        inventing the evidence text here would be worse than
        skipping the check. Event-uid membership is checked
        generically by
        :func:`corvus.llm.call.validate_semantics`.
        """
        if not isinstance(parsed, Mapping):
            return []
        payload = getattr(context, "payload", None)
        if payload is None:
            return []
        leaves = list(_string_leaves(payload))
        entities = parsed.get("entities")
        if not isinstance(entities, list):
            return []
        errors: list[dict[str, str]] = []
        for index, entity in enumerate(entities):
            if not isinstance(entity, Mapping):
                continue
            value = entity.get("value")
            if not isinstance(value, str) or not value.strip():
                continue
            if not any(value in leaf for leaf in leaves):
                errors.append(
                    {
                        "code": "invented_entity",
                        "path": f"entities.{index}.value",
                        "message": (
                            f"entity value {value!r} does not appear "
                            "in the incident evidence"
                        ),
                    }
                )
        return errors
