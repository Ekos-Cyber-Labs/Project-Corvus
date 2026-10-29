"""Model-bound payload preparation: mask, label, pseudonymize, redact.

:func:`prepare_payload` is the single path from a structured incident
payload to what a model may see:

1. Always: :func:`corvus.normalize.technique_ids.mask_payload` over
   the structured payload, never over serialized text.
2. Detector labels (``visible`` keeps them wrapped under
   ``detector_labels``; ``blind`` strips the technique-bearing ones).
3. Trust ``cloud`` only: every ``raw_data`` field is dropped first
   (raw logs stay on-prem; the typed OCSF fields carry the evidence;
   nothing is truncated or masked — the field is gone), then stable
   pseudonyms (:mod:`corvus.guardrails.pseudonymizer`, including the
   free-text entity scan over every remaining string leaf) and the
   secret redactor (:func:`corvus.guardrails.egress.redact`). Trust
   ``onprem`` skips all three — Glimmer reads raw evidence on-prem.

``labels_mode`` resolves from the ``DETECTOR_LABELS`` environment
variable (``visible`` | ``blind``) when not passed, defaulting to
``visible``; anything else raises :class:`ValueError`. The resolved
mode is returned with the payload so reports can print which mode
produced it.

Limitation (by design): rule titles are not touched in either mode —
``finding_info.title`` (and the analytic name, which is the same rule
title) stays where it is so the model can name the detection. In
``blind`` mode that means a title that itself names a technique
remains visible; titles are detector-chosen, not attacker-controlled,
which is why the mode accepts this.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any, Literal, NamedTuple

from corvus.normalize.technique_ids import TECHNIQUE_NAME_MASK, mask_payload

__all__ = [
    "DETECTOR_LABELS_VAR",
    "LabelsMode",
    "PreparedPayload",
    "TAG_KEYS",
    "prepare_payload",
]

#: Environment variable selecting the default labels mode.
DETECTOR_LABELS_VAR = "DETECTOR_LABELS"

LabelsMode = Literal["visible", "blind"]

#: ``unmapped`` keys holding rule technique tags (Sigma ``attack.*``
#: tags and their relatives). ``visible`` moves them under
#: ``detector_labels``; ``blind`` drops them.
TAG_KEYS = frozenset({"tags", "rule_tags", "sigma_tags", "attack_tags"})


class PreparedPayload(NamedTuple):
    """A model-bound payload plus the labels mode that produced it."""

    payload: Any
    labels_mode: str


def _resolve_labels_mode(labels_mode: str | None) -> str:
    if labels_mode is None:
        raw = os.environ.get(DETECTOR_LABELS_VAR, "").strip().lower()
        labels_mode = raw if raw else "visible"
    if labels_mode not in ("visible", "blind"):
        raise ValueError(
            f"labels_mode must be 'visible' or 'blind', got {labels_mode!r}"
        )
    return labels_mode


def _apply_visible(value: Any) -> Any:
    """Move detector labels under ``detector_labels``, keeping them."""
    if isinstance(value, dict):
        info = value.get("finding_info")
        if isinstance(info, dict):
            labels: dict[str, Any] = {}
            for key in ("attacks", "analytic"):
                if key in info:
                    labels[key] = info.pop(key)
            unmapped = info.get("unmapped")
            if isinstance(unmapped, dict):
                tags = {
                    k: unmapped.pop(k)
                    for k in list(unmapped)
                    if isinstance(k, str) and k.lower() in TAG_KEYS
                }
                if tags:
                    labels["tags"] = tags
            if labels:
                info["detector_labels"] = labels
        return {key: _apply_visible(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_apply_visible(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_apply_visible(item) for item in value)
    return value


def _apply_blind(value: Any) -> Any:
    """Drop attacks, rule technique tags and every technique-name value."""
    if isinstance(value, dict):
        scrubbed: dict[Any, Any] = {}
        for key, item in value.items():
            lowered = key.lower() if isinstance(key, str) else ""
            if lowered == "attacks" or "technique" in lowered or lowered in TAG_KEYS:
                if lowered == "attacks" or lowered in TAG_KEYS:
                    continue
                scrubbed[key] = TECHNIQUE_NAME_MASK
            else:
                scrubbed[key] = _apply_blind(item)
        return scrubbed
    if isinstance(value, list):
        return [_apply_blind(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_apply_blind(item) for item in value)
    return value


def _redact_strings(value: Any) -> Any:
    """Apply the secret redactor to every string leaf (keys untouched)."""
    from corvus.guardrails.egress import redact

    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: _redact_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_strings(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_strings(item) for item in value)
    return value


def _drop_raw_data(value: Any) -> Any:
    """Remove every ``raw_data`` field; keep everything else as is."""
    if isinstance(value, dict):
        return {
            key: _drop_raw_data(item)
            for key, item in value.items()
            if not (isinstance(key, str) and key.lower() == "raw_data")
        }
    if isinstance(value, list):
        return [_drop_raw_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_drop_raw_data(item) for item in value)
    return value


def prepare_payload(
    payload: Any,
    destination: Any,
    labels_mode: str | None = None,
    *,
    database_url: str | None = None,
    entities: Iterable[tuple[str, str]] | None = None,
) -> PreparedPayload:
    """Build the model-bound payload for ``destination``.

    ``destination`` is any object with a ``trust`` attribute
    (``BackendConfig``: ``"onprem"`` or ``"cloud"``); anything else
    raises :class:`ValueError` instead of guessing. Masking always
    runs on the structured payload. ``cloud`` additionally drops
    every ``raw_data`` field (raw logs stay on-prem; replaced with
    nothing, never truncated or masked), runs the stable
    pseudonymizer (``database_url``, or ``DATABASE_URL`` when unset;
    missing raises instead of sending raw evidence to the cloud)
    and the secret redactor; ``onprem`` skips all three. ``entities``
    is the incident's typed entities as ``(kind, raw_value)`` pairs
    from all its events: they are registered before pseudonymizing
    so a name typed in one event is hidden in another event's free
    text (cloud only; ignored on-prem).
    """
    trust = getattr(destination, "trust", None)
    if trust not in ("onprem", "cloud"):
        raise ValueError(
            f"destination.trust must be 'onprem' or 'cloud', got {trust!r}"
        )
    mode = _resolve_labels_mode(labels_mode)
    dumped = payload.model_dump() if hasattr(payload, "model_dump") else payload
    if trust == "cloud":
        dumped = _drop_raw_data(dumped)
    masked = mask_payload(dumped)
    labeled = _apply_visible(masked) if mode == "visible" else _apply_blind(masked)
    if trust == "onprem":
        return PreparedPayload(payload=labeled, labels_mode=mode)
    from corvus.guardrails.pseudonymizer import Pseudonymizer

    dsn = database_url or os.environ.get("DATABASE_URL", "")
    if not dsn:
        raise ValueError(
            "refusing cloud payload without a pseudonym store: "
            "pass database_url or set DATABASE_URL"
        )
    pseudonymizer = Pseudonymizer(dsn)
    if entities is not None:
        pseudonymizer.register(entities)
    pseudonymized = pseudonymizer.pseudonymize(labeled)
    return PreparedPayload(payload=_redact_strings(pseudonymized), labels_mode=mode)
