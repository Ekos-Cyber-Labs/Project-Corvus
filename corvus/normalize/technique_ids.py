"""ATT&CK technique references inside evidence text.

Some real attack evidence names its own technique: Atomic Red Team paths
like ``C:\\AtomicRedTeam\\atomics\\T1218.005\\...`` in a command line, or
a sysmon-modular ``RuleName`` such as
``technique_id=T1003,technique_name=Credential Dumping``. That evidence
stays verbatim in the OCSF record; these helpers only find and mask the
references. The model-call layer applies :func:`mask_technique_ids` to
every model-bound payload (the loader only records whether an event
carries one).
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "TECHNIQUE_ID_MASK",
    "TECHNIQUE_NAME_MASK",
    "find_technique_ids",
    "has_in_band_technique_id",
    "mask_payload",
    "mask_technique_ids",
]

#: Replacement text for one technique-id token.
TECHNIQUE_ID_MASK = "[TECHNIQUE-ID]"

#: Replacement text for one technique-name value.
TECHNIQUE_NAME_MASK = "[TECHNIQUE-NAME]"

#: One ATT&CK id token: ``T`` + 4 digits with an optional ``.###``
#: sub-technique, matched only when not glued to letters or digits
#: (so ``XT1234``, ``T12345`` and GUIDs never match). ``re.ASCII`` keeps
#: ``\\d`` to ASCII digits only.
_TECHNIQUE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![A-Za-z0-9])",
    re.IGNORECASE | re.ASCII,
)

#: A ``technique_name=`` tag value: everything up to the next comma,
#: semicolon, double quote, backslash, line break or end of string. The
#: backslash also stops the value: in serialized JSON the value ends in
#: an escaped quote (``...Masquerading\"``), and swallowing its backslash
#: would leave a stray escape that breaks parsing; likewise a literal
#: ``\r\n`` escape must not let the value eat the following fields. The
#: key and the delimiter survive masking byte-identical; only the value
#: is replaced.
_TECHNIQUE_NAME_VALUE = re.compile(
    r"(technique_name=)[^,;\"\\\r\n]*",
    re.IGNORECASE | re.ASCII,
)

#: Bare ``technique_name=`` tag presence (a tag without an id still marks
#: the evidence as naming its own technique).
_TECHNIQUE_NAME_TAG = re.compile(
    r"technique_name=",
    re.IGNORECASE | re.ASCII,
)


def find_technique_ids(text: str) -> list[str]:
    """Return the ATT&CK id tokens in ``text``, uppercased, in order found."""
    return [match.group(0).upper() for match in _TECHNIQUE_TOKEN.finditer(text)]


def mask_technique_ids(text: str) -> str:
    """Mask ATT&CK references in ``text``: ids, then technique-name values.

    Id tokens become ``[TECHNIQUE-ID]``; every ``technique_name=`` value
    becomes ``[TECHNIQUE-NAME]``. Everything else stays byte-identical:
    keys, delimiters and surrounding text never change. The name value
    also stops at a backslash so masked serialized JSON still parses,
    but prefer :func:`mask_payload` for structured data.
    """
    masked = _TECHNIQUE_TOKEN.sub(TECHNIQUE_ID_MASK, text)
    return _TECHNIQUE_NAME_VALUE.sub(r"\1" + TECHNIQUE_NAME_MASK, masked)


def mask_payload(value: Any) -> Any:
    """Mask technique references in each string leaf of a payload.

    Walks dicts, lists and tuples; mapping keys are untouched and
    non-string leaves are returned as is, so masking structured data can
    never break its serialization. The model-call layer uses this on
    structured payloads instead of masking their serialized text.
    """
    if isinstance(value, str):
        return mask_technique_ids(value)
    if isinstance(value, dict):
        return {key: mask_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [mask_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(mask_payload(item) for item in value)
    return value


def _walk(value: Any) -> bool:
    """Return True when any string leaf under ``value`` names a technique."""
    if isinstance(value, str):
        return (
            _TECHNIQUE_TOKEN.search(value) is not None
            or _TECHNIQUE_NAME_TAG.search(value) is not None
        )
    if isinstance(value, dict):
        return any(_walk(item) for item in value.values())
    if isinstance(value, list | tuple):
        return any(_walk(item) for item in value)
    return False


def has_in_band_technique_id(event: object) -> bool:
    """Return True when any string field of an OCSF event names a technique.

    Fires on an id token or on a ``technique_name=`` tag on its own.
    Takes the dumped event (any object with ``model_dump``, or a plain
    mapping) so the loader stays decoupled from the OCSF model imports.
    """
    dumped = event.model_dump() if hasattr(event, "model_dump") else event  # type: ignore[union-attr]
    return _walk(dumped)
