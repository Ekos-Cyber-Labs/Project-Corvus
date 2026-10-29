"""OCSF conformance check for emitted records (test-facing but importable).

Loads the pinned schema files from ``data/ocsf-schema`` (fetched with
``python3 scripts/fetch_datasets.py``) and resolves an event class or
object the way the schema defines it: ``extends`` chains from the event
or object file through its category/base files, ``$include`` of profile
files at every level, extension classes and objects from
``extensions/windows`` (overlaid when the record declares the ``win``
extension), and attribute types from ``dictionary.json`` (core) plus
``extensions/windows/dictionary.json`` (win).

Every emitted OCSF record must pass :func:`check_record`: each
attribute its resolved class or object marks ``requirement``/``required``
is present and non-null at every nesting level, every attribute name
exists in the resolved class or object (``unmapped`` and ``raw_data``
count as the schema defines them; profile attributes count only when
the record declares the profile in ``metadata.profiles``), every
``*_id`` attribute holding an enum value is listed there (``99`` Other
counts when the schema lists it), and ``string_t`` versus integer
values match their declared type.
"""

from __future__ import annotations

import glob
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

__all__ = [
    "ConformanceError",
    "SCHEMA_FILES",
    "check_record",
    "load_schema",
    "resolve_class",
    "resolve_object",
    "schema_dir",
]

#: Repo root (this file lives at ``corvus/normalize/conformance.py``).
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def schema_dir() -> Path:
    """Return the pinned schema directory under git-ignored ``data/``."""
    return REPO_ROOT / "data" / "ocsf-schema"


#: Schema files the check needs (only this subset is fetched).
SCHEMA_FILES = (
    "categories.json",
    "dictionary.json",
    "LICENSE",
    "events/",
    "objects/",
    "profiles/",
    "extensions/windows/",
)

_FETCH_HINT = "python3 scripts/fetch_datasets.py"


class ConformanceError(Exception):
    """One OCSF conformance violation (message names class and path)."""


def _display(path: Path) -> str:
    """Render a schema path, relative to the repo when inside it."""
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def _need(path: Path, what: str) -> dict[str, Any]:
    """Load a schema JSON file, failing with the fetch command when absent."""
    if not path.is_file():
        raise ConformanceError(
            f"missing pinned OCSF schema file {_display(path)}; "
            f"fetch it with {_FETCH_HINT} (never skip this check)"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ConformanceError(f"unparseable schema file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConformanceError(f"schema file {path} is not a JSON object")
    return data


class _Schema:
    """Loaded schema indexes (one instance per schema directory)."""

    def __init__(self, root: Path) -> None:
        if not root.is_dir():
            raise ConformanceError(
                f"missing pinned OCSF schema directory {_display(root)}; "
                f"fetch it with {_FETCH_HINT} (never skip this check)"
            )
        self.root = root
        core_dict = _need(root / "dictionary.json", "dictionary")
        win_dict = _need(
            root / "extensions" / "windows" / "dictionary.json", "win dictionary"
        )
        self.attributes: dict[str, dict[str, Any]] = {}
        self.attributes.update(_as_dict(core_dict.get("attributes")))
        self.attributes.update(_as_dict(win_dict.get("attributes")))
        self.types: dict[str, dict[str, Any]] = _as_dict(
            core_dict.get("types", {}).get("attributes")
            if isinstance(core_dict.get("types"), dict)
            else {}
        )
        win_types = win_dict.get("types", {})
        if isinstance(win_types, dict):
            self.types.update(_as_dict(win_types.get("attributes")))
        self.events_by_uid: dict[int, Path] = {}
        self.events_by_name: dict[str, Path] = {}
        categories = _as_dict(
            _need(root / "categories.json", "categories").get("attributes")
        )
        self.category_uids: dict[str, int] = {}
        for name, entry in categories.items():
            if not isinstance(entry, dict):
                continue
            uid = entry.get("uid")
            if isinstance(uid, int) and not isinstance(uid, bool):
                self.category_uids[name] = uid
        for path in glob.glob(str(root / "events" / "**" / "*.json"), recursive=True):
            self._index_event(Path(path), extension=0)
        win_events = root / "extensions" / "windows" / "events"
        for path in glob.glob(str(win_events / "*.json")):
            self._index_event(Path(path), extension=200000)
        # Object identity is the ``name`` field inside the file, not the
        # file stem (``registry_key.json`` names the ``reg_key`` object).
        self.objects: dict[str, Path] = {}
        self.objects_by_stem: dict[str, list[Path]] = {}
        for path in glob.glob(str(root / "objects" / "*.json")):
            self.objects.setdefault(_object_name(Path(path)), Path(path))
            self.objects_by_stem.setdefault(Path(path).stem, []).append(Path(path))
        win_objects = root / "extensions" / "windows" / "objects"
        for path in glob.glob(str(win_objects / "*.json")):
            name = _object_name(Path(path))
            self.objects.setdefault("win:" + name, Path(path))
            # Win-only objects (reg_key, reg_value, win_service) are also
            # addressable by bare name; core names always win.
            self.objects.setdefault(name, Path(path))

    def _index_event(self, path: Path, extension: int) -> None:
        # Class ids compose as category_uid * 1000 + uid (core) with a
        # 200000 block for extension classes: 1*1000+7 is 1007 Process
        # Activity, 2*1000+4 is 2004 Detection Finding, and 200000+1*1000+1
        # is 201001 Registry Key Activity. Verified against all eleven
        # classes Corvus emits.
        data = _need(path, "event")
        uid = data.get("uid")
        if isinstance(uid, int) and not isinstance(uid, bool):
            category = self._category_of(path)
            if category is not None:
                full = extension + category * 1000 + uid
                if full in self.events_by_uid:
                    raise ConformanceError(
                        f"duplicate class_uid {full}: {path} and "
                        f"{self.events_by_uid[full]}"
                    )
                self.events_by_uid[full] = path
        name = data.get("name")
        if isinstance(name, str):
            self.events_by_name.setdefault(name, path)

    def _category_of(self, path: Path) -> int | None:
        """Walk ``extends`` up to the file carrying ``category``."""
        seen: set[str] = set()
        current: Path | None = path
        while current is not None:
            key = _display(current)
            if key in seen:
                return None
            seen.add(key)
            data = _need(current, "event")
            category = data.get("category")
            if isinstance(category, str) and category in self.category_uids:
                return self.category_uids[category]
            parent = data.get("extends")
            if not isinstance(parent, str) or not parent:
                return None
            matches = glob.glob(
                str(self.root / "events" / "**" / f"{parent}.json"), recursive=True
            ) + glob.glob(
                str(self.root / "extensions" / "windows" / "events" / f"{parent}.json")
            )
            if len(matches) != 1:
                return None
            current = Path(matches[0])
        return None


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _object_name(path: Path) -> str:
    """Return an object file's identity: its ``name`` field, else its stem."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        return path.stem
    name = data.get("name") if isinstance(data, dict) else None
    return name if isinstance(name, str) and name else path.stem


#: Attributes defined only through one of these includes count solely
#: when the record declares the profile. Profiles are referenced as
#: ``profiles/<name>.json``.
def _profile_of(include: str) -> str | None:
    if include.startswith("profiles/") and include.endswith(".json"):
        middle = include[len("profiles/") : -len(".json")]
        if middle and "/" not in middle:
            return middle
    return None


@lru_cache(maxsize=1)
def load_schema() -> _Schema:
    """Load (and cache) the pinned schema; fails when files are missing."""
    return _Schema(schema_dir())


def _merge_into(
    merged: dict[str, dict[str, Any]],
    sources: dict[str, str | None],
    data: dict[str, Any],
    schema: _Schema,
    from_profile: str | None = None,
) -> None:
    """Merge one file's attributes, resolving its ``$include`` first.

    ``sources`` tracks per-attribute provenance: the profile name when
    the definition came solely from a ``profiles/`` include, else None.
    Definitions written directly in a class, category, base or object
    file clear the marker — that explicit declaration is what makes
    attributes such as ``actor``/``device`` unconditional while
    ``cloud``/``osint`` stay profile-gated.
    """
    for include in data.get("attributes", {}).get("$include", []) or []:
        if not isinstance(include, str):
            continue
        profile = _profile_of(include) or from_profile
        _merge_into(
            merged, sources, _need(schema.root / include, "include"), schema, profile
        )
    for name, entry in _as_dict(data.get("attributes")).items():
        if name == "$include" or not isinstance(entry, dict):
            continue
        merged.setdefault(name, {}).update(entry)
        if from_profile is None:
            sources[name] = None
        else:
            sources.setdefault(name, from_profile)


def _chain_files(schema: _Schema, start: Path) -> list[dict[str, Any]]:
    """Return the ``extends`` chain files, base first, starting file last."""
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    current: Path | None = start
    while current is not None:
        key = current.relative_to(schema.root).as_posix()
        if key in seen:
            raise ConformanceError(f"circular extends chain at {key}")
        seen.add(key)
        data = _need(current, "event")
        files.append(data)
        parent = data.get("extends")
        if not isinstance(parent, str) or not parent:
            current = None
        elif parent not in schema.events_by_name:
            raise ConformanceError(
                f"extends target {parent!r} of {key} is not in the pinned schema"
            )
        else:
            current = schema.events_by_name[parent]
    files.reverse()
    return files


def _resolve_files(
    schema: _Schema, files: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], dict[str, str | None]]:
    """Merge chain files into (attributes, profile-source) maps."""
    merged: dict[str, dict[str, Any]] = {}
    sources: dict[str, str | None] = {}
    for data in files:
        _merge_into(merged, sources, data, schema)
    return merged, sources


def resolve_class(schema: _Schema, class_uid: int) -> dict[str, dict[str, Any]]:
    """Resolve a class uid to its merged attribute definitions."""
    if class_uid not in schema.events_by_uid:
        raise ConformanceError(f"unknown class_uid {class_uid}")
    files = _chain_files(schema, schema.events_by_uid[class_uid])
    merged, _ = _resolve_files(schema, files)
    return merged


def _resolve_object_files(
    schema: _Schema, type_name: str, extensions: tuple[str, ...]
) -> tuple[dict[str, dict[str, Any]], dict[str, str | None]]:
    """Resolve an object type to (attributes, profile-source) maps."""
    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    current: str | None = type_name
    while current is not None:
        if current in seen:
            raise ConformanceError(f"circular object extends at {current!r}")
        seen.add(current)
        data = _need(_lookup_object(schema, current), "object")
        chain.append(data)
        parent = data.get("extends")
        current = parent if isinstance(parent, str) and parent else None
    merged: dict[str, dict[str, Any]] = {}
    sources: dict[str, str | None] = {}
    for data in reversed(chain):
        _merge_into(merged, sources, data, schema)
    for extension in extensions:
        overlay = f"{extension}:{type_name}"
        if overlay in schema.objects:
            _merge_into(
                merged, sources, _need(schema.objects[overlay], "object"), schema
            )
    return merged, sources


def _lookup_object(schema: _Schema, name: str) -> Path:
    if name in schema.objects:
        return schema.objects[name]
    stem_matches = schema.objects_by_stem.get(name, [])
    if len(stem_matches) == 1:
        return stem_matches[0]
    raise ConformanceError(f"unknown object type {name!r}")


def resolve_object(
    schema: _Schema, type_name: str, extensions: tuple[str, ...] = ()
) -> dict[str, dict[str, Any]]:
    """Resolve an object type to its merged attributes (extends + includes).

    Extension overlays (``win:<name>``) apply when the record declares
    that extension in ``metadata.extensions``.
    """
    merged, _ = _resolve_object_files(schema, type_name, extensions)
    return merged


def _type_of(
    schema: _Schema, entry: dict[str, Any], name: str
) -> tuple[str | None, bool]:
    """Return ``(type name, is_array)`` for an attribute definition."""
    direct = entry.get("type")
    type_name = direct if isinstance(direct, str) else None
    is_array = entry.get("is_array")
    if type_name is None:
        fallback = schema.attributes.get(name, {})
        raw = fallback.get("type")
        type_name = raw if isinstance(raw, str) else None
        if is_array is None:
            is_array = fallback.get("is_array")
    return type_name, bool(is_array)


def _kind(schema: _Schema, type_name: str | None) -> str:
    """Classify a types-table type as int, float, bool, or str."""
    current: str | None = type_name
    seen: set[str] = set()
    while (
        current is not None
        and current in schema.types
        and isinstance(schema.types[current].get("type"), str)
        and current not in seen
    ):
        seen.add(current)
        raw = schema.types[current]["type"]
        current = raw if isinstance(raw, str) else None
    if current in ("integer_t", "long_t", "timestamp_t", "port_t"):
        return "int"
    if current == "float_t":
        return "float"
    if current == "boolean_t":
        return "bool"
    return "str"


def _enums(schema: _Schema, entry: dict[str, Any], name: str) -> set[int] | None:
    """Union the listed enum ids from the entry and the dictionaries."""
    values: set[int] = set()
    found = False
    for source in (entry.get("enum"), schema.attributes.get(name, {}).get("enum")):
        if not isinstance(source, dict):
            continue
        found = True
        for key in source:
            try:
                number = int(str(key))
            except ValueError:
                continue
            if isinstance(number, bool):
                continue
            values.add(number)
    return values if found else None


def _declared_profiles(record: dict[str, Any]) -> set[str]:
    metadata = record.get("metadata")
    profiles = metadata.get("profiles") if isinstance(metadata, dict) else None
    if not isinstance(profiles, list):
        return set()
    return {str(item) for item in profiles}


def _declared_extensions(record: dict[str, Any]) -> tuple[str, ...]:
    metadata = record.get("metadata")
    entries = metadata.get("extensions") if isinstance(metadata, dict) else None
    if not isinstance(entries, list):
        return ()
    names = []
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            names.append(entry["name"])
    return tuple(names)


def _gate(
    resolved: tuple[dict[str, dict[str, Any]], dict[str, str | None]],
    profiles: set[str],
) -> dict[str, dict[str, Any]]:
    """Drop profile attributes the record does not declare (they do not count).

    Both the entry's own ``profile`` tag and its ``$include`` provenance
    gate it: an attribute defined only through a profile include counts
    solely when the record declares that profile in
    ``metadata.profiles``.
    """
    attributes, sources = resolved
    gated = {}
    for name, entry in attributes.items():
        profile = entry.get("profile")
        if isinstance(profile, str) and profile and profile not in profiles:
            continue
        source = sources.get(name)
        if isinstance(source, str) and source and source not in profiles:
            continue
        gated[name] = entry
    return gated


def check_record(record: dict[str, Any]) -> list[str]:
    """Check one serialized OCSF record; return the violation messages."""
    return _check_event(load_schema(), record, "event")


def _check_event(schema: _Schema, record: dict[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    class_uid = record.get("class_uid")
    if not isinstance(class_uid, int) or isinstance(class_uid, bool):
        return [f"{path}: class_uid is missing or not an integer"]
    if class_uid not in schema.events_by_uid:
        return [f"{path}: unknown class_uid {class_uid}"]
    try:
        files = _chain_files(schema, schema.events_by_uid[class_uid])
        resolved = _gate(_resolve_files(schema, files), _declared_profiles(record))
    except ConformanceError as exc:
        return [f"{path}: {exc}"]
    extensions = _declared_extensions(record)
    for name, entry in resolved.items():
        if entry.get("requirement") == "required" and record.get(name) is None:
            errors.append(
                f"{path}.{name}: required attribute of class {class_uid} "
                f"is missing or null"
            )
    for name, value in record.items():
        attr = resolved.get(name)
        if attr is None:
            errors.append(
                f"{path}.{name}: unknown attribute for class {class_uid} "
                f"(not in the pinned schema)"
            )
            continue
        if value is None:
            continue
        errors.extend(_check_value(schema, attr, name, value, extensions, record))
    return errors


def _check_object(
    schema: _Schema,
    type_name: str,
    value: dict[str, Any],
    extensions: tuple[str, ...],
    record: dict[str, Any],
    path: str,
) -> list[str]:
    errors: list[str] = []
    try:
        resolved = _gate(
            _resolve_object_files(schema, type_name, extensions),
            _declared_profiles(record),
        )
    except ConformanceError as exc:
        return [f"{path}: {exc}"]
    for name, entry in resolved.items():
        if entry.get("requirement") == "required" and value.get(name) is None:
            errors.append(
                f"{path}.{name}: required attribute of {type_name} is missing"
            )
    for name, item in value.items():
        attr = resolved.get(name)
        if attr is None:
            errors.append(f"{path}.{name}: unknown attribute for {type_name}")
            continue
        if item is None:
            continue
        errors.extend(_check_value(schema, attr, name, item, extensions, record, path))
    return errors


def _check_value(
    schema: _Schema,
    entry: dict[str, Any],
    name: str,
    value: Any,
    extensions: tuple[str, ...],
    record: dict[str, Any],
    path: str = "event",
) -> list[str]:
    type_name, is_array = _type_of(schema, entry, name)
    if is_array:
        if not isinstance(value, list):
            return [f"{path}.{name}: expected an array"]
        errors: list[str] = []
        for index, item in enumerate(value):
            if item is None:
                continue
            errors.extend(
                _check_single(
                    schema,
                    entry,
                    type_name,
                    name,
                    item,
                    extensions,
                    record,
                    f"{path}.{name}[{index}]",
                )
            )
        return errors
    return _check_single(
        schema, entry, type_name, name, value, extensions, record, f"{path}.{name}"
    )


def _check_single(
    schema: _Schema,
    entry: dict[str, Any],
    type_name: str | None,
    name: str,
    value: Any,
    extensions: tuple[str, ...],
    record: dict[str, Any],
    where: str,
) -> list[str]:
    if type_name == "object":
        kind = "freeform"
    elif type_name in ("json_t", "long_string", None):
        # json_t holds arbitrary JSON; long_string is long free text
        # (used by script_content) with no entry in the types table.
        kind = "any" if type_name == "json_t" else "str"
    elif type_name in schema.types:
        kind = _kind(schema, type_name)
    elif type_name in schema.objects:
        if isinstance(value, dict):
            return _check_object(schema, type_name, value, extensions, record, where)
        return [f"{where}: expected object {type_name}, got {type(value).__name__}"]
    else:
        return [f"{where}: unknown type {type_name!r} for this attribute"]
    if kind == "str" and type_name in schema.objects:
        if isinstance(value, dict):
            return _check_object(schema, type_name, value, extensions, record, where)
        return [f"{where}: expected object {type_name}, got {type(value).__name__}"]
    if kind == "any":
        return []
    if kind == "freeform":
        if not isinstance(value, dict):
            return [f"{where}: expected an object map"]
        return []
    if kind == "int":
        if not isinstance(value, int) or isinstance(value, bool):
            return [f"{where}: expected an integer, got {type(value).__name__}"]
    elif kind == "float":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return [f"{where}: expected a number, got {type(value).__name__}"]
    elif kind == "bool":
        if not isinstance(value, bool):
            return [f"{where}: expected a boolean, got {type(value).__name__}"]
    else:
        if not isinstance(value, str):
            return [f"{where}: expected a string, got {type(value).__name__}"]
    if name.endswith("_id") and not isinstance(value, bool):
        allowed = _enums(schema, entry, name)
        if allowed is not None and value not in allowed:
            ordered = sorted(allowed)
            return [
                f"{where}: {value!r} is not a listed {name} enum value "
                f"(schema lists {ordered})"
            ]
    return []
