"""Sigma rule loading, support analysis and compilation.

A rule file becomes a :class:`CompiledRule` when every step succeeds;
otherwise it lands in exactly one skip bucket, counted with the
reason (and the offending logsource, field, or construct):

- ``status``: status is not ``test`` or ``stable`` (experimental,
  deprecated and unsupported are counted and skipped).
- ``logsource``: the logsource triple has no OCSF mapping.
- ``event_id``: a service rule whose ``EventID`` selection lies fully
  outside the mapped EventIDs for that service.
- ``unmapped_field``: the rule uses a field with no extractor on its
  group (never evaluated against null).
- ``unsupported_construct``: conversion fails (unsupported modifier,
  unresolvable placeholder, multi-query shape, or a regex DuckDB
  rejects).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from corvus.detect.backend import (
    FULLTEXT_COLUMN,
    compile_rule_sql,
    translate_sqlite_to_duckdb,
    validate_regex_patterns,
)
from corvus.detect.mapping import (
    GROUPS,
    MAPPED_SERVICE_EVENT_IDS,
    route_logsource,
)

__all__ = [
    "CompiledRule",
    "LoadStats",
    "compile_loaded",
    "event_id_selection",
    "iter_rule_files",
    "load_rules",
    "required_field_names",
]

#: Rule statuses evaluated by the detector; everything else is
#: counted under the ``status`` skip reason.
EVALUATED_STATUSES = frozenset({"test", "stable"})

#: Skip reasons, in the order they are checked (first hit wins).
REASON_STATUS = "status"
REASON_LOGSOURCE = "logsource"
REASON_EVENT_ID = "event_id"
REASON_FIELD = "unmapped_field"
REASON_CONSTRUCT = "unsupported_construct"


@dataclass
class CompiledRule:
    """One evaluable Sigma rule with its DuckDB SQL and provenance."""

    rule_id: str
    title: str
    description: str | None
    author: str | None
    level: str
    tags: list[tuple[str, str]]
    references: list[str]
    group: str
    sql: str
    source_file: str
    rel_path: str = ""


@dataclass
class LoadStats:
    """Counts for one rule-load run (reported, never event content)."""

    files: int = 0
    parsed_rules: int = 0
    evaluated: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    skip_details: dict[str, dict[str, int]] = field(default_factory=dict)

    def skip(self, reason: str, detail: str) -> None:
        """Count one skipped rule under ``reason`` with ``detail``."""
        self.skipped[reason] = self.skipped.get(reason, 0) + 1
        bucket = self.skip_details.setdefault(reason, {})
        bucket[detail] = bucket.get(detail, 0) + 1


def iter_rule_files(rules_dir: str | Path) -> list[Path]:
    """Return the sorted ``.yml`` rule files under ``rules_dir``.

    Raises when ``rules_dir`` is missing or holds no rules: an empty
    rule set would silently report zeros.
    """
    root = Path(rules_dir)
    if not root.is_dir():
        raise ValueError(f"rules directory missing: {rules_dir}")
    files = sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml"))
    files = sorted(set(files))
    if not files:
        raise ValueError(f"no .yml rules under {rules_dir}")
    return files


def event_id_selection(rule: SigmaRule) -> set[int]:
    """Return the rule's ``EventID`` equality values (possibly empty).

    Walks every detection item; only plain equality values count (a
    CIDR, regex, or comparison on ``EventID`` is not a routable
    selection and yields nothing, leaving the full slice in scope).
    """
    from sigma.rule import SigmaDetection, SigmaDetectionItem

    found: set[int] = set()

    def walk(node: SigmaDetection | SigmaDetectionItem) -> None:
        if isinstance(node, SigmaDetectionItem):
            if node.field == "EventID":
                values = node.value if isinstance(node.value, list) else [node.value]
                for value in values:
                    number = getattr(value, "number", None)
                    if isinstance(number, int) and not isinstance(number, bool):
                        found.add(number)
            return
        for item in node.detection_items:
            walk(item)

    for detection in rule.detection.detections.values():
        walk(detection)
    return found


def required_field_names(rule: SigmaRule) -> set[str]:
    """Return every field name the rule's condition touches.

    Uses the backend's own analysis over the parsed condition, so
    only selections the condition actually uses count (a field in a
    dead selection does not disqualify the rule). Keyword (fieldless)
    items contribute nothing; they match the ``__fulltext`` column,
    which every group populates. ``EventID`` stays in the set: groups
    without an ``EventID`` extractor reject the rule through the same
    path. Raises ``SigmaConditionError`` for legacy pipe conditions.
    """
    backend = sqliteBackend(
        table="slice", collate_nocase=True, fulltext_field="__fulltext"
    )
    return set(backend.required_fields(rule))


def _rule_level(rule: SigmaRule) -> str | None:
    level = rule.level
    if level is None:
        return None
    name = str(level).lower()
    return (
        name if name in ("informational", "low", "medium", "high", "critical") else None
    )


def load_rules(
    rules_dir: str | Path, *, validate_regex: bool = True, strict_nulls: bool = False
) -> tuple[list[CompiledRule], LoadStats]:
    """Load, route, analyze and compile every rule under ``rules_dir``.

    Returns the compiled rules plus counts (rules loaded, evaluated,
    and skipped by reason with the top offenders). With
    ``validate_regex`` each ``|re`` pattern is trial-compiled in
    DuckDB and the rule is skipped as an unsupported construct when
    DuckDB rejects it. ``strict_nulls`` selects the legacy strict
    backend (measurement only, for the old-vs-new match delta).
    """
    compiled: list[CompiledRule] = []
    stats = LoadStats()
    root = Path(rules_dir)
    for path in iter_rule_files(root):
        stats.files += 1
        try:
            collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        except Exception as exc:
            stats.skip(REASON_CONSTRUCT, f"parse error: {type(exc).__name__}")
            continue
        for rule in collection.rules:
            stats.parsed_rules += 1
            if isinstance(rule, SigmaCorrelationRule):
                stats.skip(REASON_CONSTRUCT, "correlation rule")
                continue
            item = _analyze(rule, path, stats)
            if item is None:
                continue
            try:
                item.rel_path = str(path.relative_to(root))
            except ValueError:
                item.rel_path = path.name
            try:
                sqlite_sql = compile_rule_sql(rule, strict_nulls=strict_nulls)
                item.sql = translate_sqlite_to_duckdb(sqlite_sql)
            except Exception as exc:
                stats.skip(REASON_CONSTRUCT, f"{type(exc).__name__}")
                continue
            if validate_regex:
                bad = validate_regex_patterns(item.sql)
                if bad is not None:
                    stats.skip(REASON_CONSTRUCT, f"regexp rejected: {bad[:60]}")
                    continue
            compiled.append(item)
    stats.evaluated = len(compiled)
    return compiled, stats


def _analyze(rule: SigmaRule, path: Path, stats: LoadStats) -> CompiledRule | None:
    """Route and field-check one rule; None when it is skipped."""
    if str(rule.status) not in EVALUATED_STATUSES:
        stats.skip(REASON_STATUS, str(rule.status))
        return None
    logsource = rule.logsource
    group_name = route_logsource(
        logsource.product, logsource.category, logsource.service
    )
    if group_name is None or group_name not in GROUPS:
        stats.skip(
            REASON_LOGSOURCE,
            f"product={logsource.product} "
            f"category={logsource.category} service={logsource.service}",
        )
        return None
    group = GROUPS[group_name]
    if group_name in MAPPED_SERVICE_EVENT_IDS:
        selected = event_id_selection(rule)
        mapped = MAPPED_SERVICE_EVENT_IDS[group_name]
        if selected and not (selected & set(mapped)):
            stats.skip(
                REASON_EVENT_ID,
                f"{group_name} EventID={sorted(selected)}",
            )
            return None
    try:
        required = required_field_names(rule)
    except Exception as exc:
        stats.skip(REASON_CONSTRUCT, f"{type(exc).__name__}")
        return None
    # The fulltext column backs keyword search on every group; it is
    # not a Sigma field and never disqualifies a rule.
    required.discard(FULLTEXT_COLUMN)
    missing = sorted(name for name in required if name not in group.fields)
    if missing:
        stats.skip(REASON_FIELD, f"{group_name} {missing[0]}")
        return None
    level = _rule_level(rule)
    if level is None:
        stats.skip(REASON_CONSTRUCT, f"unknown level: {rule.level}")
        return None
    tags = [(str(tag.namespace), str(tag.name)) for tag in rule.tags or []]
    return CompiledRule(
        rule_id=str(rule.id),
        title=rule.title or "",
        description=rule.description,
        author=rule.author,
        level=level,
        tags=tags,
        references=[str(reference) for reference in rule.references or []],
        group=group_name,
        sql="",
        source_file=str(path),
    )


def compile_loaded(rule: SigmaRule) -> str:
    """Compile one parsed rule to DuckDB SQL (test helper)."""
    return translate_sqlite_to_duckdb(compile_rule_sql(rule))
