"""Sigma-to-DuckDB translation for the Corvus replay detector.

Rules are converted with the pinned ``pySigma-backend-sqlite`` backend
(``sqliteBackend``), which implements Sigma matching semantics
(case-insensitive strings, wildcards, ``contains``/``startswith``/
``endswith``/``all``, ``re``, ``cidr``, ``windash``, ``base64offset``,
keyword search, field references, existence tests). The generated
SQLite is then translated to DuckDB, whose differences from SQLite are
exactly three:

- ``LIKE`` is case-sensitive in DuckDB (SQLite: insensitive), so the
  operator becomes ``ILIKE``. ``|cased`` rules emit ``GLOB``, which
  DuckDB also implements case-sensitively, so those pass through.
- ``field REGEXP 'pattern'`` becomes
  ``regexp_matches(field, 'pattern')``; each pattern is validated in
  DuckDB at rule load, and a rule whose pattern DuckDB rejects is
  skipped as an unsupported modifier.
- Literal ``=`` string equality stays as-is: the backend is run with
  ``collate_nocase=True``, which emits ``COLLATE NOCASE``, and DuckDB
  implements that collation.

One deliberate deviation from the backend defaults, required by
the detector contract:

- Keyword (fieldless) search needs ``fulltext_field`` set to the
  ``__fulltext`` column the engine populates with the raw record.

Null handling is the stock backend semantics, which equal Sigma's:
``null_safe_expression`` stays ``COALESCE({expr}, 0)``, so a field
absent from the event never matches a value and ``NOT`` over it is
true (the row is included). A field the mapper nulled from a
placeholder still carries the source-logged value in its row (see
``corvus/detect/mapping.py``), so ``NOT`` over it follows the logged
value.
"""

from __future__ import annotations

import re
from typing import ClassVar

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

__all__ = [
    "FULLTEXT_COLUMN",
    "StrictNullSQLiteBackend",
    "compile_rule_sql",
    "translate_sqlite_to_duckdb",
    "validate_regex_patterns",
]

#: The TEXT column every group populates with the raw record for
#: keyword (fieldless) searches. It is not a Sigma field: the
#: support check ignores it instead of routing rules to the skip
#: pile for it.
FULLTEXT_COLUMN = "__fulltext"


def validate_regex_patterns(sql: str) -> str | None:
    """Trial-compile every ``regexp_matches`` pattern in DuckDB.

    Returns the first pattern DuckDB rejects (Sigma ``|re`` is
    Python-flavored; DuckDB uses RE2, so constructs like lookahead or
    backreferences fail), or None when every pattern compiles. The
    check runs a constant-time ``SELECT`` per pattern, never against
    event data.
    """
    import duckdb

    connection = duckdb.connect()
    try:
        for pattern in _iter_regex_literals(sql):
            try:
                connection.execute(
                    "SELECT regexp_matches('', $re)", {"re": pattern}
                ).fetchall()
            except Exception:
                return pattern
    finally:
        connection.close()
    return None


def _iter_regex_literals(sql: str) -> list[str]:
    """Collect the pattern literals of ``regexp_matches(f, 'pat')``."""
    patterns: list[str] = []
    index = 0
    while True:
        found = sql.find("regexp_matches(", index)
        if found == -1:
            return patterns
        depth = 0
        cursor = found + len("regexp_matches(")
        # Skip the field argument (bare or "quoted") and the comma.
        in_string: str | None = None
        escape = False
        while cursor < len(sql):
            char = sql[cursor]
            if in_string is not None:
                if char == in_string and not escape:
                    if in_string == "'" and sql[cursor + 1 : cursor + 2] == "'":
                        cursor += 2
                        continue
                    in_string = None
                escape = char == "\\" and not escape
                cursor += 1
                continue
            if char in "\"'":
                in_string = char
                cursor += 1
                continue
            if char == "(":
                depth += 1
                cursor += 1
                continue
            if char == ")":
                if depth == 0:
                    break
                depth -= 1
                cursor += 1
                continue
            if char == "," and depth == 0:
                cursor += 1
                while cursor < len(sql) and sql[cursor] in " \t\n":
                    cursor += 1
                literal = _read_string_literal(sql, cursor)
                if literal is not None:
                    text, _ = literal
                    patterns.append(text[1:-1].replace("''", "'"))
                break
            cursor += 1
        index = cursor + 1


class StrictNullSQLiteBackend(sqliteBackend):
    """SQLite backend with strict null semantics (legacy, never default).

    ``null_safe_expression`` is the identity (``"{expr}"``), so a null
    field satisfies no condition, negated or not, and ``NOT`` over a
    missing field excludes the row. This was the detector's old
    behavior; it exists only so the report can measure the per-rule
    match delta between the old and the Sigma semantics. Production
    compilation uses the stock backend (see ``compile_rule_sql``).
    """

    null_safe_expression: ClassVar[str] = "{expr}"


def compile_rule_sql(rule: SigmaRule, *, strict_nulls: bool = False) -> str:
    """Convert one parsed Sigma rule to SQLite SQL (one query).

    The stock backend (Sigma ``NOT`` semantics) is used unless
    ``strict_nulls`` selects the legacy strict backend for the
    old-vs-new match delta. Raises the backend's errors (for example
    ``SigmaFeatureNotSupportedByBackendError`` for keyword search
    without a fulltext column) when the rule uses a construct the
    backend cannot convert; the caller counts those per rule.
    """
    cls = StrictNullSQLiteBackend if strict_nulls else sqliteBackend
    backend = cls(table="slice", collate_nocase=True, fulltext_field=FULLTEXT_COLUMN)
    queries = backend.convert(SigmaCollection([rule]))
    if len(queries) != 1:
        raise ValueError(
            f"rule {rule.id} converted to {len(queries)} queries, expected 1"
        )
    query = queries[0]
    assert isinstance(query, str)
    return query


def _replace_outside_literals(sql: str, old: str, new: str) -> str:
    """Replace ``old`` with ``new`` outside single-quoted literals.

    ``old`` must match on word boundaries (identifier characters on
    either side block the match), so a value containing the word does
    not get rewritten. Single quotes escape as ``''``.
    """
    out: list[str] = []
    index = 0
    size = len(sql)
    while index < size:
        char = sql[index]
        if char == "'":
            end = index + 1
            while end < size:
                if sql[end] == "'":
                    if end + 1 < size and sql[end + 1] == "'":
                        end += 2
                        continue
                    break
                end += 1
            out.append(sql[index : end + 1])
            index = end + 1
            continue
        if sql.startswith(old, index):
            before = sql[index - 1] if index > 0 else " "
            after = sql[index + len(old)] if index + len(old) < size else " "
            if not (before.isalnum() or before == "_") and not (
                after.isalnum() or after == "_"
            ):
                out.append(new)
                index += len(old)
                continue
        out.append(char)
        index += 1
    return "".join(out)


def _read_string_literal(sql: str, index: int) -> tuple[str, int] | None:
    """Read a ``'...'`` literal at ``index``; return (literal, end)."""
    if index >= len(sql) or sql[index] != "'":
        return None
    end = index + 1
    while end < len(sql):
        if sql[end] == "'":
            if end + 1 < len(sql) and sql[end + 1] == "'":
                end += 2
                continue
            return sql[index : end + 1], end + 1
        end += 1
    return None


def _rewrite_regexp(sql: str) -> str:
    """Rewrite ``field REGEXP 'pattern'`` to ``regexp_matches(...)``.

    Only operator positions (outside string literals) are rewritten;
    a value containing the text ``REGEXP`` is left alone.
    """
    out: list[str] = []
    index = 0
    size = len(sql)
    while index < size:
        char = sql[index]
        if char == "'":
            literal = _read_string_literal(sql, index)
            if literal is None:
                out.append(sql[index:])
                break
            text, index = literal
            out.append(text)
            continue
        if sql.startswith("REGEXP", index):
            before = sql[index - 1] if index > 0 else " "
            after = sql[index + 6] if index + 6 < size else " "
            if not (before.isalnum() or before == "_") and not (
                after.isalnum() or after == "_"
            ):
                field = "".join(out).rstrip()
                # The field is the trailing bare or "quoted" token.
                if field.endswith('"'):
                    start = field.rfind('"', 0, len(field) - 1)
                    token = field[start:] if start != -1 else field
                else:
                    end = len(field)
                    start = end
                    while start > 0 and (
                        field[start - 1].isalnum() or field[start - 1] in "_$"
                    ):
                        start -= 1
                    token = field[start:end]
                offset = index + 6
                while offset < size and sql[offset] in " \t\n":
                    offset += 1
                literal = _read_string_literal(sql, offset)
                if literal is not None and token:
                    pattern, index = literal
                    out = [field[: len(field) - len(token)]]
                    out.append(f"regexp_matches({token}, {pattern})")
                    continue
                out.append(char)
                index += 1
                continue
        out.append(char)
        index += 1
    return "".join(out)


def _drop_bool_numeric_branch(sql: str) -> str:
    """Drop the numeric half of the backend's boolean comparisons.

    The backend renders ``Initiated: true`` as
    ``Initiated='true' OR Initiated=1`` for stores that keep booleans
    as 0/1. Corvus stores TEXT (``'true'``/``'false'``), where the
    ``=1``/``=0`` half is never true and DuckDB aborts the query
    trying to cast ``'true'`` to an integer. The string half alone
    keeps SQLite semantics on text storage, so the numeric branch is
    removed. Only the exact ``'true'``/``'false'`` shape the backend
    emits is rewritten.
    """
    pattern = re.compile(r"([A-Za-z_][A-Za-z0-9_$]*)='(true|false)' OR \1=(0|1)")
    return pattern.sub(r"\1='\2'", sql)


def translate_sqlite_to_duckdb(sql: str) -> str:
    """Translate backend SQLite SQL to DuckDB SQL.

    ``LIKE`` becomes ``ILIKE`` (DuckDB ``LIKE`` is case-sensitive,
    SQLite ``LIKE`` is not); ``COLLATE NOCASE`` passes through
    because DuckDB implements it. ``REGEXP`` becomes
    ``regexp_matches``. ``GLOB`` (``|cased``) keeps its operator but
    lone backslashes inside the pattern double: SQLite ``GLOB`` reads
    a backslash literally while DuckDB ``GLOB`` treats it as an
    escape, so ``\\`` is what matches one backslash there (verified
    against DuckDB directly; ``*``, ``?`` and ``[...]`` behave the
    same in both). Rewrites apply outside string literals only.
    """
    translated = _replace_outside_literals(_rewrite_regexp(sql), "LIKE", "ILIKE")
    translated = _escape_glob(translated)
    return _drop_bool_numeric_branch(translated)


def _escape_glob(sql: str) -> str:
    """Double lone backslashes in ``GLOB '...'`` pattern literals.

    Only the pattern literal following a ``GLOB`` keyword (outside
    string literals) is touched, and only outside ``[...]`` classes,
    whose contents pass through byte-identical. An already-doubled
    ``\\\\`` pair stays a pair.
    """
    out: list[str] = []
    index = 0
    size = len(sql)
    while index < size:
        char = sql[index]
        if char == "'":
            literal = _read_string_literal(sql, index)
            if literal is None:
                out.append(sql[index:])
                break
            text, index = literal
            out.append(text)
            continue
        if sql.startswith("GLOB", index):
            before = sql[index - 1] if index > 0 else " "
            after = sql[index + 4] if index + 4 < size else " "
            if not (before.isalnum() or before == "_") and not (
                after.isalnum() or after == "_"
            ):
                start = index
                offset = index + 4
                while offset < size and sql[offset] in " \t\n":
                    offset += 1
                literal = _read_string_literal(sql, offset)
                if literal is not None:
                    text, index = literal
                    # Keep the "GLOB" keyword and the gap before the
                    # pattern, then the pattern with doubled slashes.
                    out.append(sql[start:offset])
                    out.append(_double_glob_backslashes(text))
                    continue
        out.append(char)
        index += 1
    return "".join(out)


def _double_glob_backslashes(literal: str) -> str:
    """Double lone backslashes in a quoted GLOB pattern literal."""
    body = literal[1:-1]
    out: list[str] = []
    index = 0
    in_class = False
    while index < len(body):
        char = body[index]
        if char == "'" and body[index + 1 : index + 2] == "'":
            out.append("''")
            index += 2
            continue
        if char == "[":
            in_class = True
            out.append(char)
            index += 1
            continue
        if char == "]":
            in_class = False
            out.append(char)
            index += 1
            continue
        if char == "\\" and not in_class:
            if body[index + 1 : index + 2] == "\\":
                out.append("\\\\")
                index += 2
            else:
                out.append("\\\\")
                index += 1
            continue
        out.append(char)
        index += 1
    return "'" + "".join(out) + "'"
