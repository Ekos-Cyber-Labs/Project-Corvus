"""Stable pseudonyms for model-bound payloads.

The same entity always maps to the same pseudonym within a deployment,
so chains stay correlatable after pseudonymization. Mappings live in
the ``pseudonyms`` table (migration ``0002_core_tables.sql``); the real
values never leave the deployment and a pseudonym is never derived
from its value (no hashing, no reversible encoding) — each kind has
its own counter in Postgres (``HOST-0001``, ``USER-0001``,
``IP-0001``, ``DOMAIN-0001``, ``EMAIL-0001``), allocated inside a
short transaction under an advisory lock, never from process memory.

Kinds: ``host``, ``user``, ``ip``, ``domain``, ``email``.

Canonicalization before lookup (so ``web01`` and
``WEB01.example.com`` resolve the way the adapters already treat
them):

- host: :func:`corvus.normalize.ocsf.canonicalize_host`
- user: :func:`corvus.normalize.ocsf.canonicalize_user`
- ip: :func:`corvus.normalize.ocsf.canonicalize_ip`
- domain: lowercased, one trailing dot removed
- email: lowercased whole address (must hold one ``@`` with non-empty
  sides and no spaces)

Placeholders and empty values (anything canonicalization maps to
``None``) never get a pseudonym: :meth:`get_or_create` returns
``None`` and structured walks leave the value untouched.

Free-text replacement (command lines, messages): every other string
leaf is scanned for the raw values mapped during the call
(structured fields first, then the whole deployment table, so an
entity learned from an earlier payload is still hidden),
longest-first. Matching is case-insensitive for host, user, domain
and email, exact for ip. Boundary rule: an occurrence counts only
when the character before it (if any) and the character after it (if
any) are both outside ``[A-Za-z0-9_.@-]``. That keeps ``bob`` inside
``bobcat`` (letter follows), ``bob.exe`` (dot follows) and
``bob@example.com`` (``@`` follows) untouched, while ``bob`` in
``user=bob,``, ``EXAMPLE\\bob`` or ``"admin"`` is replaced — it is a
whole user token there. One extension: a known short hostname also
matches with a trailing multi-label domain suffix (``web01`` matches
``WEB01.example.com``), so a later payload cannot leak the internal
domain through the FQDN form. Single-label suffixes (``web01.corp``,
``web01.exe``) do not match and stay a documented limitation.
A second extension: a trailing run of sentence punctuation (``.``,
``?``, ``!``, including an ellipsis) followed by the end of the
text, whitespace, or a closing quote/bracket is not part of the
name — ``on workstation5.`` becomes ``on HOST-0001.`` with the dot
kept. Dotted names still match as one unit, and a name inside a
longer token (``workstation55``, ``myworkstation5``) still never
matches.

Before that replacement, :func:`scan_entities` finds entities that
appear only in free text: IPv4 and IPv6 literals, e-mail addresses,
FQDNs (two or more labels, last label two or more ASCII letters),
UNC hosts, ``DOMAIN\\user`` spans, Windows profile and Unix home
path owners, and the user arguments of ``net user``, ``/user:``,
``runas /user:``, ssh/scp ``-u`` and bare ``user@host`` forms. Each
hit is looked up with its kind, so it is hidden even when no typed
field names it. Bare words in no recognizable position (``jump01``
in ``seen from jump host jump01``) cannot be found
deterministically: they are hidden only when the caller registers
the incident's typed entities first (see :meth:`Pseudonymizer.register`).
File-like two-label names (``a.sh`` in ``scp a.sh``) match the FQDN
shape and are pseudonymized as domains; telling them apart from real
names is undecidable syntactically, so the scanner fails closed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any

import psycopg

from corvus.normalize.ocsf import (
    canonicalize_host,
    canonicalize_ip,
    canonicalize_user,
)

__all__ = [
    "EMAIL_PATTERN",
    "FIELD_KINDS",
    "KINDS",
    "PREFIX",
    "Pseudonymizer",
    "scan_entities",
]

#: Entity kinds with a stable pseudonym each.
KINDS = ("host", "user", "ip", "domain", "email")

#: Pseudonym prefix per kind (``HOST-0001``, ``USER-0001``, ...).
PREFIX = {
    "host": "HOST",
    "user": "USER",
    "ip": "IP",
    "domain": "DOMAIN",
    "email": "EMAIL",
}

#: Structured-payload key (lowercased) -> entity kind. Only these keys
#: are replaced as typed fields; everything else is free text.
FIELD_KINDS: dict[str, str] = {
    "hostname": "host",
    "host": "host",
    "computer": "host",
    "computer_name": "host",
    "device_name": "host",
    "host_name": "host",
    "username": "user",
    "user": "user",
    "user_name": "user",
    "account_name": "user",
    "srcuser": "user",
    "dstuser": "user",
    "owner": "user",
    "ip": "ip",
    "ip_address": "ip",
    "src_ip": "ip",
    "dst_ip": "ip",
    "srcip": "ip",
    "dstip": "ip",
    "source_ip": "ip",
    "dest_ip": "ip",
    "client_ip": "ip",
    "server_ip": "ip",
    "remote_ip": "ip",
    "domain": "domain",
    "dns_domain": "domain",
    "user_domain": "domain",
    "ad_domain": "domain",
    "email": "email",
    "email_address": "email",
    "sender": "email",
    "recipient": "email",
    "reply_to": "email",
}

#: Token characters that forbid a free-text match on either side.
_TOKEN_CHARS = "A-Za-z0-9_.@-"

#: Children of a ``user`` object holding the login name. The key
#: ``name`` alone is far too generic for :data:`FIELD_KINDS` (file
#: names, rule names, tactic names all use it), so it maps to the
#: user kind only with a ``user`` parent (``actor.user.name``,
#: ``process.user.name`` in OCSF).
USER_DICT_NAME_KEYS = frozenset({"name"})

#: Pseudonym tokens for :meth:`reveal` (``HOST-0001`` etc.).
PSEUDONYM_PATTERN = re.compile(r"\b(HOST|USER|IP|DOMAIN|EMAIL)-(\d+)\b")

#: Loose email shape check (full validation is not needed for lookup).
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_LOCK_KEY = "corvus:pseudonyms"


def canonicalize_domain(value: str | None) -> str | None:
    """Lowercase and strip one trailing dot; placeholders return None."""
    text = (value or "").strip().lower().rstrip(".")
    if text.lower() in ("", "-", "n/a", "unknown"):
        return None
    if not text or any(char.isspace() for char in text):
        return None
    return text


def canonicalize_email(value: str | None) -> str | None:
    """Lowercase a whole address; anything not shaped like one is None."""
    text = (value or "").strip().lower()
    if text.lower() in ("", "-", "n/a", "unknown"):
        return None
    if EMAIL_PATTERN.match(text) is None:
        return None
    return text


_CANONICALIZE: dict[str, Callable[..., str | None]] = {
    "host": canonicalize_host,
    "user": canonicalize_user,
    "ip": canonicalize_ip,
    "domain": canonicalize_domain,
    "email": canonicalize_email,
}


def _canonical(kind: str, raw: str) -> str | None:
    return _CANONICALIZE[kind](raw)


#: Candidate IPv4 literal (kept only when it parses as an address).
_SCAN_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

#: Maximal runs that may hold an IPv6 literal (same validation; a
#: trailing dot from sentence punctuation is stripped first).
_SCAN_IPV6_RUN = re.compile(r"[0-9A-Fa-f:.]+")

#: Whole e-mail address; runs before the bare user@host form.
_SCAN_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])")

#: FQDN: two or more labels, last label two or more ASCII letters.
#: Never preceded by a backslash (Windows paths) so file names in
#: backslash paths are left alone; a preceding slash is allowed so
#: URL hosts still match.
_SCAN_FQDN = re.compile(r"(?<![\w.\\@-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w.-])")

#: UNC path: the host spelling is the entity (``\\FILESRV02\share``).
_SCAN_UNC = re.compile(r"\\\\([A-Za-z0-9_.-]+)\\")

#: ``DOMAIN\user`` (and ``host\user`` from whoami output): the whole
#: span maps to one user pseudonym through UPN canonicalization.
_SCAN_DOMAIN_USER = re.compile(
    r"(?<![\w.\\@$-])([A-Za-z0-9_.-]+)\\([A-Za-z0-9_.$-]+)(?![\w.@$-])"
)

#: Windows profile path; consumes the full path token so the file
#: name inside is never scanned as an FQDN.
_SCAN_PROFILE = re.compile(
    r"(?i)([A-Za-z]:[\\/]users[\\/][^\\/:\s\"'<>|&;]+)([^\s\"']*)"
)

#: Unix home path; same full-token consumption.
_SCAN_HOME = re.compile(r"(/home/[^/:\s\"'<>|&;]+)([^\s\"']*)")

#: ``net user <name>`` with an optional quoted name.
_SCAN_NET_USER = re.compile(r"(?i)\bnet\s+user\s+(?:\"([^\"]+)\"|([^\s/\"']+))")

#: ``/user:<name>`` (also ``runas /user:``).
_SCAN_USER_FLAG = re.compile(r"(?i)/user:(?:\"([^\"]+)\"|([^\s\"']+))")

#: ``-u <name>``; only beside an ssh/scp invocation in the same text.
_SCAN_SSH_U = re.compile(r"(?<![\w-])-u\s+(?:\"([^\"]+)\"|([^\s\"']+))")
_SCAN_SSH_LIKE = re.compile(r"(?i)\b(ssh|scp)\b")

#: Bare ``user@host`` (dotless host; dotted hosts are e-mail): the
#: whole span maps to one user pseudonym through UPN canonicalization.
_SCAN_USER_AT_HOST = re.compile(r"(?<![\w.+-])([\w.+-]+)@([\w-]+)(?![\w-])")


def _named(match: re.Match[str]) -> str:
    """Return the first non-None capture group (the entity spelling)."""
    for group in match.groups():
        if group is not None:
            return group
    raise AssertionError("scanner pattern matched with no entity group")


def scan_entities(text: str) -> list[tuple[str, str]]:
    """Find entity-shaped spans in free text.

    Returns ``(kind, raw_spelling)`` candidates in span order; look
    each up with :meth:`Pseudonymizer.get_or_create` (lookup
    canonicalizes and drops placeholders and invalid values).
    Overlapping spans resolve to the earliest start, then the
    longest span. Single-character hits are dropped (they match
    everywhere); register such values explicitly with
    :meth:`Pseudonymizer.register` when they are real entities.
    Non-string input raises :class:`TypeError`.
    """
    if not isinstance(text, str):
        raise TypeError(f"scan_entities needs a string, got {type(text).__name__}")
    spans: list[tuple[int, int, int, str, str]] = []

    def _hit(
        match: re.Match[str], priority: int, kind: str, raw: str | None = None
    ) -> None:
        spelling = match.group(0) if raw is None else raw
        if len(spelling) < 2:
            return
        spans.append((match.start(), match.end(), priority, kind, spelling))

    for match in _SCAN_EMAIL.finditer(text):
        _hit(match, 0, "email")
    for match in _SCAN_IPV4.finditer(text):
        if canonicalize_ip(match.group(0)) is not None:
            _hit(match, 1, "ip")
    for match in _SCAN_IPV6_RUN.finditer(text):
        token = match.group(0).strip(".")
        if ":" in token and canonicalize_ip(token) is not None:
            _hit(match, 1, "ip", token)
    for match in _SCAN_UNC.finditer(text):
        _hit(match, 2, "host", match.group(1))
    for match in _SCAN_PROFILE.finditer(text):
        _hit(match, 3, "user", re.split(r"[\\/]", match.group(1))[-1])
    for match in _SCAN_HOME.finditer(text):
        _hit(match, 3, "user", match.group(1).rsplit("/", 1)[-1])
    for match in _SCAN_NET_USER.finditer(text):
        _hit(match, 4, "user", _named(match))
    for match in _SCAN_USER_FLAG.finditer(text):
        _hit(match, 5, "user", _named(match))
    if _SCAN_SSH_LIKE.search(text) is not None:
        for match in _SCAN_SSH_U.finditer(text):
            _hit(match, 6, "user", _named(match))
    for match in _SCAN_DOMAIN_USER.finditer(text):
        _hit(match, 7, "user")
    for match in _SCAN_USER_AT_HOST.finditer(text):
        _hit(match, 8, "user")
    for match in _SCAN_FQDN.finditer(text):
        _hit(match, 9, "domain")
    spans.sort(key=lambda span: (span[0], -span[1], span[2]))
    kept: list[tuple[str, str]] = []
    consumed: list[tuple[int, int]] = []
    for start, end, _, kind, raw in spans:
        if any(start < stop and end > begin for begin, stop in consumed):
            continue
        consumed.append((start, end))
        kept.append((kind, raw))
    return kept


class Pseudonymizer:
    """Get-or-create stable pseudonyms backed by the ``pseudonyms`` table.

    One short connection per call (the transaction never stays open
    across calls), so concurrent threads are safe: allocation runs
    under a Postgres advisory lock and the insert carries
    ``ON CONFLICT`` on ``(entity_kind, entity_value)``.
    """

    def __init__(self, database_url: str) -> None:
        if not database_url:
            raise ValueError("Pseudonymizer needs a database URL")
        self._database_url = database_url

    def get_or_create(self, kind: str, raw_value: str) -> str | None:
        """Return the stable pseudonym for ``raw_value``, creating it.

        The value is canonicalized first; placeholders and empty
        values return ``None`` (they never get a pseudonym). An
        unknown kind raises :class:`ValueError`.
        """
        mapping = self.register([(kind, raw_value)])
        if not mapping:
            return None
        return next(iter(mapping.values()))

    def register(
        self, entities: Iterable[tuple[str, str]]
    ) -> dict[tuple[str, str], str]:
        """Ensure every ``(kind, raw_value)`` entity has a pseudonym.

        The caller passes every typed entity of the whole incident
        (hosts, users, ips, domains, e-mails from all its events, not
        only the payload being sent), so a name typed in event A is
        already known when it appears only in the free text of event
        B. Returns ``{(kind, canonical): pseudonym}``. An unknown
        kind raises :class:`ValueError`; a non-string value raises
        :class:`TypeError`; placeholders resolve to nothing and are
        skipped.
        """
        pairs: list[tuple[str, str]] = []
        for kind, raw_value in entities:
            if kind not in PREFIX:
                raise ValueError(f"unknown pseudonym kind {kind!r}")
            if not isinstance(raw_value, str):
                raise TypeError(
                    f"value must be a string, got {type(raw_value).__name__}"
                )
            canonical = _canonical(kind, raw_value)
            if canonical is not None:
                pairs.append((kind, canonical))
        return self._ensure_many(pairs)

    def _ensure_many(self, items: list[tuple[str, str]]) -> dict[tuple[str, str], str]:
        """Map each (kind, canonical) pair, allocating missing numbers."""
        ordered: list[tuple[str, str]] = list(dict.fromkeys(items))
        if not ordered:
            return {}
        with psycopg.connect(self._database_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (_LOCK_KEY,))
                kinds = sorted({kind for kind, _ in ordered})
                cur.execute(
                    "SELECT entity_kind, entity_value, pseudonym FROM pseudonyms "
                    "WHERE entity_kind = ANY(%s)",
                    (kinds,),
                )
                known: dict[tuple[str, str], str] = {
                    (row[0], row[1]): row[2] for row in cur.fetchall()
                }
                highest: dict[str, int] = {}
                for (kind, _), pseudonym in known.items():
                    number = _suffix_number(pseudonym)
                    if number is not None:
                        highest[kind] = max(highest.get(kind, 0), number)
                mapping: dict[tuple[str, str], str] = dict(known)
                for kind, canonical in ordered:
                    if (kind, canonical) in mapping:
                        continue
                    highest[kind] = highest.get(kind, 0) + 1
                    candidate = f"{PREFIX[kind]}-{highest[kind]:04d}"
                    cur.execute(
                        "INSERT INTO pseudonyms (entity_kind, entity_value, pseudonym)"
                        " VALUES (%s, %s, %s)"
                        " ON CONFLICT (entity_kind, entity_value) DO NOTHING"
                        " RETURNING pseudonym",
                        (kind, canonical, candidate),
                    )
                    row = cur.fetchone()
                    if row is None:
                        cur.execute(
                            "SELECT pseudonym FROM pseudonyms"
                            " WHERE entity_kind = %s AND entity_value = %s",
                            (kind, canonical),
                        )
                        found = cur.fetchone()
                        assert found is not None
                        mapping[kind, canonical] = str(found[0])
                    else:
                        mapping[kind, canonical] = str(row[0])
            conn.commit()
        return {
            (kind, canonical): mapping[kind, canonical] for kind, canonical in ordered
        }

    def _known_map(self) -> dict[str, tuple[str, str]]:
        """Return every stored raw value -> (pseudonym, kind)."""
        with psycopg.connect(self._database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT entity_kind, entity_value, pseudonym FROM pseudonyms"
                )
                rows = cur.fetchall()
        return {
            str(value): (str(pseudonym), str(kind)) for kind, value, pseudonym in rows
        }

    def pseudonymize(self, payload: Any) -> Any:
        """Replace entity values in a structured payload with pseudonyms.

        Dicts keyed by :data:`FIELD_KINDS` are replaced as typed fields
        (canonicalized first, so ``WEB01.example.com`` and ``web01``
        share one pseudonym); every other string leaf first goes
        through :func:`scan_entities` so entities that appear only in
        free text are looked up too. Then every string leaf is scanned
        for the mapped raw values (this call's plus every earlier
        row, including entities from :meth:`register`), longest-first,
        under the boundary rule from the module docstring. Mapping
        keys are untouched and non-string leaves pass through.
        Pydantic models are dumped first.
        """
        dumped = payload.model_dump() if hasattr(payload, "model_dump") else payload
        collected: list[tuple[str, str, str]] = []
        self._collect(dumped, collected)
        known = self._known_map()
        known_hosts = {value for value, (_, kind) in known.items() if kind == "host"}
        structured_hosts = {
            canonical for kind, canonical, _ in collected if kind == "host"
        }
        structured_raws = {raw for _, _, raw in collected}
        scanned: list[tuple[str, str, str]] = []
        for kind, raw in self._scan_strings(dumped):
            if raw in structured_raws:
                # The typed field already maps this spelling; a second
                # lookup (often under another kind) must not shadow it.
                continue
            if kind == "domain":
                short = canonicalize_host(raw)
                if short is not None and (
                    short in structured_hosts or short in known_hosts
                ):
                    # A known short hostname covers this FQDN through
                    # the host-suffix rule; no domain row is needed and
                    # the span keeps the host's pseudonym.
                    continue
            canonical = _canonical(kind, raw)
            if canonical is not None:
                scanned.append((kind, canonical, raw))
        fresh = self._ensure_many(
            [(kind, canonical) for kind, canonical, _ in collected + scanned]
        )
        table: dict[str, tuple[str, str]] = dict(known)
        for kind, canonical, raw in collected:
            pseudonym = fresh.get((kind, canonical))
            if pseudonym is None:
                continue
            table[canonical] = (pseudonym, kind)
            # The raw spelling too: free text may carry
            # "WEB01.example.com" while the canonical form is "web01",
            # which the boundary rule would otherwise never match.
            table[raw] = (pseudonym, kind)
        for kind, canonical, raw in scanned:
            pseudonym = fresh.get((kind, canonical))
            if pseudonym is None:
                continue
            # Typed spellings win ties: a raw already mapped above
            # keeps its pseudonym.
            table.setdefault(canonical, (pseudonym, kind))
            table.setdefault(raw, (pseudonym, kind))
        return self._replace(dumped, table)

    def _scan_strings(self, value: Any) -> list[tuple[str, str]]:
        """Run :func:`scan_entities` over every string leaf's value."""
        found: list[tuple[str, str]] = []
        if isinstance(value, str):
            found.extend(scan_entities(value))
        elif isinstance(value, dict):
            for item in value.values():
                found.extend(self._scan_strings(item))
        elif isinstance(value, list | tuple):
            for item in value:
                found.extend(self._scan_strings(item))
        return found

    def _collect(self, value: Any, out: list[tuple[str, str, str]]) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = key.lower() if isinstance(key, str) else ""
                kind = FIELD_KINDS.get(lowered)
                if kind is not None and isinstance(item, str):
                    canonical = _canonical(kind, item)
                    if canonical is not None:
                        out.append((kind, canonical, item))
                elif lowered == "user" and isinstance(item, dict):
                    for child in USER_DICT_NAME_KEYS:
                        raw = item.get(child)
                        if isinstance(raw, str):
                            canonical = _canonical("user", raw)
                            if canonical is not None:
                                out.append(("user", canonical, raw))
                    self._collect(item, out)
                else:
                    self._collect(item, out)
        elif isinstance(value, list | tuple):
            for item in value:
                self._collect(item, out)

    def _replace(self, value: Any, table: dict[str, tuple[str, str]]) -> Any:
        if isinstance(value, str):
            return _replace_free_text(value, table)
        if isinstance(value, dict):
            replaced: dict[Any, Any] = {}
            for key, item in value.items():
                lowered = key.lower() if isinstance(key, str) else ""
                kind = FIELD_KINDS.get(lowered)
                if kind is not None and isinstance(item, str):
                    canonical = _canonical(kind, item)
                    if canonical is not None and canonical in table:
                        replaced[key] = table[canonical][0]
                    else:
                        replaced[key] = _replace_free_text(item, table)
                elif lowered == "user" and isinstance(item, dict):
                    new_user: dict[Any, Any] = {}
                    for child_key, child_value in item.items():
                        if (
                            isinstance(child_key, str)
                            and child_key.lower() in USER_DICT_NAME_KEYS
                            and isinstance(child_value, str)
                        ):
                            canonical = _canonical("user", child_value)
                            if canonical is not None and canonical in table:
                                new_user[child_key] = table[canonical][0]
                            else:
                                new_user[child_key] = _replace_free_text(
                                    child_value, table
                                )
                        else:
                            new_user[child_key] = self._replace(child_value, table)
                    replaced[key] = new_user
                else:
                    replaced[key] = self._replace(item, table)
            return replaced
        if isinstance(value, list):
            return [self._replace(item, table) for item in value]
        if isinstance(value, tuple):
            return tuple(self._replace(item, table) for item in value)
        return value

    def reveal(self, text: str) -> str:
        """Map pseudonyms in ``text`` back to canonical values (UI use).

        Only pseudonyms stored in the table are replaced; unknown
        tokens (``HOST-9999`` with no row) stay untouched. Real values
        returned here must stay on-prem: never send the result to a
        cloud model. Non-string input raises :class:`TypeError`.
        """
        if not isinstance(text, str):
            raise TypeError(f"reveal needs a string, got {type(text).__name__}")
        tokens = {match.group(0) for match in PSEUDONYM_PATTERN.finditer(text)}
        if not tokens:
            return text
        with psycopg.connect(self._database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pseudonym, entity_value FROM pseudonyms"
                    " WHERE pseudonym = ANY(%s)",
                    (sorted(tokens),),
                )
                mapping = {str(row[0]): str(row[1]) for row in cur.fetchall()}
        if not mapping:
            return text
        return PSEUDONYM_PATTERN.sub(
            lambda match: mapping.get(match.group(0), match.group(0)), text
        )


def _suffix_number(pseudonym: str) -> int | None:
    """Parse the trailing ``-NNNN`` counter of a pseudonym."""
    head, sep, tail = pseudonym.rpartition("-")
    if not sep or not head or not tail.isdigit():
        return None
    return int(tail)


#: A trailing multi-label domain suffix for short hostnames in free
#: text (``.example.com`` but not ``.exe``).
_HOST_SUFFIX = r"(?:\.[A-Za-z0-9-]+){2,}"

#: Sentence punctuation that may follow a name without belonging to
#: it: a run of ``.``, ``?`` or ``!`` (an ellipsis counts) followed
#: by the end of the text, whitespace, or a closing quote/bracket.
#: The run stays in the output after the pseudonym.
_SENTENCE_PUNCT = r"[.?!]+"

#: Closing characters that may end a sentence after the punctuation.
_CLOSING_CHARS = r")\]}'\""


def _replace_free_text(text: str, table: dict[str, tuple[str, str]]) -> str:
    """Replace known raw values inside one free-text string."""
    if not text or not table:
        return text
    for raw in sorted(table, key=len, reverse=True):
        pseudonym, kind = table[raw]
        if not raw or raw == pseudonym:
            continue
        flags = 0 if kind == "ip" else re.IGNORECASE
        body = re.escape(raw)
        if kind == "host" and "." not in raw:
            # Longest-first ordering already prefers an earlier full
            # spelling; the alternation tries the suffixed form first.
            body = f"(?:{re.escape(raw)}{_HOST_SUFFIX}|{re.escape(raw)})"
        pattern = re.compile(
            r"(?<!["
            + _TOKEN_CHARS
            + r"])"
            + body
            + r"(?:(?P<punct>"
            + _SENTENCE_PUNCT
            + r")(?=$|\s|["
            + _CLOSING_CHARS
            + r"])|(?!["
            + _TOKEN_CHARS
            + r"]))",
            flags,
        )

        def _emit(match: re.Match[str], pseudo: str = pseudonym) -> str:
            return pseudo + (match.group("punct") or "")

        text = pattern.sub(_emit, text)
    return text
