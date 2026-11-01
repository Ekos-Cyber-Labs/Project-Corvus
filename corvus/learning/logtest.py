"""Offline Wazuh-side parity: runner interface and output parsing.

Nothing here contacts a server on its own. A *runner* feeds bundle
input lines to ``wazuh-logtest`` and returns one parsed JSON mapping
per line; the command to reach the manager lives only in the
:envvar:`CORVUS_WAZUH_LOGTEST_CMD` environment variable (never in
code or in the bundle), and tests use a stand-in runner.

Wire contract (documented in every bundle's deploy plan): the
command reads one JSON object per stdin line
(``{"location": ..., "agent": {...}, "log": ...}``) and writes one
JSON object per stdout line. Parsing relies only on the ``decoder``
and ``rule`` blocks — the same ``decoder``/``rule`` JSON Wazuh emits
in its archives and alerts (verified against the real records under
``data/lab-chain1/``): ``decoder.name`` names the decoder,
``rule.id``/``rule.level`` name the firing rule. Anything else in
the output is ignored. Fail-closed behavior:

- transport errors, timeouts, line-count mismatch or non-JSON lines
  raise :class:`LogtestError` (no report is written);
- a well-formed line with no ``rule`` block means "did not fire";
- a well-formed ``rule`` block with an unparseable ``id`` raises
  :class:`LogtestError` (a fire is never claimed on garbage).
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

__all__ = [
    "BRIDGE_CONTRACT",
    "LOGTEST_ENV_VAR",
    "LOGTEST_TIMEOUT_S",
    "LogtestError",
    "LogtestRunner",
    "LogtestVerdict",
    "ParityReport",
    "SubprocessLogtestRunner",
    "compare_parity",
    "parse_logtest_result",
]

#: Environment variable holding the logtest command (full argv in
#: shell words, e.g. ``ssh wazuh-manager wazuh-logtest --json`` is
#: the OPERATOR's value; nothing here assumes one).
LOGTEST_ENV_VAR = "CORVUS_WAZUH_LOGTEST_CMD"

#: Default wall-clock budget for one logtest run.
LOGTEST_TIMEOUT_S = 120.0

#: The exact bridge contract between a bundle and the operator-side
#: ``wazuh-logtest`` command (repeated in the deploy plan).
BRIDGE_CONTRACT = {
    "in": (
        "The runner feeds one JSON object per stdin line: "
        '{"location": ..., "agent": {...}, "log": ...} '
        "(the RAW full_log plus its location and agent fields)."
    ),
    "out": (
        "The command writes one JSON object per stdout line carrying "
        "the decoder block (decoder.name) and, when a rule fired, the "
        "rule block (rule.id, rule.level) -- the same blocks Wazuh "
        "emits in archives and alerts. Anything else is ignored."
    ),
    "command": (
        "The operator-side command is configured only through "
        f"{LOGTEST_ENV_VAR} (never in code or in the bundle)."
    ),
}


class LogtestError(RuntimeError):
    """The logtest run or its output cannot be trusted (fail closed)."""


class LogtestRunner(Protocol):
    """Feeds input lines to ``wazuh-logtest``; one mapping per line."""

    def run(
        self, inputs: Sequence[Mapping[str, Any]], *, timeout_s: float = ...
    ) -> list[dict[str, Any]]:
        """Return one parsed JSON object per input, in order."""
        ...


@dataclass(frozen=True)
class LogtestVerdict:
    """One parsed logtest answer: did our rule fire?"""

    fired: bool
    decoder: str | None
    rule_id: int | None
    level: int | None


def parse_logtest_result(raw: Any, *, rule_ids: Collection[int]) -> LogtestVerdict:
    """Parse one logtest JSON object; raise :class:`LogtestError`.

    Relies only on ``decoder.name`` plus ``rule.id``/``rule.level``
    (the archive/alert block shape). No ``rule`` block means the
    line did not fire; anything misshapen raises instead of
    claiming either way.
    """
    wanted = {int(item) for item in rule_ids}
    if not isinstance(raw, dict):
        raise LogtestError(f"logtest output is not an object: {raw!r}"[:200])
    decoder = raw.get("decoder")
    if not isinstance(decoder, dict):
        raise LogtestError("logtest output has no decoder block")
    name = decoder.get("name")
    if not isinstance(name, str) or not name:
        raise LogtestError("logtest decoder block has no name")
    rule = raw.get("rule")
    if rule is None:
        return LogtestVerdict(fired=False, decoder=name, rule_id=None, level=None)
    if not isinstance(rule, dict):
        raise LogtestError("logtest rule block is not an object")
    raw_id = rule.get("id")
    try:
        rule_id = int(str(raw_id).strip())
    except TypeError, ValueError:
        raise LogtestError(f"logtest rule id is not an integer: {raw_id!r}") from None
    level: int | None = None
    if rule.get("level") is not None:
        try:
            level = int(str(rule["level"]).strip())
        except TypeError, ValueError:
            raise LogtestError(
                f"logtest rule level is not an integer: {rule.get('level')!r}"
            ) from None
    return LogtestVerdict(
        fired=rule_id in wanted, decoder=name, rule_id=rule_id, level=level
    )


class SubprocessLogtestRunner:
    """Pipes bundle inputs through the env-configured command.

    The command comes from :envvar:`CORVUS_WAZUH_LOGTEST_CMD`
    (or the explicit ``command``); a missing variable raises
    :class:`LogtestError` instead of guessing a default.
    """

    def __init__(self, command: Sequence[str] | None = None) -> None:
        if command is None:
            raw = os.environ.get(LOGTEST_ENV_VAR, "").strip()
            if not raw:
                raise LogtestError(
                    f"{LOGTEST_ENV_VAR} is not set: no logtest command configured"
                )
            command = shlex.split(raw)
        if not command:
            raise LogtestError("logtest command is empty")
        self._command = list(command)

    def run(
        self,
        inputs: Sequence[Mapping[str, Any]],
        *,
        timeout_s: float = LOGTEST_TIMEOUT_S,
    ) -> list[dict[str, Any]]:
        """Pipe ``inputs`` as JSONL; return one JSON object per line."""
        payload = (
            "\n".join(
                json.dumps(dict(item), sort_keys=True, default=str) for item in inputs
            )
            + "\n"
        )
        try:
            proc = subprocess.run(
                self._command,
                input=payload,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            raise LogtestError(f"logtest timed out after {timeout_s} s") from exc
        except OSError as exc:
            raise LogtestError(f"logtest command failed to start: {exc}") from None
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "")[:300]
            raise LogtestError(f"logtest exited {proc.returncode}: {detail}".rstrip())
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        if len(lines) != len(inputs):
            raise LogtestError(
                f"logtest returned {len(lines)} lines for {len(inputs)} inputs"
            )
        parsed: list[dict[str, Any]] = []
        for line in lines:
            try:
                value = json.loads(line)
            except ValueError as exc:
                raise LogtestError(f"logtest line is not JSON: {line[:120]!r}") from exc
            if not isinstance(value, dict):
                raise LogtestError("logtest line is not a JSON object")
            parsed.append(value)
        return parsed


@dataclass(frozen=True)
class ParityLine:
    """Sigma vs Wazuh on one bundle line."""

    key: int
    event_uid: str | None
    must_fire: bool
    fired: bool
    decoder: str | None
    rule_id: int | None

    @property
    def agrees(self) -> bool:
        """True when Wazuh did what Sigma said it must."""
        return self.must_fire == self.fired


@dataclass
class ParityReport:
    """Per-line parity plus every disagreement listed."""

    lines: list[ParityLine]
    disagreements: list[ParityLine]

    @property
    def agreement(self) -> int:
        """Lines where Sigma and Wazuh agree."""
        return sum(1 for line in self.lines if line.agrees)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable report."""
        return {
            "inputs": len(self.lines),
            "agreement": self.agreement,
            "bridge": dict(BRIDGE_CONTRACT),
            "disagreements": [
                {
                    "key": line.key,
                    "event_uid": line.event_uid,
                    "must_fire": line.must_fire,
                    "fired": line.fired,
                    "decoder": line.decoder,
                    "rule_id": line.rule_id,
                }
                for line in self.disagreements
            ],
            "per_line": [
                {
                    "key": line.key,
                    "event_uid": line.event_uid,
                    "must_fire": line.must_fire,
                    "fired": line.fired,
                    "agree": line.agrees,
                }
                for line in self.lines
            ],
        }


def compare_parity(
    expected: Sequence[Mapping[str, Any]],
    verdicts: Sequence[LogtestVerdict],
) -> ParityReport:
    """Compare Sigma ``must_fire`` flags to logtest verdicts, in order.

    Raises :class:`LogtestError` on length mismatch (a shifted
    pairing would silently invert the report).
    """
    if len(expected) != len(verdicts):
        raise LogtestError(
            f"{len(verdicts)} verdicts for {len(expected)} expected lines"
        )
    lines: list[ParityLine] = []
    for want, got in zip(expected, verdicts, strict=True):
        try:
            key = int(want["key"])  # type: ignore[index]
        except TypeError, ValueError, KeyError:
            raise LogtestError("expected line has no integer key") from None
        line = ParityLine(
            key=key,
            event_uid=str(want.get("event_uid"))
            if want.get("event_uid") is not None
            else None,
            must_fire=bool(want.get("must_fire", False)),
            fired=got.fired,
            decoder=got.decoder,
            rule_id=got.rule_id,
        )
        lines.append(line)
    care = [entry for entry in lines if not entry.agrees]
    return ParityReport(lines=lines, disagreements=care)
