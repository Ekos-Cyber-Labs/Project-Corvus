"""Deterministic correlation and ATT&CK mapping."""

from corvus.correlate.correlate import (
    DEFAULT_AUTH_FAILURE_THRESHOLD,
    DEFAULT_MAX_SPAN,
    DEFAULT_SESSION_GAP,
    Incident,
    correlate_findings,
)
from corvus.correlate.identities import SERVICE_USER_NAMES, is_service_identity
from corvus.correlate.severity import (
    STAGE_LEVELS,
    check_stage_coverage,
    primary_of,
    severity_floor,
)

__all__ = [
    "DEFAULT_AUTH_FAILURE_THRESHOLD",
    "DEFAULT_MAX_SPAN",
    "DEFAULT_SESSION_GAP",
    "STAGE_LEVELS",
    "SERVICE_USER_NAMES",
    "Incident",
    "check_stage_coverage",
    "correlate_findings",
    "is_service_identity",
    "primary_of",
    "severity_floor",
]
