"""Well-known machine and service identities.

These identities are kept as incident attributes but never used as
correlation join keys: a single service account (for example
``NT AUTHORITY\\SYSTEM``) appears on nearly every alert on a host, so
joining on it would glue unrelated alerts into one incident.
"""

from __future__ import annotations

__all__ = ["SERVICE_USER_NAMES", "is_service_identity"]

#: Canonical user names (the part after an optional ``domain\\`` prefix,
#: already lowercased by :func:`corvus.normalize.ocsf.canonicalize_user`)
#: that name a well-known machine or service identity rather than a human
#: or service-account principal worth joining on.
SERVICE_USER_NAMES = frozenset(
    {
        "system",
        "local service",
        "network service",
        "anonymous logon",
    }
)


def is_service_identity(user_key: str | None) -> bool:
    """Return True when a canonical user key is a service identity.

    ``user_key`` is the lowercased ``domain\\name`` (or bare ``name``)
    key from :func:`corvus.normalize.ocsf.canonicalize_user`. Machine
    accounts (names ending in ``$``), the well-known service names in
    :data:`SERVICE_USER_NAMES`, and empty or missing keys (``None`` or
    blank, already rejected as placeholders upstream) count as service
    identities. Anything else is a joinable principal.
    """
    if user_key is None:
        return True
    name = user_key.rsplit("\\", 1)[-1].strip().lower()
    if not name:
        return True
    return name in SERVICE_USER_NAMES or name.endswith("$")
