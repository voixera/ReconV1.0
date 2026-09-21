"""Time helpers.

All timestamps in VXRecon are ISO-8601 in UTC. Centralizing them keeps the
database, reports and timeline consistent and makes diffing reliable.
"""

from __future__ import annotations

from datetime import datetime, timezone


def now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with timezone."""

    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: str) -> datetime | None:
    """Parse an ISO-8601 string, returning ``None`` on failure."""

    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def humanize_age(value: str) -> str:
    """Return a coarse human-readable age like ``"3 days ago"``."""

    parsed = parse_iso(value)
    if parsed is None:
        return "unknown"
    delta = datetime.now(timezone.utc) - parsed
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"
