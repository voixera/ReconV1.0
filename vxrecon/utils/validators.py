"""Target validation helpers.

Small, dependency-free validators used by the CLI and analyzers. They are
deliberately permissive (the goal is to catch obvious mistakes, not to be an
RFC-complete parser) and never perform any network lookup.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})$"
)


def is_domain(value: str) -> bool:
    """Return True if ``value`` looks like a registrable domain / hostname."""

    if not value or len(value) > 253:
        return False
    return bool(_DOMAIN_RE.match(value.rstrip(".")))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


def normalize_url(value: str) -> str:
    """Add ``https://`` when the user omitted a scheme."""

    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value}"


def host_from_target(value: str) -> str:
    """Extract the hostname from a URL or return the value unchanged."""

    if is_url(value):
        return urlparse(value).hostname or value
    return value


def classify_target(value: str) -> str:
    """Classify a raw target string into a coarse ``kind``.

    Returns one of ``domain``, ``url``, ``ip`` or ``unknown``.
    """

    value = value.strip()
    if is_url(value):
        return "url"
    if is_ip(value):
        return "ip"
    if is_domain(value):
        return "domain"
    if "@" in value:
        return "email"
    return "unknown"
