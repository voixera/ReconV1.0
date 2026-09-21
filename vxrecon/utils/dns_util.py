"""DNS resolution helpers.

Design goals:

* **Work without dnspython.** The standard library can resolve A/AAAA (via
  ``socket``) but cannot query MX/TXT/NS/SOA/CAA. When dnspython is missing we
  return those record types as *unavailable* rather than guessing.
* **Fail soft.** Every function returns structured data; network/DNS errors
  become fields, never exceptions.
* **No external APIs.** We use the system resolver and, when available,
  dnspython against the OS-configured nameservers. No third-party DNS APIs.

All functions are read-only queries. Nothing here can modify a zone.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any

try:  # optional enrichment
    import dns.exception  # type: ignore
    import dns.resolver  # type: ignore

    _HAS_DNSPYTHON = True
except Exception:  # noqa: BLE001
    _HAS_DNSPYTHON = False

# Record types we know how to query. A/AAAA work with the stdlib; the rest
# require dnspython.
STDLIB_TYPES = ("A", "AAAA")
DNSPYTHON_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "CNAME", "PTR", "SRV")
DEFAULT_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")


@dataclass
class DnsRecord:
    """A single DNS record observation."""

    record_type: str
    name: str
    value: str
    ttl: int | None = None
    source: str = "resolver"


@dataclass
class DnsResult:
    """Aggregate DNS result for one name."""

    name: str
    records: list[DnsRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    resolver_available: bool = True
    backend: str = "stdlib"

    def by_type(self, record_type: str) -> list[DnsRecord]:
        return [r for r in self.records if r.record_type == record_type.upper()]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "backend": self.backend,
            "records": [r.__dict__ for r in self.records],
            "errors": list(self.errors),
        }


def dnspython_available() -> bool:
    return _HAS_DNSPYTHON


def _resolve_stdlib(name: str, record_type: str) -> list[DnsRecord]:
    """Resolve A/AAAA using the standard library only."""

    family = socket.AF_INET if record_type == "A" else socket.AF_INET6
    try:
        infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise _ResolveError(str(exc)) from exc
    seen: set[str] = set()
    records: list[DnsRecord] = []
    for info in infos:
        addr = info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        records.append(DnsRecord(record_type, name, addr, source="stdlib"))
    return records


class _ResolveError(Exception):
    """Internal marker for a resolver failure."""


def _resolve_dnspython(name: str, record_type: str, timeout: float = 10.0) -> list[DnsRecord]:
    """Resolve an arbitrary record type using dnspython.

    ``timeout`` guards against slow/hanging resolvers (e.g. a local router that
    drops certain queries). A per-query lifetime keeps the whole scan bounded.
    """

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 5.0)
    try:
        answers = resolver.resolve(name, record_type, raise_on_no_answer=False)
    except dns.exception.DNSException as exc:  # type: ignore[attr-defined]
        raise _ResolveError(str(exc)) from exc

    records: list[DnsRecord] = []
    if answers.rrset is None:
        return records
    ttl = answers.rrset.ttl
    for rdata in answers:
        value = _format_rdata(record_type, rdata)
        records.append(DnsRecord(record_type, name, value, ttl=ttl, source="dnspython"))
    return records


def _format_rdata(record_type: str, rdata: Any) -> str:
    """Normalize dnspython rdata into a stable string form."""

    if record_type == "MX":
        return f"{rdata.preference} {rdata.exchange}".rstrip(".")
    if record_type == "TXT":
        # TXT rdata may span multiple strings; join without separators.
        parts = getattr(rdata, "strings", None)
        if parts:
            return "".join(p.decode("utf-8", "replace") for p in parts)
        return str(rdata).strip('"')
    if record_type in {"NS", "CNAME", "PTR"}:
        return str(rdata).rstrip(".")
    if record_type == "SOA":
        return (
            f"{rdata.mname} {rdata.rname} serial={rdata.serial} "
            f"refresh={rdata.refresh} retry={rdata.retry} "
            f"expire={rdata.expire} minimum={rdata.minimum}"
        )
    if record_type == "CAA":
        return f"{rdata.flags} {rdata.tag.decode() if isinstance(rdata.tag, bytes) else rdata.tag} {rdata.value.decode() if isinstance(rdata.value, bytes) else rdata.value}"
    return str(rdata)


def query(
    name: str,
    record_types: tuple[str, ...] = DEFAULT_TYPES,
    timeout: float = 10.0,
) -> DnsResult:
    """Query multiple record types for ``name`` and return a :class:`DnsResult`.

    Never raises: resolver failures are captured per-type into ``errors``.
    """

    result = DnsResult(name=name, backend="dnspython" if _HAS_DNSPYTHON else "stdlib")
    for record_type in record_types:
        try:
            if _HAS_DNSPYTHON:
                records = _resolve_dnspython(name, record_type, timeout=timeout)
            elif record_type in STDLIB_TYPES:
                records = _resolve_stdlib(name, record_type)
            else:
                result.errors.append(
                    f"{record_type}: unavailable without dnspython"
                )
                continue
            result.records.extend(records)
        except _ResolveError as exc:
            result.errors.append(f"{record_type}: {exc}")
        except Exception as exc:  # noqa: BLE001 - resolver must never crash us
            result.errors.append(f"{record_type}: unexpected error: {exc}")
    return result


def resolve_a(name: str, timeout: float = 5.0) -> list[str]:
    """Return IPv4 addresses for ``name`` (best effort)."""

    if _HAS_DNSPYTHON:
        try:
            return [r.value for r in _resolve_dnspython(name, "A", timeout=timeout)]
        except _ResolveError:
            return []
    try:
        return [r.value for r in _resolve_stdlib(name, "A")]
    except _ResolveError:
        return []
