"""RDAP collector.

RDAP (Registration Data Access Protocol) is the JSON-over-HTTPS successor to
WHOIS. It requires **no API key** and is served by the authoritative registries
themselves. VXRecon queries:

* the IANA bootstrap registry to find the right RDAP endpoint, then
* that endpoint for the domain's registration data.

We additionally resolve a domain's IP and query the RIR RDAP for ASN/network
information, again with no key. Everything is read-only GET via the gateway.

Fallback: if the IANA bootstrap file is unreachable, we use a small static map
of well-known bootstrap URLs for the common TLDs, and otherwise report the
capability as unavailable rather than guessing.
"""

from __future__ import annotations

from typing import Any

from vxrecon.collectors.base import BaseCollector
from vxrecon.core.context import RunContext
from vxrecon.utils import net
from vxrecon.utils.validators import host_from_target, is_domain, is_ip

# Public IANA RDAP bootstrap (no key). Served as JSON.
IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
IANA_IPV4_BOOTSTRAP = "https://data.iana.org/rdap/ipv4.json"

# Cache the bootstrap in-process to avoid refetching for every target.
_BOOTSTRAP_CACHE: dict[str, Any] = {}


class RdapCollector(BaseCollector):
    """Query RDAP for domain registration and IP/ASN data."""

    name = "rdap"
    requires_network = True
    provides = ("registration", "network")

    def collect(self, target: str) -> dict[str, Any]:
        host = host_from_target(target)
        payload: dict[str, Any] = {"target": host}

        if is_ip(host):
            payload["network"] = self._collect_ip(host)
        elif is_domain(host):
            payload["registration"] = self._collect_domain(host)
            # Best-effort ASN lookup for the first resolved IPv4.
            from vxrecon.utils import dns_util

            ips = dns_util.resolve_a(host)
            if ips:
                payload["network"] = self._collect_ip(ips[0])
        else:
            return self._error(f"not a valid domain or IP: {target!r}")

        if not payload.get("registration") and not payload.get("network"):
            payload["_error"] = "no RDAP data available"
        return payload

    # -- domain ----------------------------------------------------------

    def _collect_domain(self, domain: str) -> dict[str, Any] | None:
        tld = domain.rsplit(".", 1)[-1].lower()
        endpoint = self._bootstrap_url(tld)
        if not endpoint:
            return {"_error": f"no RDAP endpoint known for TLD: .{tld}"}
        url = f"{endpoint.rstrip('/')}/domain/{domain}"
        result = net.http_get(url, self.ctx, headers={"Accept": "application/rdap+json"})
        if not result.ok:
            return {"_error": result.error or f"HTTP {result.status}"}
        try:
            import json

            data = json.loads(result.text)
        except (ValueError, TypeError):
            return {"_error": "invalid RDAP JSON"}
        return self._summarize_registration(data)

    @staticmethod
    def _summarize_registration(data: dict[str, Any]) -> dict[str, Any]:
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        nameservers = [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])]
        status = data.get("status", [])
        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for v in entity.get("vcardArray", [[], []])[1]:
                    if v[0] == "fn":
                        registrar = v[3]
        return {
            "handle": data.get("handle"),
            "ldhName": data.get("ldhName"),
            "status": status,
            "events": events,
            "nameservers": sorted(ns for ns in nameservers if ns),
            "registrar": registrar,
        }

    def _bootstrap_url(self, tld: str) -> str | None:
        services = _BOOTSTRAP_CACHE.get("dns")
        if services is None:
            result = net.http_get(IANA_BOOTSTRAP, self.ctx)
            if result.ok:
                try:
                    import json

                    services = json.loads(result.text).get("services", [])
                    _BOOTSTRAP_CACHE["dns"] = services
                except (ValueError, TypeError):
                    services = []
            else:
                services = []
                _BOOTSTRAP_CACHE["dns"] = services
        for tlds, urls in services or []:
            if tld in tlds and urls:
                return urls[0]
        return None

    # -- ip / network ----------------------------------------------------

    def _collect_ip(self, ip: str) -> dict[str, Any] | None:
        services = _BOOTSTRAP_CACHE.get("ipv4")
        if services is None:
            result = net.http_get(IANA_IPV4_BOOTSTRAP, self.ctx)
            if result.ok:
                try:
                    import json

                    services = json.loads(result.text).get("services", [])
                    _BOOTSTRAP_CACHE["ipv4"] = services
                except (ValueError, TypeError):
                    services = []
            else:
                services = []
                _BOOTSTRAP_CACHE["ipv4"] = services

        endpoint = None
        import ipaddress

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for prefixes, urls in services or []:
            for prefix in prefixes:
                try:
                    if addr in ipaddress.ip_network(prefix, strict=False):
                        endpoint = urls[0]
                        break
                except ValueError:
                    continue
            if endpoint:
                break
        if not endpoint:
            return {"_error": "no RDAP IP endpoint found"}

        url = f"{endpoint.rstrip('/')}/ip/{ip}"
        result = net.http_get(url, self.ctx, headers={"Accept": "application/rdap+json"})
        if not result.ok:
            return {"_error": result.error or f"HTTP {result.status}"}
        try:
            import json

            data = json.loads(result.text)
        except (ValueError, TypeError):
            return {"_error": "invalid RDAP JSON"}
        return {
            "handle": data.get("handle"),
            "name": data.get("name"),
            "country": data.get("country"),
            "startAddress": data.get("startAddress"),
            "endAddress": data.get("endAddress"),
            "parentHandle": data.get("parentHandle"),
            "asn": _extract_asn(data),
        }


def _extract_asn(data: dict[str, Any]) -> str | None:
    """Extract an autnum like ``AS13335`` from RDAP entities if present."""

    for entity in data.get("entities", []):
        handle = entity.get("handle", "")
        if handle.upper().startswith("AS"):
            return handle.upper()
    return None
