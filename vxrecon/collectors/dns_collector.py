"""DNS collector.

Gathers DNS records for a domain using the system resolver (and dnspython when
available for MX/TXT/NS/SOA/CAA). This is pure read-only DNS: no zone transfer
attempts, no AXFR, nothing that could be considered intrusive.
"""

from __future__ import annotations

from typing import Any

from vxrecon.collectors.base import BaseCollector
from vxrecon.utils import dns_util
from vxrecon.utils.validators import host_from_target, is_domain


class DnsCollector(BaseCollector):
    """Collect A/AAAA/MX/NS/TXT/CAA/SOA records for a hostname."""

    name = "dns"
    requires_network = True
    provides = ("dns",)

    def collect(self, target: str) -> dict[str, Any]:
        host = host_from_target(target)
        if not is_domain(host):
            return self._error(f"not a valid domain: {target!r}")

        result = dns_util.query(host, timeout=self.ctx.timeout)
        payload: dict[str, Any] = {
            "target": host,
            "records": [r.__dict__ for r in result.records],
            "errors": result.errors,
            "backend": result.backend,
            "dnspython": dns_util.dnspython_available(),
        }
        if not result.records and result.errors:
            payload["_error"] = "no DNS records resolved"
        return payload
