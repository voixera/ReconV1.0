"""Certificate Transparency subdomain collector (feature: passive discovery).

Uses the public crt.sh JSON interface to enumerate names that appear in
Certificate Transparency logs for a domain. **No API key, no account.**

This is purely passive: CT logs are public append-only records that CAs submit
to by design. We only read them.

Design notes:

* We never brute-force subdomains. Discovery is limited to names that already
  exist in public CT data.
* Results are de-duplicated and filtered to the registrable domain to avoid
  pulling in unrelated names.
* Every name carries the source (``ct:crt.sh``) and the certificate IDs it was
  seen in, so it can be evidenced in reports.
"""

from __future__ import annotations

import json
import time
from typing import Any

from vxrecon.collectors.base import BaseCollector
from vxrecon.utils import net
from vxrecon.utils.validators import host_from_target, is_domain

# crt.sh is the canonical free CT interface. It is frequently overloaded and
# returns 502/503/429 under load; we retry a bounded number of times with
# backoff and fail soft if it stays unavailable.
CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# Cap the number of names we retain, to keep reports readable and to avoid
# excessive downstream work. This is a *passive* cap, not a scan limit.
MAX_NAMES = 500
MAX_CERTS = 500
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 3


class CtSubdomainCollector(BaseCollector):
    """Enumerate subdomains from public Certificate Transparency logs."""

    name = "ct"
    requires_network = True
    provides = ("subdomains",)

    def collect(self, target: str) -> dict[str, Any]:
        domain = host_from_target(target).lower()
        if not is_domain(domain):
            return self._error(f"not a valid domain: {target!r}")

        url = CRT_SH_URL.format(domain=domain)
        response = self._fetch_with_retry(url)
        if response is None:
            return {
                "target": domain,
                "source": "ct:crt.sh",
                "_error": "certificate transparency service unavailable (crt.sh)",
            }

        try:
            rows = json.loads(response.text)
        except (ValueError, TypeError):
            return {"target": domain, "source": "ct:crt.sh", "_error": "invalid CT JSON"}
        if not isinstance(rows, list):
            return {"target": domain, "source": "ct:crt.sh", "_error": "unexpected CT response"}

        names: dict[str, list[int]] = {}
        cert_count = 0
        for row in rows[:MAX_CERTS]:
            cert_count += 1
            cert_id = row.get("id")
            for raw_name in str(row.get("name_value", "")).splitlines():
                for name in _candidate_names(raw_name, domain):
                    names.setdefault(name, [])
                    if cert_id is not None and cert_id not in names[name]:
                        names[name].append(cert_id)

        trimmed = dict(sorted(names.items())[:MAX_NAMES])
        return {
            "target": domain,
            "source": "ct:crt.sh",
            "certificates_seen": cert_count,
            "subdomains": [{"name": n, "cert_ids": ids} for n, ids in trimmed.items()],
            "total_found": len(names),
        }

    def _fetch_with_retry(self, url: str) -> net.HttpResult | None:
        """Fetch with bounded exponential backoff for transient CT outages."""

        for attempt in range(MAX_ATTEMPTS):
            response = net.http_get(
                url, self.ctx, headers={"Accept": "application/json"}, max_bytes=5_000_000
            )
            if response.ok:
                return response
            if response.status in RETRYABLE_STATUS and attempt < MAX_ATTEMPTS - 1:
                time.sleep(1.5 * (attempt + 1))
                continue
            # Non-retryable or final attempt.
            if response.status in RETRYABLE_STATUS:
                return None
            return response if response.status else None
        return None


def _candidate_names(raw_name: str, domain: str) -> list[str]:
    """Normalize, validate and filter a raw CT name to the target domain."""

    name = raw_name.strip().lower().lstrip("*.")
    if not name or not is_domain(name):
        return []
    # Keep only names within the registrable domain.
    if name == domain or name.endswith("." + domain):
        return [name]
    return []
