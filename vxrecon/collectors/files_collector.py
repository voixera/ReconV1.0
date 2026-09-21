"""Public file exposure collector (feature 9).

Fetches only resources a site *publicly references or exposes by convention*:
``robots.txt`` and ``sitemap.xml``. It does NOT brute-force directories, probe
hidden paths, or attempt path traversal. If robots.txt points at sitemaps via
``Sitemap:`` directives, those public, declared sitemaps are followed (bounded).

Everything goes through the gateway (offline-aware, rate-limited, timeout).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from vxrecon.collectors.base import BaseCollector
from vxrecon.utils import net
from vxrecon.utils.validators import normalize_url

MAX_SITEMAPS = 5
_SITEMAP_REF = re.compile(r"(?im)^\s*sitemap:\s*(\S+)\s*$")


class PublicFilesCollector(BaseCollector):
    """Fetch robots.txt and declared sitemaps."""

    name = "files"
    requires_network = True
    provides = ("robots", "sitemap")

    def collect(self, target: str) -> dict[str, Any]:
        url = normalize_url(target)
        parsed = urlparse(url)
        if not parsed.hostname:
            return self._error(f"not a valid URL: {target!r}")
        origin = f"{parsed.scheme}://{parsed.netloc}"

        robots_url = urljoin(origin + "/", "robots.txt")
        robots_response = net.http_get(robots_url, self.ctx, max_bytes=200_000)

        robots: dict[str, Any] = {
            "url": robots_url,
            "status": robots_response.status,
            "present": robots_response.ok and "html" not in (robots_response.content_type or ""),
        }
        sitemap_urls: list[str] = []
        if robots["present"]:
            text = robots_response.text
            robots["text"] = text[:50_000]
            sitemap_urls = [m.strip() for m in _SITEMAP_REF.findall(text)]
        else:
            robots["error"] = robots_response.error or f"HTTP {robots_response.status}"

        # Always consider the conventional sitemap.xml, plus any declared ones.
        candidates = [urljoin(origin + "/", "sitemap.xml")] + sitemap_urls
        sitemaps: list[dict[str, Any]] = []
        seen: set[str] = set()
        for sm_url in candidates[:MAX_SITEMAPS]:
            if sm_url in seen:
                continue
            seen.add(sm_url)
            response = net.http_get(sm_url, self.ctx, max_bytes=500_000)
            sitemaps.append(
                {
                    "url": sm_url,
                    "status": response.status,
                    "present": response.ok,
                    "content_type": response.content_type,
                    "text": response.text[:100_000] if response.ok else "",
                    "error": None if response.ok else (response.error or f"HTTP {response.status}"),
                }
            )
        return {"target": url, "robots": robots, "sitemaps": sitemaps}
