"""JavaScript collector (feature 10 foundation).

Downloads *public* JavaScript files referenced by a page and returns them for
offline analysis. It only fetches scripts that the page itself references
(``<script src>``), never inventing paths or probing directories.

Bounded by ``MAX_SCRIPTS`` and a per-file size cap so a scan stays polite.
All fetching goes through the gateway.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

from vxrecon.collectors.base import BaseCollector
from vxrecon.utils import net
from vxrecon.utils.html_parse import parse_page
from vxrecon.utils.validators import normalize_url

MAX_SCRIPTS = 10
MAX_JS_BYTES = 1_000_000


class JavaScriptCollector(BaseCollector):
    """Fetch page-referenced JavaScript files for offline analysis."""

    name = "javascript"
    requires_network = True
    provides = ("javascript",)

    def collect(self, target: str) -> dict[str, Any]:
        url = normalize_url(target)

        # If the caller already fetched HTML (http collector), reuse it via the
        # pipeline? We cannot depend on that here, so we fetch the page once.
        page = net.http_get(url, self.ctx)
        if page.error and page.status is None:
            return self._error(page.error)
        if "html" not in (page.content_type or "").lower():
            return {"target": url, "scripts": [], "note": "target is not HTML"}

        facts = parse_page(page.text)
        sources = _resolve_script_sources(facts.scripts, page.final_url or url)

        scripts: list[dict[str, Any]] = []
        for src in sources[:MAX_SCRIPTS]:
            host = urlparse(src).hostname or "default"
            if host != (urlparse(url).hostname or ""):
                # Same-origin only: avoid pulling third-party scripts.
                continue
            response = net.http_get(src, self.ctx, max_bytes=MAX_JS_BYTES)
            if not response.ok:
                scripts.append({"url": src, "_error": response.error or f"HTTP {response.status}"})
                continue
            scripts.append(
                {
                    "url": src,
                    "bytes": len(response.body),
                    "content_type": response.content_type,
                    "code": response.text,
                }
            )
        return {"target": url, "scripts": scripts}


def _resolve_script_sources(sources: list[str], base: str) -> list[str]:
    resolved: list[str] = []
    seen: set[str] = set()
    for src in sources:
        if src.startswith(("data:", "javascript:")):
            continue
        absolute = urljoin(base, src)
        if absolute not in seen:
            seen.add(absolute)
            resolved.append(absolute)
    return resolved
