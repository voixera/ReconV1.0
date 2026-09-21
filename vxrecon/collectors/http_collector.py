"""HTTP behaviour collector.

Performs a *single* polite GET (following redirects) and records the response
behaviour: status, redirect chain, headers, cookies, body size and the HTML
body (bounded). Everything goes through the gateway, so ``--offline``,
timeouts, rate limiting and the User-Agent are all enforced.

We deliberately do NOT: send POST, probe paths, brute-force directories, or
follow links. One request to the target URL, nothing more.
"""

from __future__ import annotations

from typing import Any

from vxrecon.collectors.base import BaseCollector
from vxrecon.utils import net
from vxrecon.utils.http_parse import normalize_headers, parse_cookies
from vxrecon.utils.validators import normalize_url


class HttpCollector(BaseCollector):
    """Collect HTTP response behaviour for a URL."""

    name = "http"
    requires_network = True
    provides = ("http",)

    def collect(self, target: str) -> dict[str, Any]:
        url = normalize_url(target)
        if not url.lower().startswith(("http://", "https://")):
            return self._error(f"not a valid URL: {target!r}")

        response = net.http_get(url, self.ctx, allow_redirects=True)
        if response.error and response.status is None:
            return self._error(response.error)

        headers = normalize_headers(response.headers)
        # urllib merges duplicate headers; collect raw Set-Cookie where present.
        raw_set_cookie = [
            v for k, v in response.headers.items() if k.lower() == "set-cookie"
        ]
        cookies = parse_cookies(raw_set_cookie)

        body_text = ""
        if response.content_type and "html" in response.content_type.lower():
            body_text = response.text

        return {
            "target": url,
            "status": response.status,
            "reason": response.reason,
            "final_url": response.final_url or url,
            "redirected": (response.final_url or url) != url,
            "redirect_chain": response.redirect_chain,
            "headers": headers,
            "cookies": cookies,
            "content_type": response.content_type,
            "content_length": len(response.body),
            "elapsed_ms": response.elapsed_ms,
            "http_version": response.http_version,
            "html": body_text,
            "error": response.error,
        }
