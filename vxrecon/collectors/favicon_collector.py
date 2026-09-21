"""Favicon / image collector (feature 4 foundation).

Downloads the favicon a site references (``<link rel="icon">``) or the
conventional ``/favicon.ico``. Only publicly referenced assets are fetched; we
do not probe arbitrary paths.

The bytes are returned for hashing/analysis. Evidence integrity (SHA-256, size,
content type, source URL) is attached by the collector so the fingerprint can be
traced back to its origin.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from vxrecon.collectors.base import BaseCollector
from vxrecon.utils import net
from vxrecon.utils.html_parse import parse_page
from vxrecon.utils.validators import normalize_url

MAX_ICON_BYTES = 512_000


class FaviconCollector(BaseCollector):
    """Fetch a site's favicon for fingerprinting."""

    name = "favicon"
    requires_network = True
    provides = ("favicon",)

    def collect(self, target: str) -> dict[str, Any]:
        url = normalize_url(target)
        page = net.http_get(url, self.ctx, max_bytes=500_000)
        if page.error and page.status is None:
            return self._error(page.error)

        base = page.final_url or url
        candidates: list[str] = []
        if "html" in (page.content_type or "").lower():
            facts = parse_page(page.text)
            candidates = [urljoin(base, h) for h in facts.favicon_hints]
        candidates.append(urljoin(base, "/favicon.ico"))

        for candidate in candidates:
            response = net.http_get(candidate, self.ctx, max_bytes=MAX_ICON_BYTES)
            if response.ok and response.body:
                return {
                    "target": url,
                    "favicon": {
                        "source_url": candidate,
                        "status": response.status,
                        "content_type": response.content_type,
                        "bytes": response.body,
                        "size": len(response.body),
                    },
                }
        return {"target": url, "favicon": None, "note": "no favicon found"}


class LocalImageCollector(BaseCollector):
    """Wrap local image bytes for analysis (used by the ``image`` action)."""

    name = "local_image"
    requires_network = False
    provides = ("image",)

    def __init__(self, ctx, path: str | None = None) -> None:  # type: ignore[override]
        super().__init__(ctx)
        self.path = path

    def collect(self, target: str) -> dict[str, Any]:
        from pathlib import Path

        path = Path(self.path or target)
        if not path.exists() or not path.is_file():
            return self._error(f"file not found: {path}")
        try:
            data = path.read_bytes()
        except OSError as exc:
            return self._error(f"cannot read file: {exc}")
        return {
            "target": str(path),
            "image": {
                "source_url": str(path),
                "content_type": _guess_content_type(path.suffix),
                "bytes": data,
                "size": len(data),
            },
        }


def _guess_content_type(suffix: str) -> str:
    return {
        ".ico": "image/x-icon",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".svg": "image/svg+xml",
        ".bmp": "image/bmp",
    }.get(suffix.lower(), "application/octet-stream")
