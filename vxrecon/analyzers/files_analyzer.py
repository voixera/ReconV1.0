"""Public file exposure analyzer (feature 9).

Analyses robots.txt directives and sitemap contents. Reports disallowed paths,
declared sitemaps, sitemap index entries and the count/locations of URLs the
site itself publishes. Pure function: no network access.

We only report what the site *already tells the world* via robots/sitemaps.
Discovering a path here is not evidence it is sensitive; it is evidence it is
publicly referenced or disallowed.
"""

from __future__ import annotations

import re
from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult

_DISALLOW = re.compile(r"(?im)^\s*disallow:\s*(\S+)\s*$")
_ALLOW = re.compile(r"(?im)^\s*allow:\s*(\S+)\s*$")
_LOC = re.compile(r"(?i)<loc>\s*([^<\s]+)\s*</loc>")
_SITEMAPINDEX = re.compile(r"(?i)<sitemapindex")


class PublicFilesAnalyzer(BaseAnalyzer):
    """Derive exposure findings from robots.txt and sitemaps."""

    name = "files"
    consumes = ("files",)

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        data = raw.get("files")
        if not data:
            result.errors.append("no public files collected")
            return result

        self._analyze_robots(result, data.get("robots") or {})
        self._analyze_sitemaps(result, data.get("sitemaps") or [])
        return result

    def _analyze_robots(self, result: ScanResult, robots: dict[str, Any]) -> None:
        if robots.get("present"):
            result.add_finding(
                Finding(
                    key="files.robots",
                    value=robots.get("url"),
                    confidence=Confidence.HIGH,
                    evidence=[f"robots.txt present ({robots.get('url')})"],
                )
            )
            text = robots.get("text", "")
            for path in _DISALLOW.findall(text):
                result.add_finding(
                    Finding(
                        key="files.disallow",
                        value=path,
                        confidence=Confidence.HIGH,
                        evidence=[f"robots.txt Disallow: {path}"],
                    )
                )
            for path in _ALLOW.findall(text):
                result.add_finding(
                    Finding(
                        key="files.allow",
                        value=path,
                        confidence=Confidence.MEDIUM,
                        evidence=[f"robots.txt Allow: {path}"],
                    )
                )
        else:
            result.add_finding(
                Finding(
                    key="files.robots_missing",
                    value=False,
                    confidence=Confidence.LOW,
                    evidence=[f"robots.txt not present ({robots.get('error') or 'n/a'})"],
                )
            )

    def _analyze_sitemaps(self, result: ScanResult, sitemaps: list[dict[str, Any]]) -> None:
        present = [s for s in sitemaps if s.get("present")]
        if not present:
            return
        result.add_finding(
            Finding(
                key="files.sitemap_count",
                value=len(present),
                confidence=Confidence.HIGH,
                evidence=[f"{len(present)} sitemap(s) accessible"],
            )
        )
        for sitemap in present:
            text = sitemap.get("text", "")
            is_index = bool(_SITEMAPINDEX.search(text))
            locs = _LOC.findall(text)
            result.add_finding(
                Finding(
                    key="files.sitemap",
                    value=sitemap.get("url"),
                    confidence=Confidence.HIGH,
                    evidence=[
                        f"sitemap accessible ({sitemap.get('url')})",
                        f"type: {'index' if is_index else 'urlset'}",
                        f"{len(locs)} <loc> entrie(s) public",
                    ],
                )
            )
            # Report a bounded sample of published URLs.
            for loc in locs[:50]:
                result.add_finding(
                    Finding(
                        key="files.sitemap_url",
                        value=loc,
                        confidence=Confidence.MEDIUM,
                        evidence=[f"published in {sitemap.get('url')}"],
                    )
                )
