"""Website DNA analyzer (feature 3).

Builds a layered fingerprint of a website from HTML structure, meta tags,
generator hints, script/CSS references, framework markers and the HTTP DNA.
The result is a compact, reproducible "DNA" hash plus the component signals.

Important: the DNA describes *the page as served*. It is a similarity hint.
Two sites sharing a DNA are not asserted to share an owner.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult
from vxrecon.utils.html_parse import html_skeleton, parse_page

# Ordered categories displayed in the DNA summary.
_DNA_LABELS = ("frontend", "framework", "server", "cdn", "cms")


class WebsiteDnaAnalyzer(BaseAnalyzer):
    """Produce a Website DNA fingerprint and layer breakdown."""

    name = "website_dna"
    consumes = ("http", "technology")

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        data = raw.get("http")
        if not data or data.get("_error"):
            result.errors.append("no HTTP data for DNA analysis")
            return result

        html = data.get("html", "") or ""
        facts = parse_page(html) if html else None

        components: dict[str, Any] = {}
        if facts:
            self._add_html_signals(result, facts)
            components["title_pattern"] = _title_pattern(facts.title)
            components["meta_keys"] = sorted(facts.meta.keys())
            components["generator"] = facts.generator
            components["script_hosts"] = _hosts(facts.scripts)
            components["style_hosts"] = _hosts(facts.stylesheets)
            components["skeleton_hash"] = hashlib.sha256(
                html_skeleton(html).encode("utf-8")
            ).hexdigest()

        components["http_dna"] = data.get("http_dna") or _http_dna_from(data)
        components["content_type"] = (data.get("content_type") or "").split(";")[0].strip().lower()

        # Detect a favicon hint for later phases (feature 4 links here).
        if facts and facts.favicon_hints:
            result.add_finding(
                Finding(
                    key="dna.favicon_hint",
                    value=facts.favicon_hints,
                    confidence=Confidence.MEDIUM,
                    evidence=[f"favicon reference: {h}" for h in facts.favicon_hints],
                )
            )

        dna = hashlib.sha256(
            json.dumps(components, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()

        result.add_finding(
            Finding(
                key="dna.fingerprint",
                value=dna,
                confidence=Confidence.MEDIUM,
                evidence=[
                    "Website DNA = hash(html skeleton, title pattern, meta keys, "
                    "script/style hosts, http dna, content type)",
                    f"DNA: {dna}",
                ],
            )
        )
        result.artifacts["website_dna"] = dna
        result.artifacts["dna_components"] = components
        return result

    # -- HTML signals ----------------------------------------------------

    def _add_html_signals(self, result: ScanResult, facts) -> None:
        if facts.title:
            result.add_finding(
                Finding(
                    key="dna.title",
                    value=facts.title,
                    confidence=Confidence.HIGH,
                    evidence=[f"<title>: {facts.title}"],
                )
            )
        if facts.generator:
            result.add_finding(
                Finding(
                    key="dna.generator",
                    value=facts.generator,
                    confidence=Confidence.HIGH,
                    evidence=[f'meta generator: "{facts.generator}"'],
                )
            )
        if facts.scripts:
            result.add_finding(
                Finding(
                    key="dna.script_count",
                    value=len(facts.scripts),
                    confidence=Confidence.HIGH,
                    evidence=[f"{len(facts.scripts)} external script reference(s)"],
                )
            )
        if facts.stylesheets:
            result.add_finding(
                Finding(
                    key="dna.stylesheet_count",
                    value=len(facts.stylesheets),
                    confidence=Confidence.HIGH,
                    evidence=[f"{len(facts.stylesheets)} stylesheet reference(s)"],
                )
            )


def _hosts(urls: list[str]) -> list[str]:
    """Return unique hosts from a list of URLs, sorted."""

    from urllib.parse import urlparse

    hosts: set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname:
            hosts.add(parsed.hostname)
    return sorted(hosts)


def _title_pattern(title: str) -> str:
    """Coarsen a title into a structural pattern.

    Letters become ``w`` and digit runs become ``0`` (a non-letter marker, so
    the letter pass does not consume it), preserving word/segment structure.
    """

    if not title:
        return ""
    digits_replaced = re.sub(r"\d+", "0", title)
    return re.sub(r"[A-Za-z]+", "w", digits_replaced).strip()


def _http_dna_from(data: dict[str, Any]) -> str:
    """Fallback HTTP DNA if the http analyzer did not provide one."""

    from vxrecon.utils.http_parse import header_fingerprint

    return header_fingerprint(data.get("headers", {}))
