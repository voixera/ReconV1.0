"""Technology Confidence Engine (feature 13).

Detects technologies from HTTP response data using the JSON rules in
``signatures/technologies.json``. The critical design rule: **every detection
carries evidence**. A match does not prove ownership or certainty; it
contributes a weight that maps to a confidence level:

    score >= 2.0  -> HIGH
    score >= 1.0  -> MEDIUM
    score >  0.0  -> LOW

The engine is a pure function over the collected HTTP facts (headers, cookies,
HTML, meta tags, script/link references). It never performs I/O.
"""

from __future__ import annotations

import re
from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult
from vxrecon.signatures import technologies as load_techs
from vxrecon.utils.html_parse import PageFacts, parse_page


class TechnologyAnalyzer(BaseAnalyzer):
    """Detect technologies with weighted, evidence-backed confidence."""

    name = "technology"
    consumes = ("http",)

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        data = raw.get("http")
        if not data or data.get("_error"):
            result.errors.append("no HTTP data for technology detection")
            return result

        headers = data.get("headers", {})
        cookies = data.get("cookies", [])
        html = data.get("html", "") or ""
        facts = parse_page(html) if html else PageFacts()

        page = _PageContext(headers=headers, cookies=cookies, html=html, facts=facts)

        for tech in load_techs():
            score = 0.0
            evidence: list[str] = []
            for rule in tech.get("rules", []):
                matched, note = self._match_rule(rule, page)
                if matched:
                    score += float(rule.get("weight", 0.5))
                    evidence.append(note or rule.get("note", "match"))
            if score > 0:
                confidence = _score_to_confidence(score)
                result.add_finding(
                    Finding(
                        key=f"tech.{_slug(tech['name'])}",
                        value={"name": tech["name"], "category": tech.get("category", "unknown")},
                        confidence=confidence,
                        evidence=evidence + [f"weighted score: {score:.1f}"],
                    )
                )
        return result

    # -- rule matching ---------------------------------------------------

    def _match_rule(self, rule: dict[str, Any], page: "_PageContext") -> tuple[bool, str | None]:
        rtype = rule.get("type")
        pattern = rule.get("pattern", "")
        note = rule.get("note")

        if rtype == "header":
            return self._match_header(rule, page)
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return False, None

        if rtype == "header_value":
            for value in page.headers.values():
                if regex.search(value):
                    return True, note
            return False, None
        if rtype == "cookie":
            for cookie in page.cookies:
                if regex.search(cookie.get("name", "")):
                    return True, note
            return False, None
        if rtype == "meta":
            joined = " ".join(f'{k}"{v}' for k, v in page.facts.meta.items())
            return (True, note) if regex.search(joined) else (False, None)
        if rtype == "script":
            for src in page.facts.scripts:
                if regex.search(src):
                    return True, note
            return False, None
        if rtype == "link":
            for href in page.facts.stylesheets:
                if regex.search(href):
                    return True, note
            return False, None
        if rtype == "html_attr":
            joined = " ".join(page.facts.html_attrs)
            return (True, note) if regex.search(joined) else (False, None)
        if rtype == "path":
            haystack = page.html + " " + " ".join(page.facts.scripts + page.facts.stylesheets)
            return (True, note) if regex.search(haystack) else (False, None)
        if rtype == "title":
            return (True, note) if regex.search(page.facts.title) else (False, None)
        if rtype == "body":
            return (True, note) if regex.search(page.html) else (False, None)
        return False, None

    def _match_header(self, rule: dict[str, Any], page: "_PageContext") -> tuple[bool, str | None]:
        name = rule.get("pattern", "").lower()
        note = rule.get("note")
        if name not in page.headers:
            return False, None
        value_pattern = rule.get("value_pattern")
        if value_pattern:
            try:
                if not re.search(value_pattern, page.headers[name], re.IGNORECASE):
                    return False, None
            except re.error:
                return False, None
        return True, note


class _PageContext:
    """Bundles the HTTP facts the rule engine matches against."""

    def __init__(self, headers: dict, cookies: list, html: str, facts: PageFacts) -> None:
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.cookies = cookies
        self.html = html
        self.facts = facts


def _score_to_confidence(score: float) -> Confidence:
    if score >= 2.0:
        return Confidence.HIGH
    if score >= 1.0:
        return Confidence.MEDIUM
    return Confidence.LOW


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
