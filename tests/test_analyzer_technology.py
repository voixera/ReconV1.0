"""Tests for the Technology Confidence Engine (offline)."""

from __future__ import annotations

from vxrecon.analyzers.technology import TechnologyAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence


def _raw(headers=None, cookies=None, html="") -> dict:
    return {
        "http": {
            "target": "https://example.com",
            "headers": headers or {},
            "cookies": cookies or [],
            "html": html,
            "content_type": "text/html",
        }
    }


def _tech(result, name_slug: str):
    key = f"tech.{name_slug}"
    return next((f for f in result.findings if f.key == key), None)


def test_detects_cloudflare_high_confidence() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw(headers={"cf-ray": "abc", "server": "cloudflare"})
    result = TechnologyAnalyzer(ctx).analyze("x", raw, ctx)
    finding = _tech(result, "cloudflare")
    assert finding is not None
    assert finding.confidence is Confidence.HIGH
    assert finding.evidence


def test_detects_nginx_from_server_header() -> None:
    ctx = RunContext(quiet=True)
    result = TechnologyAnalyzer(ctx).analyze("x", _raw(headers={"server": "nginx/1.25"}), ctx)
    assert _tech(result, "nginx") is not None


def test_detects_wordpress_from_generator_and_paths() -> None:
    ctx = RunContext(quiet=True)
    html = '<meta name="generator" content="WordPress 6.4"><link href="/wp-content/x.css">'
    result = TechnologyAnalyzer(ctx).analyze("x", _raw(html=html), ctx)
    wp = _tech(result, "wordpress")
    assert wp is not None
    assert len(wp.evidence) >= 2


def test_detects_nextjs_from_next_data() -> None:
    ctx = RunContext(quiet=True)
    html = '<script id="__NEXT_DATA__" type="application/json">{}</script>'
    result = TechnologyAnalyzer(ctx).analyze("x", _raw(html=html), ctx)
    assert _tech(result, "next_js") is not None


def test_detects_php_from_cookie() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw(cookies=[{"name": "PHPSESSID", "value": "x", "attrs": ""}])
    result = TechnologyAnalyzer(ctx).analyze("x", raw, ctx)
    assert _tech(result, "php") is not None


def test_no_detection_without_evidence() -> None:
    ctx = RunContext(quiet=True)
    result = TechnologyAnalyzer(ctx).analyze("x", _raw(headers={"x-custom": "1"}), ctx)
    # Nothing should be asserted without a matching rule.
    assert all(f.evidence for f in result.findings)
