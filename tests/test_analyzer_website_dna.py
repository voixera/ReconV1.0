"""Tests for the Website DNA analyzer (offline)."""

from __future__ import annotations

from vxrecon.analyzers.website_dna import WebsiteDnaAnalyzer, _title_pattern
from vxrecon.core.context import RunContext


def _raw(html: str, headers=None) -> dict:
    return {
        "http": {
            "target": "https://example.com",
            "headers": headers or {},
            "cookies": [],
            "html": html,
            "content_type": "text/html",
            "http_dna": None,
        }
    }


def test_dna_fingerprint_is_deterministic() -> None:
    ctx = RunContext(quiet=True)
    html = "<html><head><title>App</title></head><body>x</body></html>"
    a = WebsiteDnaAnalyzer(ctx).analyze("x", _raw(html), ctx)
    b = WebsiteDnaAnalyzer(ctx).analyze("x", _raw(html), ctx)
    da = next(f.value for f in a.findings if f.key == "dna.fingerprint")
    db = next(f.value for f in b.findings if f.key == "dna.fingerprint")
    assert da == db


def test_dna_differs_across_structure() -> None:
    ctx = RunContext(quiet=True)
    a = WebsiteDnaAnalyzer(ctx).analyze("x", _raw("<html><body><div></div></body></html>"), ctx)
    b = WebsiteDnaAnalyzer(ctx).analyze("x", _raw("<html><body><section><p></p></section></body></html>"), ctx)
    da = next(f.value for f in a.findings if f.key == "dna.fingerprint")
    db = next(f.value for f in b.findings if f.key == "dna.fingerprint")
    assert da != db


def test_dna_captures_title_and_generator() -> None:
    ctx = RunContext(quiet=True)
    html = '<head><title>Shop</title><meta name="generator" content="Shopify"></head>'
    result = WebsiteDnaAnalyzer(ctx).analyze("x", _raw(html), ctx)
    keys = {f.key for f in result.findings}
    assert "dna.title" in keys
    assert "dna.generator" in keys


def test_title_pattern_coarsens() -> None:
    assert _title_pattern("My App 2") == "w w 0"
    assert _title_pattern("") == ""


def test_dna_handles_missing_http() -> None:
    ctx = RunContext(quiet=True)
    result = WebsiteDnaAnalyzer(ctx).analyze("x", {}, ctx)
    assert result.errors
