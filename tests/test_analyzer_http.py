"""Tests for the HTTP behaviour analyzer (offline, synthetic facts)."""

from __future__ import annotations

from vxrecon.analyzers.http_analyzer import HttpAnalyzer
from vxrecon.core.context import RunContext


def _raw(**overrides) -> dict:
    base = {
        "http": {
            "target": "https://example.com",
            "status": 200,
            "reason": "OK",
            "final_url": "https://example.com/",
            "redirected": False,
            "redirect_chain": [],
            "headers": {"server": "nginx", "content-type": "text/html; charset=utf-8"},
            "cookies": [{"name": "session", "value": "abc", "attrs": "session=abc; Path=/"}],
            "content_type": "text/html; charset=utf-8",
            "content_length": 1234,
            "http_version": "HTTP/1.1",
            "html": "<html></html>",
            "error": None,
        }
    }
    base["http"].update(overrides)
    return base


def test_http_analyzer_basic_findings() -> None:
    ctx = RunContext(quiet=True)
    result = HttpAnalyzer(ctx).analyze("https://example.com", _raw(), ctx)
    keys = {f.key for f in result.findings}
    assert "http.status" in keys
    assert "http.content_type" in keys
    assert "http.version" in keys
    assert "http.dna" in keys


def test_http_analyzer_records_redirect_chain() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw(redirect_chain=["https://example.com/a", "https://example.com/b"])
    result = HttpAnalyzer(ctx).analyze("https://example.com", raw, ctx)
    chain = next(f for f in result.findings if f.key == "http.redirect_chain")
    assert len(chain.value) == 2


def test_http_analyzer_flags_missing_security_headers() -> None:
    ctx = RunContext(quiet=True)
    result = HttpAnalyzer(ctx).analyze("https://example.com", _raw(), ctx)
    missing = [f.key for f in result.findings if f.key.startswith("http.security_missing.")]
    assert "http.security_missing.hsts" in missing


def test_http_analyzer_detects_present_security_header() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw(headers={"strict-transport-security": "max-age=63072000"}, content_type="text/html")
    result = HttpAnalyzer(ctx).analyze("https://example.com", raw, ctx)
    present = [f.key for f in result.findings if f.key == "http.security.hsts"]
    assert present


def test_http_dna_is_stable_across_value_changes() -> None:
    ctx = RunContext(quiet=True)
    a = HttpAnalyzer(ctx).analyze("x", _raw(headers={"server": "nginx"}), ctx)
    b = HttpAnalyzer(ctx).analyze("x", _raw(headers={"server": "nginx"}), ctx)
    da = next(f.value for f in a.findings if f.key == "http.dna")
    db = next(f.value for f in b.findings if f.key == "http.dna")
    assert da == db


def test_http_analyzer_handles_missing_data() -> None:
    ctx = RunContext(quiet=True)
    result = HttpAnalyzer(ctx).analyze("x", {}, ctx)
    assert result.errors
