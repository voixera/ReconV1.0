"""Tests for Phase 4 analyzers: subdomains, JS endpoints, source maps, files."""

from __future__ import annotations

from vxrecon.analyzers.files_analyzer import PublicFilesAnalyzer
from vxrecon.analyzers.js_endpoint import JsEndpointAnalyzer
from vxrecon.analyzers.sourcemap import SourceMapAnalyzer
from vxrecon.analyzers.subdomain_analyzer import SubdomainAnalyzer
from vxrecon.core.context import RunContext


# -- subdomains -------------------------------------------------------------


def test_subdomain_analyzer_reports_names_with_evidence() -> None:
    ctx = RunContext(quiet=True)
    raw = {
        "ct": {
            "source": "ct:crt.sh",
            "subdomains": [
                {"name": "www.example.com", "cert_ids": [1, 2]},
                {"name": "api.example.com", "cert_ids": [3]},
            ],
        }
    }
    result = SubdomainAnalyzer(ctx).analyze("example.com", raw, ctx)
    names = [f.value for f in result.findings if f.key == "subdomains.name"]
    assert "www.example.com" in names
    assert all(f.evidence for f in result.findings)


def test_subdomain_analyzer_handles_ct_outage() -> None:
    # A CT outage is an availability condition, not a scan failure: it becomes
    # an informational finding so the overall scan stays OK.
    ctx = RunContext(quiet=True)
    result = SubdomainAnalyzer(ctx).analyze("x", {"ct": {"_error": "crt.sh unavailable"}}, ctx)
    assert result.errors == []
    assert any(f.key == "subdomains.unavailable" for f in result.findings)


# -- js endpoints -----------------------------------------------------------


def _js_raw(code: str) -> dict:
    return {"javascript": {"scripts": [{"url": "https://example.com/app.js", "code": code}]}}


def test_js_endpoint_extracts_api_paths() -> None:
    ctx = RunContext(quiet=True)
    code = 'fetch("/api/v1/users"); var u = "https://api.example.com/graphql";'
    result = JsEndpointAnalyzer(ctx).analyze("x", _js_raw(code), ctx)
    keys = {f.key for f in result.findings}
    assert "js.path" in keys or "js.api_path" in keys
    assert "js.url" in keys


def test_js_endpoint_notes_not_contacted() -> None:
    ctx = RunContext(quiet=True)
    result = JsEndpointAnalyzer(ctx).analyze("x", _js_raw('var x="/api/x";'), ctx)
    url_findings = [f for f in result.findings if f.key.startswith("js.")]
    assert any("not contacted" in e for f in url_findings for e in f.evidence)


def test_js_endpoint_ignores_schema_org() -> None:
    ctx = RunContext(quiet=True)
    code = 'var a = "https://schema.org/Thing";'
    result = JsEndpointAnalyzer(ctx).analyze("x", _js_raw(code), ctx)
    urls = [f.value for f in result.findings if f.key == "js.url"]
    assert not any("schema.org" in u for u in urls)


# -- source maps ------------------------------------------------------------


def test_sourcemap_detects_reference_offline() -> None:
    ctx = RunContext(quiet=True, offline=True)
    code = "//# sourceMappingURL=app.js.map"
    result = SourceMapAnalyzer(ctx).analyze("x", _js_raw(code), ctx)
    refs = [f for f in result.findings if f.key == "sourcemap.reference"]
    assert refs
    availability = [f for f in result.findings if f.key == "sourcemap.availability"]
    assert availability and "offline" in str(availability[0].value)


def test_sourcemap_reports_none_when_absent() -> None:
    ctx = RunContext(quiet=True)
    result = SourceMapAnalyzer(ctx).analyze("x", _js_raw("var a = 1;"), ctx)
    none = next(f for f in result.findings if f.key == "sourcemap.references")
    assert none.value == 0


# -- public files -----------------------------------------------------------


def _files_raw(robots_text: str = "", sitemap_text: str = "") -> dict:
    return {
        "files": {
            "robots": {
                "url": "https://example.com/robots.txt",
                "present": bool(robots_text),
                "status": 200 if robots_text else 404,
                "text": robots_text,
            },
            "sitemaps": [
                {
                    "url": "https://example.com/sitemap.xml",
                    "present": bool(sitemap_text),
                    "status": 200 if sitemap_text else 404,
                    "text": sitemap_text,
                }
            ],
        }
    }


def test_files_analyzer_parses_robots_disallow() -> None:
    ctx = RunContext(quiet=True)
    raw = _files_raw(robots_text="User-agent: *\nDisallow: /admin\nDisallow: /private\n")
    result = PublicFilesAnalyzer(ctx).analyze("x", raw, ctx)
    disallows = sorted(f.value for f in result.findings if f.key == "files.disallow")
    assert disallows == ["/admin", "/private"]


def test_files_analyzer_parses_sitemap_locs() -> None:
    ctx = RunContext(quiet=True)
    sitemap = "<urlset><url><loc>https://example.com/a</loc></url><url><loc>https://example.com/b</loc></url></urlset>"
    result = PublicFilesAnalyzer(ctx).analyze("x", _files_raw(sitemap_text=sitemap), ctx)
    urls = [f.value for f in result.findings if f.key == "files.sitemap_url"]
    assert "https://example.com/a" in urls
    assert "https://example.com/b" in urls


def test_files_analyzer_detects_sitemap_index() -> None:
    ctx = RunContext(quiet=True)
    index = "<sitemapindex><sitemap><loc>https://example.com/s1.xml</loc></sitemap></sitemapindex>"
    result = PublicFilesAnalyzer(ctx).analyze("x", _files_raw(sitemap_text=index), ctx)
    sitemap = next(f for f in result.findings if f.key == "files.sitemap")
    assert any("index" in e for e in sitemap.evidence)
