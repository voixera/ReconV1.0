"""Tests for Phase 8: HTML report, graph HTML and timeline HTML (offline)."""

from __future__ import annotations

from vxrecon.core.context import RunContext
from vxrecon.reporters.graph_html import render_graph_html, render_timeline_html
from vxrecon.reporters.html_report import HtmlReporter


def _payload() -> dict:
    return {
        "target": "example.com",
        "action": "recon",
        "results": [
            {
                "module": "dns",
                "findings": [
                    {
                        "key": "dns.a",
                        "value": "1.2.3.4",
                        "confidence": "HIGH",
                        "evidence": ["A record"],
                        "evidence_ref": {
                            "sha256": "abc123",
                            "source_url": "https://example.com",
                            "http_status": 200,
                            "content_type": "text/html",
                            "acquired_at": "2026-01-01T00:00:00Z",
                        },
                    }
                ],
                "errors": [],
            }
        ],
        "graph": {
            "nodes": [
                {"kind": "domain", "value": "example.com", "label": "example.com"},
                {"kind": "ip", "value": "1.2.3.4", "label": "1.2.3.4"},
            ],
            "edges": [
                {
                    "src_kind": "domain",
                    "src_value": "example.com",
                    "dst_kind": "ip",
                    "dst_value": "1.2.3.4",
                    "relation": "resolves_to",
                    "confidence": "HIGH",
                }
            ],
        },
    }


def test_html_report_is_self_contained() -> None:
    ctx = RunContext(quiet=True)
    html = HtmlReporter(ctx).render(_payload())
    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html
    assert "http://" not in html.split("<style>")[0]  # no external refs before CSS


def test_html_report_includes_disclaimer() -> None:
    ctx = RunContext(quiet=True)
    html = HtmlReporter(ctx).render(_payload())
    assert "not ownership" in html.lower()


def test_html_report_includes_evidence_integrity() -> None:
    ctx = RunContext(quiet=True)
    html = HtmlReporter(ctx).render(_payload())
    assert "Evidence Integrity" in html
    assert "abc123" in html


def test_html_report_escapes_content() -> None:
    ctx = RunContext(quiet=True)
    payload = _payload()
    payload["results"][0]["findings"][0]["value"] = "<script>alert(1)</script>"
    html = HtmlReporter(ctx).render(payload)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_graph_html_renders_svg() -> None:
    html = render_graph_html(_payload()["graph"], "example.com")
    assert "<svg" in html
    assert "resolves_to" in html


def test_timeline_html_renders_events() -> None:
    events = [
        {"ts": "2026-01-01T00:00:00Z", "message": "scan started"},
        {"ts": "2026-01-02T00:00:00Z", "message": "dns resolved"},
    ]
    html = render_timeline_html(events, "example.com")
    assert "scan started" in html
    assert "dns resolved" in html


def test_timeline_html_empty() -> None:
    html = render_timeline_html([], "example.com")
    assert "no events recorded" in html
