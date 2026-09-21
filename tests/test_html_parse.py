"""Tests for the stdlib HTML parser helpers (offline)."""

from __future__ import annotations

from vxrecon.utils.html_parse import html_skeleton, parse_page


SAMPLE = """
<html>
<head>
  <title>My App</title>
  <meta name="generator" content="WordPress 6.4">
  <meta property="og:title" content="Hi">
  <link rel="stylesheet" href="https://cdn.example.com/bootstrap.min.css">
  <link rel="icon" href="/favicon.ico">
  <script src="/static/react.production.min.js"></script>
  <script src="/_next/static/chunks/main.js"></script>
</head>
<body data-reactroot id="__next">
  <div class="flex items-center justify-between">Hello</div>
  <a href="/about">About</a>
  <form action="/login" method="post"></form>
</body>
</html>
"""


def test_parse_page_extracts_title_and_generator() -> None:
    facts = parse_page(SAMPLE)
    assert facts.title == "My App"
    assert facts.generator == "WordPress 6.4"


def test_parse_page_extracts_scripts_and_styles() -> None:
    facts = parse_page(SAMPLE)
    assert any("react" in s for s in facts.scripts)
    assert any("_next" in s for s in facts.scripts)
    assert any("bootstrap" in s for s in facts.stylesheets)


def test_parse_page_extracts_links_and_forms() -> None:
    facts = parse_page(SAMPLE)
    assert "/about" in facts.links
    assert facts.forms and facts.forms[0]["method"] == "post"


def test_parse_page_extracts_favicon_hint() -> None:
    facts = parse_page(SAMPLE)
    assert "/favicon.ico" in facts.favicon_hints


def test_parse_page_captures_framework_attrs() -> None:
    facts = parse_page(SAMPLE)
    joined = " ".join(facts.html_attrs)
    assert "data-reactroot" in joined
    assert "id" in joined or "__next" in joined or "class=" in joined


def test_parse_page_handles_malformed_html() -> None:
    facts = parse_page("<html><title>Broken<div><span></html>")
    assert facts.title == "Broken"


def test_html_skeleton_is_stable_over_text() -> None:
    a = html_skeleton("<div class='x'>Hello</div>")
    b = html_skeleton("<div class='y'>World</div>")
    # Skeleton keeps tag + attribute keys, not values.
    assert a == b
