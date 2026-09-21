"""HTML parsing helpers built on the standard library.

We parse HTML with ``html.parser`` so the core has no hard dependency on
BeautifulSoup. The API exposes the bits the analyzers need: title, meta tags,
scripts, stylesheets, forms and a normalized HTML skeleton for fingerprinting.

All parsing is defensive: malformed markup must never raise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any


@dataclass
class PageFacts:
    """Structured facts extracted from an HTML document."""

    title: str = ""
    meta: dict[str, str] = field(default_factory=dict)          # name/property -> content
    generator: str = ""
    scripts: list[str] = field(default_factory=list)            # src values
    inline_script_count: int = 0
    stylesheets: list[str] = field(default_factory=list)        # href values
    links: list[str] = field(default_factory=list)              # <a href>
    forms: list[dict[str, str]] = field(default_factory=list)
    favicon_hints: list[str] = field(default_factory=list)
    html_attrs: list[str] = field(default_factory=list)         # raw attribute strings
    body_text_sample: str = ""
    generator_comment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "meta": self.meta,
            "generator": self.generator,
            "scripts": self.scripts,
            "inline_script_count": self.inline_script_count,
            "stylesheets": self.stylesheets,
            "links": self.links,
            "forms": self.forms,
            "favicon_hints": self.favicon_hints,
            "body_text_sample": self.body_text_sample[:500],
        }


class _VXParser(HTMLParser):
    """Internal HTMLParser that fills a :class:`PageFacts`."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.facts = PageFacts()
        self._in_title = False
        self._in_script = False
        self._collect_text = False
        self._text_buf: list[str] = []

    # -- tags ------------------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        # Record raw attribute strings for framework markers (data-reactroot etc.)
        for key, value in attr_map.items():
            if key.startswith(("data-", "ng-", "v-", "x-", "_ng", "@")):
                self.facts.html_attrs.append(f'{key}="{value}"')
        if "class" in attr_map and attr_map["class"]:
            self.facts.html_attrs.append(f'class="{attr_map["class"]}"')

        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            self._handle_meta(attr_map)
        elif tag == "script":
            src = attr_map.get("src")
            if src:
                self.facts.scripts.append(src)
            else:
                self._in_script = True
                self.facts.inline_script_count += 1
        elif tag == "link":
            rel = attr_map.get("rel", "").lower()
            href = attr_map.get("href", "")
            if "stylesheet" in rel and href:
                self.facts.stylesheets.append(href)
            if "icon" in rel and href:
                self.facts.favicon_hints.append(href)
        elif tag == "a":
            href = attr_map.get("href")
            if href:
                self.facts.links.append(href)
        elif tag == "form":
            self.facts.forms.append(
                {"action": attr_map.get("action", ""), "method": attr_map.get("method", "get")}
            )
        elif tag == "body":
            self._collect_text = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False
        elif tag == "body":
            self._collect_text = False

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if not text:
            return
        if self._in_title:
            self.facts.title = (self.facts.title + " " + text).strip()
        if self._collect_text and len(self.facts.body_text_sample) < 1000:
            self.facts.body_text_sample += text + " "

    def _handle_meta(self, attr_map: dict[str, str]) -> None:
        key = attr_map.get("name") or attr_map.get("property") or attr_map.get("http-equiv")
        content = attr_map.get("content", "")
        if not key:
            return
        self.facts.meta[key.lower()] = content
        if key.lower() == "generator":
            self.facts.generator = content


def parse_page(html: str, limit: int = 2_000_000) -> PageFacts:
    """Parse an HTML string into :class:`PageFacts`. Never raises."""

    parser = _VXParser()
    try:
        parser.feed(html[:limit])
        parser.close()
    except Exception:  # noqa: BLE001 - malformed HTML must not break analysis
        pass
    return parser.facts


def html_skeleton(html: str, limit: int = 400_000) -> str:
    """Return a coarse skeleton of the HTML: tags and attribute keys only.

    Used to build a stable fingerprint that is insensitive to text content and
    attribute values (so two pages of the same app share a DNA more often).
    """

    tokens: list[str] = []

    class _Skel(HTMLParser):
        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            keys = ",".join(sorted(k.lower() for k, _ in attrs))
            tokens.append(f"<{tag.lower()}[{keys}]>")

        def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self.handle_starttag(tag, attrs)

    parser = _Skel()
    try:
        parser.feed(html[:limit])
        parser.close()
    except Exception:  # noqa: BLE001
        pass
    return "".join(tokens)
