"""HTML report renderer (feature: reports).

Generates a single self-contained HTML file (no external assets, no CDN, no
tracking) from a scan payload. All dynamic content is HTML-escaped. The report
includes findings grouped by module with confidence badges and evidence, plus a
rendered graph and evidence-integrity table.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

from vxrecon import __program__, __version__
from vxrecon.core.context import RunContext
from vxrecon.reporters.base import BaseReporter

_MODULE_TITLES = {
    "dns": "DNS Intelligence",
    "tls": "Certificate Intelligence",
    "rdap": "Registration / Network",
    "http": "HTTP Behaviour",
    "technology": "Technology Confidence",
    "website_dna": "Website DNA",
    "subdomains": "Subdomains (CT)",
    "js_endpoints": "JavaScript Endpoints",
    "sourcemap": "Source Maps",
    "files": "Public Files",
    "favicon": "Favicon Fingerprint",
    "metadata": "File Metadata",
}

_CONF_CLASS = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

_CSS = """
:root { --bg:#0f1419; --panel:#161b22; --border:#30363d; --text:#c9d1d9;
        --muted:#8b949e; --accent:#58a6ff; --high:#3fb950; --medium:#d29922; --low:#8b949e; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text);
       font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
header { padding:24px 32px; border-bottom:1px solid var(--border); }
header h1 { margin:0; font-size:22px; letter-spacing:1px; }
header .meta { color:var(--muted); font-size:13px; margin-top:6px; }
main { padding:24px 32px; max-width:1100px; }
section { margin-bottom:28px; }
h2 { font-size:16px; border-bottom:1px solid var(--border); padding-bottom:6px; }
.finding { background:var(--panel); border:1px solid var(--border); border-radius:6px;
           padding:10px 14px; margin:8px 0; }
.finding .key { color:var(--accent); font-family:ui-monospace, Consolas, monospace; }
.badge { font-size:11px; padding:1px 6px; border-radius:4px; margin-right:8px; font-weight:600; }
.badge.high { background:rgba(63,185,80,.15); color:var(--high); }
.badge.medium { background:rgba(210,153,34,.15); color:var(--medium); }
.badge.low { background:rgba(139,148,158,.15); color:var(--low); }
.evidence { color:var(--muted); font-size:12px; margin-top:6px;
            font-family:ui-monospace, Consolas, monospace; }
.evidence div::before { content:"- "; }
table { border-collapse:collapse; width:100%; font-size:13px; }
th,td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--border); }
th { color:var(--muted); font-weight:600; }
code { font-family:ui-monospace, Consolas, monospace; color:var(--text); word-break:break-all; }
.disclaimer { background:rgba(210,153,34,.1); border-left:3px solid var(--medium);
              padding:10px 14px; font-size:13px; color:var(--muted); margin-bottom:20px; }
.edge { font-family:ui-monospace, Consolas, monospace; font-size:12px; color:var(--muted); }
"""


class HtmlReporter(BaseReporter):
    """Render a scan payload to a self-contained HTML document."""

    name = "html"

    def render(self, data: dict[str, Any]) -> str:
        target = html.escape(str(data.get("target", "unknown")))
        generated = datetime.now(timezone.utc).isoformat()
        parts: list[str] = [
            "<!DOCTYPE html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{__program__} report - {target}</title>",
            f"<style>{_CSS}</style>",
            "</head><body>",
            "<header>",
            f"<h1>{__program__} - {target}</h1>",
            f'<div class="meta">v{__version__} &middot; action: {html.escape(str(data.get("action", "")))}'
            f' &middot; {html.escape(generated)}</div>',
            "</header>",
            "<main>",
            '<div class="disclaimer">Passive OSINT output. Relationships indicate shared '
            "infrastructure indicators, not ownership. Verify findings independently.</div>",
        ]
        parts.append(self._render_results(data.get("results", [])))
        parts.append(self._render_graph(data.get("graph")))
        parts.append(self._render_evidence(data.get("results", [])))
        parts.extend(["</main></body></html>"])
        return "\n".join(parts)

    def _render_results(self, results: list[dict[str, Any]]) -> str:
        out: list[str] = []
        for result in results:
            findings = result.get("findings", [])
            if not findings:
                continue
            module = result.get("module", "?")
            title = _MODULE_TITLES.get(module, module.title())
            out.append("<section>")
            out.append(f"<h2>{html.escape(title)}</h2>")
            for finding in findings:
                out.append(self._render_finding(finding))
            for error in result.get("errors", []):
                out.append(f'<div class="evidence">error: {html.escape(str(error))}</div>')
            out.append("</section>")
        return "\n".join(out)

    def _render_finding(self, finding: dict[str, Any]) -> str:
        conf = str(finding.get("confidence", "MEDIUM")).upper()
        cls = _CONF_CLASS.get(conf, "low")
        key = html.escape(str(finding.get("key", "")))
        value = html.escape(_stringify(finding.get("value")))
        evidence = "".join(
            f"<div>{html.escape(str(e))}</div>" for e in finding.get("evidence", [])
        )
        return (
            '<div class="finding">'
            f'<span class="badge {cls}">{conf}</span>'
            f'<span class="key">{key}</span> = <code>{value}</code>'
            f'<div class="evidence">{evidence}</div>'
            "</div>"
        )

    def _render_graph(self, graph: dict[str, Any] | None) -> str:
        if not graph or not graph.get("edges"):
            return ""
        out = ["<section><h2>Relationship Graph</h2><table>",
               "<tr><th>Source</th><th>Relation</th><th>Target</th><th>Confidence</th></tr>"]
        for edge in graph["edges"]:
            src = f"{edge.get('src_kind')}:{edge.get('src_value')}"
            dst = f"{edge.get('dst_kind')}:{edge.get('dst_value')}"
            out.append(
                f"<tr><td>{html.escape(src)}</td>"
                f"<td><code>{html.escape(str(edge.get('relation')))}</code></td>"
                f"<td>{html.escape(dst)}</td>"
                f"<td>{html.escape(str(edge.get('confidence')))}</td></tr>"
            )
        out.append("</table></section>")
        return "\n".join(out)

    def _render_evidence(self, results: list[dict[str, Any]]) -> str:
        rows: list[str] = []
        seen: set[tuple] = set()
        for result in results:
            for finding in result.get("findings", []):
                ref = finding.get("evidence_ref")
                if not ref:
                    continue
                identity = (ref.get("sha256"), ref.get("source_url"))
                if identity in seen:
                    continue
                seen.add(identity)
                rows.append(
                    "<tr>"
                    f"<td><code>{html.escape(str(ref.get('sha256') or '-')[:24])}</code></td>"
                    f"<td>{html.escape(str(ref.get('source_url') or '-'))}</td>"
                    f"<td>{html.escape(str(ref.get('http_status') or '-'))}</td>"
                    f"<td>{html.escape(str(ref.get('content_type') or '-'))}</td>"
                    f"<td>{html.escape(str(ref.get('acquired_at') or '-'))}</td>"
                    "</tr>"
                )
        if not rows:
            return ""
        return (
            "<section><h2>Evidence Integrity</h2><table>"
            "<tr><th>SHA-256</th><th>Source</th><th>Status</th><th>Content-Type</th><th>Acquired</th></tr>"
            + "".join(rows)
            + "</table></section>"
        )


def _stringify(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)
