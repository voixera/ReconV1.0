"""Markdown report renderer.

Produces a portable Markdown report suitable for pasting into issues, wikis or
pull requests. Every finding states its confidence and evidence; relationship
edges carry their confidence. Output is intentionally plain so it renders
anywhere.
"""

from __future__ import annotations

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


class MarkdownReporter(BaseReporter):
    """Render a scan payload as Markdown."""

    name = "markdown"

    def render(self, data: dict[str, Any]) -> str:
        target = str(data.get("target", "unknown"))
        generated = datetime.now(timezone.utc).isoformat()
        lines: list[str] = [
            f"# {__program__} report: `{target}`",
            "",
            f"- Tool: {__program__} v{__version__}",
            f"- Action: `{data.get('action', '')}`",
            f"- Generated: {generated}",
            "",
            "> Passive OSINT output. Relationships indicate shared infrastructure",
            "> indicators, not ownership. Verify findings independently.",
            "",
        ]
        lines.extend(self._results(data.get("results", [])))
        lines.extend(self._graph(data.get("graph")))
        lines.extend(self._evidence(data.get("results", [])))
        return "\n".join(lines)

    def _results(self, results: list[dict[str, Any]]) -> list[str]:
        out: list[str] = []
        for result in results:
            findings = result.get("findings", [])
            if not findings:
                continue
            module = result.get("module", "?")
            out.append(f"## {_MODULE_TITLES.get(module, module.title())}")
            out.append("")
            out.append("| Confidence | Key | Value |")
            out.append("|---|---|---|")
            for finding in findings:
                value = _escape_table(_stringify(finding.get("value")))
                key = f"`{finding.get('key', '')}`"
                conf = str(finding.get("confidence", "")).upper()
                out.append(f"| {conf} | {key} | {value} |")
            out.append("")
            evidence_lines = [
                f"- `{finding.get('key')}`: {e}"
                for finding in findings
                for e in finding.get("evidence", [])
            ]
            if evidence_lines:
                out.append("<details><summary>Evidence</summary>")
                out.append("")
                out.extend(evidence_lines)
                out.append("")
                out.append("</details>")
                out.append("")
        return out

    def _graph(self, graph: dict[str, Any] | None) -> list[str]:
        if not graph or not graph.get("edges"):
            return []
        out = ["## Relationship Graph", "", "| Source | Relation | Target | Confidence |", "|---|---|---|---|"]
        for edge in graph["edges"]:
            src = f"{edge.get('src_kind')}:{edge.get('src_value')}"
            dst = f"{edge.get('dst_kind')}:{edge.get('dst_value')}"
            out.append(
                f"| `{src}` | `{edge.get('relation')}` | `{dst}` | {edge.get('confidence')} |"
            )
        out.append("")
        return out

    def _evidence(self, results: list[dict[str, Any]]) -> list[str]:
        rows: list[str] = []
        seen: set = set()
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
                    f"| `{ref.get('sha256') or '-'}` | {ref.get('source_url') or '-'} "
                    f"| {ref.get('http_status') or '-'} | {ref.get('acquired_at') or '-'} |"
                )
        if not rows:
            return []
        return [
            "## Evidence Integrity",
            "",
            "| SHA-256 | Source | Status | Acquired |",
            "|---|---|---|---|",
            *rows,
            "",
        ]


def _stringify(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def _escape_table(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
