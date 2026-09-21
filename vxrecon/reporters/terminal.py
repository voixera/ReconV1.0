"""Terminal reporter.

Renders findings grouped by module, with confidence badges and evidence lines.
All output respects ``--no-color`` and ``--quiet`` and never crashes on
unusual values.
"""

from __future__ import annotations

from typing import Any

from vxrecon.core.context import RunContext
from vxrecon.reporters.base import BaseReporter
from vxrecon.ui.theme import Theme

_CONFIDENCE_STYLE = {
    "HIGH": "green",
    "MEDIUM": "yellow",
    "LOW": "grey",
}

_MODULE_TITLES = {
    "dns": "DNS INTELLIGENCE",
    "tls": "CERTIFICATE INTELLIGENCE",
    "rdap": "REGISTRATION / NETWORK",
    "http": "HTTP BEHAVIOUR",
    "technology": "TECHNOLOGY CONFIDENCE",
    "website_dna": "WEBSITE DNA",
}


class TerminalReporter(BaseReporter):
    """Human-readable terminal renderer for a scan payload."""

    name = "terminal"

    def render(self, data: dict[str, Any]) -> str:
        theme = Theme(enabled=not self.ctx.no_color)
        lines: list[str] = []

        results = data.get("results", [])
        for result in results:
            module = result.get("module", "?")
            findings = result.get("findings", [])
            if not findings:
                continue
            title = _MODULE_TITLES.get(module, module.upper())
            lines.append("")
            lines.append(theme.color(title, "bold", "white"))
            lines.append(theme.divider(len(title)))
            for finding in findings:
                lines.extend(self._render_finding(finding, theme))
            for error in result.get("errors", []):
                lines.append(theme.glyph("warn", str(error)))
            for note in result.get("notes", []):
                lines.append(theme.glyph("skip", str(note)))

        graph = data.get("graph")
        if graph and graph.get("edges"):
            lines.append("")
            lines.append(theme.color("INFRASTRUCTURE GRAPH", "bold", "white"))
            lines.append(theme.divider(20))
            for edge in graph["edges"]:
                lines.append(self._render_edge(edge, theme))

        return "\n".join(lines)

    def _render_finding(self, finding: dict[str, Any], theme: Theme) -> list[str]:
        key = finding.get("key", "?")
        value = finding.get("value")
        confidence = str(finding.get("confidence", "MEDIUM"))
        badge = theme.color(f"[{confidence}]", _CONFIDENCE_STYLE.get(confidence, "grey"))
        line = f"  {badge} {theme.color(key, 'cyan')} = {_stringify(value)}"
        out = [line]
        for ev in finding.get("evidence", []):
            out.append("        " + theme.color(f"- {ev}", "grey"))
        return out

    def _render_edge(self, edge: dict[str, Any], theme: Theme) -> str:
        src = f"{edge.get('src_kind')}:{edge.get('src_value')}"
        dst = f"{edge.get('dst_kind')}:{edge.get('dst_value')}"
        relation = edge.get("relation")
        confidence = str(edge.get("confidence", "MEDIUM"))
        badge = theme.color(f"[{confidence}]", _CONFIDENCE_STYLE.get(confidence, "grey"))
        return f"  {src} {theme.color('--' + str(relation) + '-->', 'magenta')} {dst} {badge}"


def _stringify(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)
