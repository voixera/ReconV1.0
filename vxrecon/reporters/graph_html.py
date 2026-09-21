"""Interactive graph and timeline HTML exporters.

Both produce self-contained HTML (inline CSS/SVG/JS, no CDN, no tracking).

* The graph exporter renders an SVG force-free layout: a hub-and-spoke diagram
  around the target node. Positions are computed deterministically so exports
  are reproducible.
* The timeline exporter renders a vertical event list.
"""

from __future__ import annotations

import html
import math
from typing import Any

_CSS = """
:root { --bg:#0f1419; --panel:#161b22; --border:#30363d; --text:#c9d1d9;
        --muted:#8b949e; --accent:#58a6ff; }
body { margin:0; background:var(--bg); color:var(--text);
       font-family:-apple-system,"Segoe UI",Roboto,sans-serif; }
header { padding:20px 28px; border-bottom:1px solid var(--border); }
h1 { margin:0; font-size:18px; }
.hint { color:var(--muted); font-size:12px; margin-top:4px; }
.wrap { padding:20px 28px; }
svg { background:var(--panel); border:1px solid var(--border); border-radius:8px; width:100%; height:auto; }
.node-label { fill:var(--text); font-size:11px; font-family:ui-monospace,Consolas,monospace; }
.edge-line { stroke:#3a4552; stroke-width:1.2; fill:none; }
.edge-label { fill:var(--muted); font-size:9px; }
.event { border-left:2px solid var(--border); padding:6px 0 6px 16px; margin-left:8px; position:relative; }
.event::before { content:""; position:absolute; left:-5px; top:12px; width:8px; height:8px;
                 border-radius:50%; background:var(--accent); }
.event .ts { color:var(--muted); font-size:12px; font-family:ui-monospace,Consolas,monospace; }
.event .msg { margin-top:2px; }
.disclaimer { background:rgba(210,153,34,.1); border-left:3px solid #d29922; padding:10px 14px;
              font-size:13px; color:var(--muted); margin:16px 28px; }
"""

_NODE_COLOR = {
    "target": "#58a6ff",
    "domain": "#58a6ff",
    "ip": "#3fb950",
    "certificate": "#d29922",
    "favicon": "#bc8cff",
    "technology": "#f778ba",
    "nameserver": "#79c0ff",
    "mail": "#79c0ff",
    "provider": "#79c0ff",
    "asn": "#ffa657",
}


def render_graph_html(graph: dict[str, Any], target: str) -> str:
    """Render a hub-and-spoke SVG graph to a self-contained HTML page."""

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    positions: dict[str, tuple[float, float]] = {}
    width, height = 900, 560
    cx, cy = width / 2, height / 2
    positions[_node_id(nodes[0]) if nodes else "target"] = (cx, cy)

    # Place nodes on concentric rings by kind, deterministically sorted.
    ordered = sorted(
        nodes,
        key=lambda n: (n.get("kind", ""), n.get("value", "")),
    )
    ring_sizes = [0]
    radius = 200
    for index, node in enumerate(ordered):
        nid = _node_id(node)
        angle = 2 * math.pi * (index / max(1, len(ordered)))
        if index == 0:
            positions[nid] = (cx, cy)
        else:
            r = radius + (index % 2) * 60
            positions[nid] = (cx + r * math.cos(angle), cy + r * math.sin(angle))

    svg: list[str] = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">']
    for edge in edges:
        sid = f"{edge.get('src_kind')}:{edge.get('src_value')}"
        did = f"{edge.get('dst_kind')}:{edge.get('dst_value')}"
        if sid not in positions or did not in positions:
            continue
        x1, y1 = positions[sid]
        x2, y2 = positions[did]
        svg.append(f'<line class="edge-line" x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}"/>')
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        svg.append(
            f'<text class="edge-label" x="{mx:.0f}" y="{my:.0f}" text-anchor="middle">'
            f"{html.escape(str(edge.get('relation')))}</text>"
        )
    for node in nodes:
        nid = _node_id(node)
        x, y = positions.get(nid, (cx, cy))
        color = _NODE_COLOR.get(node.get("kind", ""), "#8b949e")
        label = html.escape(str(node.get("label") or node.get("value", ""))[:28])
        svg.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="6" fill="{color}"/>')
        svg.append(
            f'<text class="node-label" x="{x:.0f}" y="{y - 10:.0f}" text-anchor="middle">{label}</text>'
        )
    svg.append("</svg>")

    return "\n".join(
        [
            "<!DOCTYPE html>",
            '<html lang="en"><head><meta charset="utf-8">',
            f"<title>VXRecon graph - {html.escape(target)}</title>",
            f"<style>{_CSS}</style></head><body>",
            f"<header><h1>Relationship Graph - {html.escape(target)}</h1>",
            '<div class="hint">Nodes are typed; edges are evidence-backed relationships.</div></header>',
            '<div class="disclaimer">Shared infrastructure indicators only. No ownership is implied.</div>',
            f'<div class="wrap">{"".join(svg)}</div>',
            "</body></html>",
        ]
    )


def render_timeline_html(events: list[dict[str, Any]], target: str) -> str:
    """Render a vertical timeline of events to a self-contained HTML page."""

    rows: list[str] = []
    for event in events:
        ts = html.escape(str(event.get("ts", "")).split(".")[0])
        msg = html.escape(str(event.get("message", "")))
        rows.append(f'<div class="event"><div class="ts">{ts}</div><div class="msg">{msg}</div></div>')
    if not rows:
        rows.append('<div class="event">no events recorded</div>')

    return "\n".join(
        [
            "<!DOCTYPE html>",
            '<html lang="en"><head><meta charset="utf-8">',
            f"<title>VXRecon timeline - {html.escape(target)}</title>",
            f"<style>{_CSS}</style></head><body>",
            f"<header><h1>Investigation Timeline - {html.escape(target)}</h1></header>",
            f'<div class="wrap">{"".join(rows)}</div>',
            "</body></html>",
        ]
    )


def _node_id(node: dict[str, Any]) -> str:
    return f"{node.get('kind')}:{node.get('value')}"
