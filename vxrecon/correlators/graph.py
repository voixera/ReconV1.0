"""Digital footprint graph model (feature 1 foundation).

A lightweight, dependency-free graph of nodes and edges. Nodes are typed by
``kind`` (domain, subdomain, ip, asn, cert, tech, ...). Edges carry a
``relation``, a ``confidence`` and human-readable ``evidence`` so every
relationship in a report is traceable.

Export targets: JSON (canonical) and HTML (interactive, later phase).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Node:
    """A node in the footprint graph."""

    kind: str
    value: str
    label: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def node_id(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass
class Edge:
    """A directed relationship between two nodes."""

    src_kind: str
    src_value: str
    dst_kind: str
    dst_value: str
    relation: str
    confidence: str = "MEDIUM"
    evidence: str | None = None

    @property
    def src_id(self) -> str:
        return f"{self.src_kind}:{self.src_value}"

    @property
    def dst_id(self) -> str:
        return f"{self.dst_kind}:{self.dst_value}"


@dataclass
class Graph:
    """A collection of nodes and edges with helper accessors."""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(
        self, kind: str, value: str, label: str | None = None, **meta: Any
    ) -> Node:
        node = Node(kind=kind, value=value, label=label, meta=meta)
        self.nodes.setdefault(node.node_id, node)
        return self.nodes[node.node_id]

    def add_edge(
        self,
        src: tuple[str, str],
        dst: tuple[str, str],
        relation: str,
        confidence: str = "MEDIUM",
        evidence: str | None = None,
    ) -> Edge:
        edge = Edge(
            src_kind=src[0],
            src_value=src[1],
            dst_kind=dst[0],
            dst_value=dst[1],
            relation=relation,
            confidence=confidence,
            evidence=evidence,
        )
        # De-duplicate identical edges.
        if edge not in self.edges:
            self.edges.append(edge)
        return edge

    def neighbors(self, kind: str, value: str, relation: str | None = None) -> list[Node]:
        node_id = f"{kind}:{value}"
        out: list[Node] = []
        for edge in self.edges:
            if relation and edge.relation != relation:
                continue
            if edge.src_id == node_id:
                node = self.nodes.get(edge.dst_id)
                if node:
                    out.append(node)
            elif edge.dst_id == node_id:
                node = self.nodes.get(edge.src_id)
                if node:
                    out.append(node)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [asdict(n) for n in self.nodes.values()],
            "edges": [asdict(e) for e in self.edges],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
