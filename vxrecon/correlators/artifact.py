"""Artifact Correlation (feature 17).

Relates artifacts discovered across analyzers — favicon hashes, certificate
fingerprints, HTTP/Website DNA, IPs, technologies — into a single correlation
graph. Every edge carries the evidence source that justified it.

The purpose is to help an analyst see "what goes with what" without asserting
ownership. Shared artifacts are *shared indicators*, nothing more.
"""

from __future__ import annotations

from vxrecon.core.context import RunContext
from vxrecon.core.result import ScanResult
from vxrecon.correlators.base import BaseCorrelator
from vxrecon.correlators.graph import Graph


class ArtifactCorrelator(BaseCorrelator):
    """Correlate artifacts (favicon, cert, DNA, tech, IP) around a target."""

    name = "artifact"

    def correlate(self, target: str, results: list[ScanResult], ctx: RunContext) -> Graph:
        graph = Graph()
        target_label = target.lower().rstrip("/")
        graph.add_node("target", target_label, label=target)

        by_key: dict[str, list] = {}
        for result in results:
            for finding in result.findings:
                by_key.setdefault(finding.key, []).append(finding)

        # Favicon fingerprint -> target
        for finding in by_key.get("favicon.sha256", []):
            graph.add_node("favicon", str(finding.value), label=str(finding.value)[:16])
            graph.add_edge(
                ("target", target_label),
                ("favicon", str(finding.value)),
                "has_favicon",
                confidence="HIGH",
                evidence="; ".join(finding.evidence)[:200],
            )

        # Certificate fingerprint -> target
        for finding in by_key.get("tls.fingerprint_sha256", []):
            graph.add_node("certificate", str(finding.value), label=str(finding.value)[:16])
            graph.add_edge(
                ("target", target_label),
                ("certificate", str(finding.value)),
                "presents_cert",
                confidence="HIGH",
                evidence="; ".join(finding.evidence)[:200],
            )

        # DNA fingerprints -> target
        for key, kind in (("http.dna", "http_dna"), ("dna.fingerprint", "website_dna")):
            for finding in by_key.get(key, []):
                graph.add_node(kind, str(finding.value), label=str(finding.value)[:16])
                graph.add_edge(
                    ("target", target_label),
                    (kind, str(finding.value)),
                    "has_dna",
                    confidence="MEDIUM",
                    evidence="; ".join(finding.evidence)[:200],
                )

        # Technologies -> target (evidence-backed)
        for result in results:
            for finding in result.findings:
                if finding.key.startswith("tech."):
                    name = finding.value.get("name") if isinstance(finding.value, dict) else finding.key
                    graph.add_node("technology", str(name))
                    graph.add_edge(
                        ("target", target_label),
                        ("technology", str(name)),
                        "uses",
                        confidence=finding.confidence.value,
                        evidence="; ".join(finding.evidence)[:200],
                    )

        # IPs -> target
        for finding in by_key.get("dns.a", []) + by_key.get("dns.aaaa", []):
            graph.add_node("ip", str(finding.value))
            graph.add_edge(
                ("target", target_label),
                ("ip", str(finding.value)),
                "resolves_to",
                confidence="HIGH",
                evidence="; ".join(finding.evidence)[:200],
            )
        return graph
