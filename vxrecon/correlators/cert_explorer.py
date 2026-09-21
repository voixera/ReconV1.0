"""Certificate Relationship Explorer (feature 6).

Builds a certificate-centric view of the graph: which domains a certificate
was issued for (SAN), who issued it, and when it is valid. This is the passive
counterpart of certificate "enumeration" - we read the certificate the server
already presents to every client.

We never assert that SAN entries share an owner. Sharing a certificate is a
**shared infrastructure indicator**, nothing more.
"""

from __future__ import annotations

from vxrecon.core.context import RunContext
from vxrecon.core.result import ScanResult
from vxrecon.correlators.base import BaseCorrelator
from vxrecon.correlators.graph import Graph


class CertificateExplorer(BaseCorrelator):
    """Build a certificate -> issuer / SAN graph."""

    name = "cert_explorer"

    def correlate(self, target: str, results: list[ScanResult], ctx: RunContext) -> Graph:
        graph = Graph()
        domain = target.lower().rstrip("/")

        fingerprint = None
        issuer = None
        san_entries: list[str] = []
        validity = None

        for result in results:
            for finding in result.findings:
                if finding.key == "tls.fingerprint_sha256":
                    fingerprint = str(finding.value)
                elif finding.key == "tls.issuer":
                    issuer = str(finding.value)
                elif finding.key == "tls.san":
                    san_entries.append(str(finding.value))
                elif finding.key == "tls.validity":
                    validity = finding.value

        if not fingerprint:
            return graph

        graph.add_node("certificate", fingerprint, label=fingerprint[:16])
        graph.add_node("domain", domain, label=domain)
        graph.add_edge(
            ("certificate", fingerprint),
            ("domain", domain),
            "issued_for",
            confidence="HIGH",
            evidence="certificate presented by target",
        )
        if issuer:
            graph.add_node("issuer", issuer)
            graph.add_edge(
                ("certificate", fingerprint),
                ("issuer", issuer),
                "issued_by",
                confidence="HIGH",
                evidence=f"issuer: {issuer}",
            )
        for san in san_entries:
            graph.add_node("san", san, label=san)
            graph.add_edge(
                ("certificate", fingerprint),
                ("san", san),
                "has_san",
                confidence="HIGH",
                evidence=f"SAN entry: {san}",
            )
        if validity:
            graph.nodes[f"certificate:{fingerprint}"].meta["validity"] = validity
        return graph
