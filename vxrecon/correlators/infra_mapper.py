"""Infrastructure relationship mapper (feature 2 foundation).

Consumes findings from the DNS, TLS and RDAP analyzers and builds a graph of
relationships such as::

    [domain] --resolves_to--> [ip] --belongs_to--> [asn]
    [domain] --uses_nameserver--> [ns]
    [domain] --has_mx--> [mail host]
    [domain] --presented_cert--> [cert fingerprint] --has_san--> [domain]

Every edge carries evidence and a confidence indicator. We never assert
ownership; relations describe **shared infrastructure indicators**.
"""

from __future__ import annotations

from vxrecon.core.context import RunContext
from vxrecon.core.result import ScanResult
from vxrecon.correlators.base import BaseCorrelator
from vxrecon.correlators.graph import Graph


class InfraMapper(BaseCorrelator):
    """Build a domain-centric infrastructure graph."""

    name = "infra_mapper"

    def correlate(self, target: str, results: list[ScanResult], ctx: RunContext) -> Graph:
        graph = Graph()
        domain = target.lower().rstrip("/")
        graph.add_node("domain", domain, label=domain)

        for result in results:
            for finding in result.findings:
                handler = getattr(self, f"_handle_{finding.key.replace('.', '_')}", None)
                if handler is not None:
                    handler(graph, domain, finding)
        return graph

    # -- DNS -------------------------------------------------------------

    def _handle_dns_a(self, graph: Graph, domain: str, finding) -> None:
        graph.add_node("ip", str(finding.value))
        graph.add_edge(
            ("domain", domain),
            ("ip", str(finding.value)),
            "resolves_to",
            confidence=finding.confidence.value,
            evidence="; ".join(finding.evidence),
        )

    _handle_dns_aaaa = _handle_dns_a

    def _handle_dns_mx(self, graph: Graph, domain: str, finding) -> None:
        parts = str(finding.value).split()
        host = (parts[-1] if parts else str(finding.value)).rstrip(".")
        graph.add_node("mail", host, label=host)
        graph.add_edge(
            ("domain", domain),
            ("mail", host),
            "has_mx",
            confidence=finding.confidence.value,
            evidence="; ".join(finding.evidence),
        )

    def _handle_dns_ns(self, graph: Graph, domain: str, finding) -> None:
        host = str(finding.value).rstrip(".")
        graph.add_node("nameserver", host, label=host)
        graph.add_edge(
            ("domain", domain),
            ("nameserver", host),
            "uses_nameserver",
            confidence=finding.confidence.value,
            evidence="; ".join(finding.evidence),
        )

    # -- TLS -------------------------------------------------------------

    def _handle_tls_fingerprint_sha256(self, graph: Graph, domain: str, finding) -> None:
        fp = str(finding.value)
        graph.add_node("certificate", fp, label=fp[:16])
        graph.add_edge(
            ("domain", domain),
            ("certificate", fp),
            "presented_cert",
            confidence=finding.confidence.value,
            evidence="; ".join(finding.evidence),
        )

    def _handle_tls_san(self, graph: Graph, domain: str, finding) -> None:
        san = str(finding.value).lower()
        graph.add_node("subdomain", san, label=san)
        graph.add_edge(
            ("domain", domain),
            ("subdomain", san),
            "certificate_san",
            confidence=finding.confidence.value,
            evidence="; ".join(finding.evidence),
        )

    # -- RDAP ------------------------------------------------------------

    def _handle_net_asn(self, graph: Graph, domain: str, finding) -> None:
        asn = str(finding.value)
        graph.add_node("asn", asn)
        # Link ASN to every IP we know for this domain.
        for node in graph.neighbors("domain", domain, relation="resolves_to"):
            if node.kind == "ip":
                graph.add_edge(
                    ("ip", node.value),
                    ("asn", asn),
                    "belongs_to",
                    confidence=finding.confidence.value,
                    evidence="; ".join(finding.evidence),
                )

    def _handle_rdap_registrar(self, graph: Graph, domain: str, finding) -> None:
        graph.add_node("registrar", str(finding.value))
        graph.add_edge(
            ("domain", domain),
            ("registrar", str(finding.value)),
            "registered_via",
            confidence=finding.confidence.value,
            evidence="; ".join(finding.evidence),
        )

    def _handle_mail_provider(self, graph: Graph, domain: str, finding) -> None:
        value = str(finding.value)
        if value in {"self-hosted/unknown", "unknown"}:
            return
        graph.add_node("provider", value)
        graph.add_edge(
            ("domain", domain),
            ("provider", value),
            "mail_provider",
            confidence=finding.confidence.value,
            evidence="; ".join(finding.evidence),
        )
