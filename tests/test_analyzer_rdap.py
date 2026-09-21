"""Tests for the RDAP analyzer and the correlator graph."""

from __future__ import annotations

from vxrecon.analyzers.rdap_analyzer import RdapAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult
from vxrecon.correlators.infra_mapper import InfraMapper


def test_rdap_analyzer_registration_events() -> None:
    ctx = RunContext(quiet=True)
    raw = {
        "rdap": {
            "target": "example.com",
            "registration": {
                "registrar": "Example Registrar, Inc.",
                "events": {"registration": "1995-08-14T04:00:00Z"},
                "nameservers": ["hera.ns.cloudflare.com"],
                "status": ["client transfer prohibited"],
            },
        }
    }
    result = RdapAnalyzer(ctx).analyze("example.com", raw, ctx)
    keys = {f.key for f in result.findings}
    assert "rdap.registrar" in keys
    assert "rdap.event.registration" in keys
    assert "rdap.nameserver" in keys


def test_infra_mapper_builds_graph_with_evidence() -> None:
    ctx = RunContext(quiet=True)
    result = ScanResult(target="example.com", module="dns")
    result.add_finding(
        Finding(key="dns.a", value="1.2.3.4", confidence=Confidence.HIGH, evidence=["A record"])
    )
    result.add_finding(
        Finding(key="dns.ns", value="ns1.example.net", confidence=Confidence.HIGH, evidence=["NS"])
    )
    graph = InfraMapper(ctx).correlate("example.com", [result], ctx)
    relations = {e.relation for e in graph.edges}
    assert "resolves_to" in relations
    assert "uses_nameserver" in relations
    for edge in graph.edges:
        assert edge.evidence, "every edge must carry evidence"


def test_infra_mapper_links_asn_to_ips() -> None:
    ctx = RunContext(quiet=True)
    dns = ScanResult(target="example.com", module="dns")
    dns.add_finding(Finding(key="dns.a", value="1.2.3.4", confidence=Confidence.HIGH))
    rdap = ScanResult(target="example.com", module="rdap")
    rdap.add_finding(Finding(key="net.asn", value="AS13335", confidence=Confidence.MEDIUM))
    graph = InfraMapper(ctx).correlate("example.com", [dns, rdap], ctx)
    asn_edges = [e for e in graph.edges if e.relation == "belongs_to"]
    assert asn_edges
    assert asn_edges[0].dst_value == "AS13335"


def test_graph_exports_to_dict_and_json() -> None:
    ctx = RunContext(quiet=True)
    result = ScanResult(target="example.com", module="dns")
    result.add_finding(Finding(key="dns.a", value="1.2.3.4", confidence=Confidence.HIGH))
    graph = InfraMapper(ctx).correlate("example.com", [result], ctx)
    data = graph.to_dict()
    assert "nodes" in data and "edges" in data
    assert isinstance(graph.to_json(), str)
