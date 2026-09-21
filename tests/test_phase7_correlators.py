"""Tests for Phase 7: similarity engine and artifact correlator."""

from __future__ import annotations

from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult
from vxrecon.correlators.artifact import ArtifactCorrelator
from vxrecon.correlators.similarity import compare


def _result(module: str, findings: list[tuple[str, object]]) -> ScanResult:
    r = ScanResult(target="x", module=module)
    for key, value in findings:
        r.add_finding(Finding(key=key, value=value, confidence=Confidence.HIGH, evidence=["e"]))
    return r


def test_similarity_identical_infrastructure() -> None:
    a = [_result("dns", [("dns.a", "1.2.3.4")])]
    b = [_result("dns", [("dns.a", "1.2.3.4")])]
    result = compare(a, b, "a.com", "b.com")
    dns = next(d for d in result.dimensions if d.name.startswith("DNS"))
    assert dns.score == 100.0


def test_similarity_no_overlap() -> None:
    a = [_result("dns", [("dns.a", "1.2.3.4")])]
    b = [_result("dns", [("dns.a", "9.9.9.9")])]
    result = compare(a, b, "a.com", "b.com")
    dns = next(d for d in result.dimensions if d.name.startswith("DNS"))
    assert dns.score == 0.0


def test_similarity_marks_incomparable_none() -> None:
    a = [_result("dns", [("dns.a", "1.2.3.4")])]
    b = [_result("dns", [("dns.a", "1.2.3.4")])]
    result = compare(a, b, "a.com", "b.com")
    favicon = next(d for d in result.dimensions if "Favicon" in d.name)
    assert favicon.score is None


def test_similarity_technology_overlap() -> None:
    a = [_result("technology", [("tech.react", {"name": "React"}), ("tech.nginx", {"name": "nginx"})])]
    b = [_result("technology", [("tech.react", {"name": "React"})])]
    result = compare(a, b, "a", "b")
    tech = next(d for d in result.dimensions if d.name == "Technology")
    assert tech.score == 50.0
    assert "React" in tech.shared


def test_similarity_disclaimer_present() -> None:
    result = compare([], [], "a", "b")
    assert "not ownership" in result.to_dict()["disclaimer"].lower()


def test_artifact_correlator_edges_have_evidence() -> None:
    ctx = RunContext(quiet=True)
    results = [
        _result("favicon", [("favicon.sha256", "abc123")]),
        _result("tls", [("tls.fingerprint_sha256", "deadbeef")]),
        _result("technology", [("tech.react", {"name": "React"})]),
        _result("dns", [("dns.a", "1.2.3.4")]),
    ]
    graph = ArtifactCorrelator(ctx).correlate("example.com", results, ctx)
    relations = {e.relation for e in graph.edges}
    assert "has_favicon" in relations
    assert "presents_cert" in relations
    assert "uses" in relations
    assert "resolves_to" in relations
    for edge in graph.edges:
        assert edge.evidence
