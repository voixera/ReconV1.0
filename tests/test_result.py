"""Tests for core result contracts (finding evidence + snapshot hashing)."""

from __future__ import annotations

from vxrecon.core.result import Confidence, Evidence, Finding, ScanResult, Status


def test_confidence_weights_ordered() -> None:
    assert Confidence.HIGH.weight > Confidence.MEDIUM.weight > Confidence.LOW.weight


def test_finding_requires_evidence_serialization() -> None:
    finding = Finding(
        key="technology.react",
        value=True,
        confidence=Confidence.HIGH,
        evidence=["react runtime reference", "/static/react.js"],
    )
    data = finding.to_dict()
    assert data["key"] == "technology.react"
    assert data["confidence"] == "HIGH"
    assert len(data["evidence"]) == 2


def test_evidence_integrity_fields() -> None:
    ev = Evidence(
        source_url="https://example.com/favicon.ico",
        http_status=200,
        content_type="image/x-icon",
        sha256="abc",
        bytes=42,
        acquired_at="2026-01-01T00:00:00Z",
    )
    d = ev.to_dict()
    assert d["sha256"] == "abc"
    assert d["http_status"] == 200


def test_summary_hash_is_order_independent() -> None:
    a = ScanResult(target="example.com", module="dns")
    a.add_finding(Finding(key="a", value=1))
    a.add_finding(Finding(key="b", value=2))
    a.add_finding(Finding(key="b", value=2))

    b = ScanResult(target="example.com", module="dns")
    b.add_finding(Finding(key="b", value=2))
    b.add_finding(Finding(key="b", value=2))
    b.add_finding(Finding(key="a", value=1))

    assert a.summary_hash() == b.summary_hash()


def test_summary_hash_changes_on_content() -> None:
    a = ScanResult(target="example.com", module="dns")
    a.add_finding(Finding(key="a", value=1))
    b = ScanResult(target="example.com", module="dns")
    b.add_finding(Finding(key="a", value=2))
    assert a.summary_hash() != b.summary_hash()


def test_add_finding_sets_source_module() -> None:
    result = ScanResult(target="x", module="dns")
    result.add_finding(Finding(key="a", value=1))
    assert result.findings[0].source_module == "dns"
    assert result.status is Status.OK
