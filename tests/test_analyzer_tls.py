"""Tests for the TLS analyzer (offline, synthetic certificate facts)."""

from __future__ import annotations

from vxrecon.analyzers.tls_analyzer import TlsAnalyzer
from vxrecon.core.context import RunContext


def _raw(cert: dict) -> dict:
    return {"tls": {"target": "example.com", "certificate": cert}}


def test_tls_analyzer_emits_issuer_and_fingerprint() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw(
        {
            "fingerprint_sha256": "abc123",
            "issuer_cn": "Let's Encrypt Authority X3",
            "san": ["example.com", "www.example.com"],
            "key_type": "EC",
            "key_bits": 256,
            "sig_alg": "ecdsa-with-SHA256",
        }
    )
    result = TlsAnalyzer(ctx).analyze("example.com", raw, ctx)
    keys = {f.key for f in result.findings}
    assert "tls.fingerprint_sha256" in keys
    assert "tls.issuer" in keys
    assert "tls.san" in keys
    assert "tls.key" in keys


def test_tls_analyzer_labels_lets_encrypt() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw({"issuer_cn": "R3 (Let's Encrypt)", "san": []})
    result = TlsAnalyzer(ctx).analyze("example.com", raw, ctx)
    issuer = next(f for f in result.findings if f.key == "tls.issuer")
    assert issuer.value == "Let's Encrypt"


def test_tls_analyzer_flags_weak_rsa_key() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw({"key_type": "RSA", "key_bits": 1024, "san": []})
    result = TlsAnalyzer(ctx).analyze("example.com", raw, ctx)
    key = next(f for f in result.findings if f.key == "tls.key")
    assert key.confidence.value == "MEDIUM"
    assert any("2048" in e for e in key.evidence)


def test_tls_analyzer_flags_expired() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw({"not_after": "2000-01-01T00:00:00+00:00", "san": []})
    result = TlsAnalyzer(ctx).analyze("example.com", raw, ctx)
    assert any(f.key == "tls.expired" for f in result.findings)


def test_tls_analyzer_handles_collector_error() -> None:
    ctx = RunContext(quiet=True)
    result = TlsAnalyzer(ctx).analyze("example.com", {"tls": {"_error": "timeout"}}, ctx)
    assert result.errors
    assert result.findings == []
