"""Tests for the DNS analyzer (offline, using synthetic raw facts)."""

from __future__ import annotations

from vxrecon.analyzers.dns_analyzer import DnsAnalyzer
from vxrecon.core.context import RunContext


def _raw(records: list[tuple[str, str]], errors: list[str] | None = None) -> dict:
    return {
        "dns": {
            "target": "example.com",
            "records": [
                {"record_type": t, "name": "example.com", "value": v, "ttl": 300}
                for t, v in records
            ],
            "errors": errors or [],
            "backend": "dnspython",
        }
    }


def test_dns_analyzer_emits_findings_with_evidence() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw([("A", "1.2.3.4"), ("NS", "hera.ns.cloudflare.com")])
    result = DnsAnalyzer(ctx).analyze("example.com", raw, ctx)
    keys = {f.key for f in result.findings}
    assert "dns.a" in keys
    assert "dns.ns" in keys
    for finding in result.findings:
        assert finding.evidence, f"{finding.key} has no evidence"


def test_dns_analyzer_detects_cloudflare_nameservers() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw([("NS", "elliott.ns.cloudflare.com")])
    result = DnsAnalyzer(ctx).analyze("example.com", raw, ctx)
    provider = next(f for f in result.findings if f.key == "dns.nameserver_provider")
    assert provider.value == "Cloudflare"
    assert provider.confidence.value == "HIGH"


def test_dns_analyzer_detects_spf_and_dmarc() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw([("TXT", "v=spf1 include:_spf.example.com -all"), ("TXT", "v=DMARC1; p=reject")])
    result = DnsAnalyzer(ctx).analyze("example.com", raw, ctx)
    keys = {f.key for f in result.findings}
    assert "email.spf" in keys
    assert "email.dmarc" in keys


def test_dns_analyzer_detects_microsoft_mail() -> None:
    ctx = RunContext(quiet=True)
    raw = _raw([("MX", "10 example-com.mail.protection.outlook.com")])
    result = DnsAnalyzer(ctx).analyze("example.com", raw, ctx)
    provider = next(f for f in result.findings if f.key == "mail.provider")
    assert provider.value == "Microsoft 365"


def test_dns_analyzer_handles_missing_data() -> None:
    ctx = RunContext(quiet=True)
    result = DnsAnalyzer(ctx).analyze("example.com", {}, ctx)
    assert result.errors
    assert result.findings == []
