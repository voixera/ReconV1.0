"""DNS analyzer.

Turns raw DNS records into evidence-backed findings and derives higher-level
signals (mail provider, nameserver provider, SPF/DMARC posture). No network
access: it only reads what the DNS collector already gathered.
"""

from __future__ import annotations

from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult

# Small, offline provider hints. Matching these is a *hint*, never a claim of
# ownership; confidence reflects that.
_MAIL_PROVIDER_HINTS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "zoho.com": "Zoho Mail",
    "yandex.net": "Yandex Mail",
    "mail.ru": "Mail.ru",
}

_NS_PROVIDER_HINTS = {
    "cloudflare.com": "Cloudflare",
    "awsdns": "Amazon Route 53",
    "googledomains.com": "Google Cloud DNS",
    "azure-dns": "Azure DNS",
    "digitalocean.com": "DigitalOcean",
    "namecheap.com": "Namecheap",
    "godaddy.com": "GoDaddy",
}


class DnsAnalyzer(BaseAnalyzer):
    """Derive findings from collected DNS records."""

    name = "dns"
    consumes = ("dns",)

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        data = raw.get("dns")
        if not data:
            result.errors.append("no DNS data collected")
            return result
        if data.get("_error"):
            result.errors.append(str(data["_error"]))

        records = data.get("records", [])
        for record in records:
            rtype = record.get("record_type", "?")
            value = record.get("value", "")
            ttl = record.get("ttl")
            evidence = [f"{rtype} {record.get('name')} -> {value}"]
            if ttl is not None:
                evidence.append(f"TTL {ttl}")
            result.add_finding(
                Finding(
                    key=f"dns.{rtype.lower()}",
                    value=value,
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                )
            )

        self._derive_mail(result, records)
        self._derive_nameservers(result, records)
        self._derive_email_posture(result, records)

        # Per-type resolver timeouts (common with restrictive local resolvers)
        # are availability notes, not scan failures, provided *some* records
        # resolved. Only a total failure is a hard error.
        collector_errors = [str(e) for e in data.get("errors", [])]
        if collector_errors:
            if records:
                for err in collector_errors:
                    result.add_finding(
                        Finding(
                            key="dns.partial",
                            value=err,
                            confidence=Confidence.LOW,
                            evidence=[f"some record types unavailable: {err}"],
                        )
                    )
            else:
                result.errors.extend(collector_errors)
        return result

    # -- derivations -----------------------------------------------------

    def _derive_mail(self, result: ScanResult, records: list[dict[str, Any]]) -> None:
        mx = [r for r in records if r.get("record_type") == "MX"]
        if not mx:
            return
        hosts = []
        provider = None
        for record in mx:
            parts = record.get("value", "").split()
            host = parts[-1] if parts else record.get("value", "")
            hosts.append(host)
            for needle, name in _MAIL_PROVIDER_HINTS.items():
                if needle in host.lower():
                    provider = name
        evidence = [f"MX {h}" for h in hosts]
        if provider:
            evidence.append(f"pattern matches {provider}")
        result.add_finding(
            Finding(
                key="mail.provider",
                value=provider or "self-hosted/unknown",
                confidence=Confidence.HIGH if provider else Confidence.LOW,
                evidence=evidence,
            )
        )

    def _derive_nameservers(self, result: ScanResult, records: list[dict[str, Any]]) -> None:
        ns = [r.get("value", "") for r in records if r.get("record_type") == "NS"]
        if not ns:
            return
        provider = None
        for host in ns:
            for needle, name in _NS_PROVIDER_HINTS.items():
                if needle in host.lower():
                    provider = name
        evidence = [f"NS {h}" for h in ns]
        if provider:
            evidence.append(f"pattern matches {provider}")
        result.add_finding(
            Finding(
                key="dns.nameserver_provider",
                value=provider or "unknown",
                confidence=Confidence.HIGH if provider else Confidence.LOW,
                evidence=evidence,
            )
        )

    def _derive_email_posture(self, result: ScanResult, records: list[dict[str, Any]]) -> None:
        txt_values = [r.get("value", "") for r in records if r.get("record_type") == "TXT"]
        spf = next((v for v in txt_values if v.startswith("v=spf1")), None)
        if spf:
            result.add_finding(
                Finding(
                    key="email.spf",
                    value=spf,
                    confidence=Confidence.HIGH,
                    evidence=[f"TXT {spf}"],
                )
            )
        dmarc = next((v for v in txt_values if v.startswith("v=DMARC1")), None)
        if dmarc:
            result.add_finding(
                Finding(
                    key="email.dmarc",
                    value=dmarc,
                    confidence=Confidence.HIGH,
                    evidence=[f"TXT {dmarc}"],
                )
            )
