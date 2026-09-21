"""TLS certificate analyzer.

Turns a decoded certificate into findings: issuer, validity window, SAN set,
key strength signals, and expiry posture. Pure function; no network access.

SAN entries become separate findings so later phases can build a certificate
relationship graph (domains that share a certificate are *related*, not
necessarily co-owned).
"""

from __future__ import annotations

from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult
from vxrecon.utils.timeutil import now_iso, parse_iso

# Well-known CAs for a friendlier issuer label. Purely a display nicety.
_CA_HINTS = {
    "Let's Encrypt": "Let's Encrypt",
    "ISRG": "Let's Encrypt",
    "DigiCert": "DigiCert",
    "GlobalSign": "GlobalSign",
    "Sectigo": "Sectigo",
    "Amazon": "Amazon",
    "Google Trust": "Google Trust Services",
    "ZeroSSL": "ZeroSSL",
    "Microsoft": "Microsoft",
}


class TlsAnalyzer(BaseAnalyzer):
    """Derive findings from a decoded TLS certificate."""

    name = "tls"
    consumes = ("tls",)

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        data = raw.get("tls")
        if not data:
            result.errors.append("no TLS data collected")
            return result
        if data.get("_error"):
            result.errors.append(str(data["_error"]))
            return result

        cert = data.get("certificate") or {}
        if not cert or cert.get("decode_error"):
            if cert.get("decode_error"):
                result.errors.append(str(cert["decode_error"]))

        fp = cert.get("fingerprint_sha256") or cert.get("der_sha256")
        if fp:
            result.add_finding(
                Finding(
                    key="tls.fingerprint_sha256",
                    value=fp,
                    confidence=Confidence.HIGH,
                    evidence=[f"certificate SHA-256 {fp}"],
                )
            )

        issuer = cert.get("issuer_cn") or cert.get("issuer")
        if issuer:
            label = self._issuer_label(str(issuer))
            result.add_finding(
                Finding(
                    key="tls.issuer",
                    value=label,
                    confidence=Confidence.HIGH,
                    evidence=[f"issuer: {issuer}"],
                )
            )

        self._add_validity(result, cert)
        self._add_san(result, cert)
        self._add_key_info(result, cert)
        return result

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _issuer_label(issuer: str) -> str:
        for needle, name in _CA_HINTS.items():
            if needle.lower() in issuer.lower():
                return name
        return issuer

    def _add_validity(self, result: ScanResult, cert: dict[str, Any]) -> None:
        not_before = cert.get("not_before")
        not_after = cert.get("not_after")
        if not_before or not_after:
            result.add_finding(
                Finding(
                    key="tls.validity",
                    value={"not_before": not_before, "not_after": not_after},
                    confidence=Confidence.HIGH,
                    evidence=[f"valid from {not_before} to {not_after}"],
                )
            )
        parsed = parse_iso(not_after) if not_after else None
        known = parse_iso(now_iso())
        if parsed and known:
            days = (parsed - known).days
            if days < 0:
                result.add_finding(
                    Finding(
                        key="tls.expired",
                        value=True,
                        confidence=Confidence.HIGH,
                        evidence=[f"certificate expired {abs(days)} day(s) ago"],
                    )
                )
            elif days <= 30:
                result.add_finding(
                    Finding(
                        key="tls.expiring_soon",
                        value=days,
                        confidence=Confidence.MEDIUM,
                        evidence=[f"certificate expires in {days} day(s)"],
                    )
                )

    def _add_san(self, result: ScanResult, cert: dict[str, Any]) -> None:
        san = cert.get("san") or []
        if not san:
            return
        for name in san:
            result.add_finding(
                Finding(
                    key="tls.san",
                    value=name,
                    confidence=Confidence.HIGH,
                    evidence=[f"SAN entry: {name}"],
                )
            )

    def _add_key_info(self, result: ScanResult, cert: dict[str, Any]) -> None:
        key_type = cert.get("key_type")
        key_bits = cert.get("key_bits")
        sig_alg = cert.get("sig_alg")
        if key_type:
            evidence = [f"public key: {key_type}" + (f" {key_bits} bits" if key_bits else "")]
            confidence = Confidence.HIGH
            # Flag weak keys as informational (never as a claim of vulnerability).
            if key_type == "RSA" and key_bits and key_bits < 2048:
                confidence = Confidence.MEDIUM
                evidence.append("RSA key below 2048 bits")
            result.add_finding(
                Finding(
                    key="tls.key",
                    value={"type": key_type, "bits": key_bits},
                    confidence=confidence,
                    evidence=evidence,
                )
            )
        if sig_alg:
            result.add_finding(
                Finding(
                    key="tls.signature_algorithm",
                    value=sig_alg,
                    confidence=Confidence.HIGH,
                    evidence=[f"signature algorithm: {sig_alg}"],
                )
            )
