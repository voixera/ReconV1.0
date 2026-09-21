"""HTTP behaviour analyzer.

Produces an "HTTP DNA" fingerprint and derives signals from response behaviour:
status, redirect chain, HTTP version, content type, compression, caching,
cookies and security header posture.

The DNA is a stable hash over coarse, behaviour-describing attributes so that
two deployments of the same stack tend to share a DNA, without depending on
volatile values (dates, tokens, ETags). It is a *similarity hint*, not proof.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult
from vxrecon.signatures import load_signatures
from vxrecon.utils.http_parse import header_fingerprint

# Headers whose *presence* (not value) matters for the DNA.
_DNA_HEADERS = (
    "server",
    "x-powered-by",
    "via",
    "cf-cache-status",
    "x-cache",
    "cache-control",
    "content-encoding",
    "content-type",
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)


class HttpAnalyzer(BaseAnalyzer):
    """Derive HTTP behaviour findings and an HTTP DNA fingerprint."""

    name = "http"
    consumes = ("http",)

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        data = raw.get("http")
        if not data:
            result.errors.append("no HTTP data collected")
            return result
        if data.get("_error"):
            result.errors.append(str(data["_error"]))
            return result

        self._add_basics(result, data)
        self._add_redirects(result, data)
        self._add_cookies(result, data)
        self._add_security_headers(result, data)
        self._add_dna(result, data)
        return result

    # -- basics ----------------------------------------------------------

    def _add_basics(self, result: ScanResult, data: dict[str, Any]) -> None:
        status = data.get("status")
        if status is not None:
            result.add_finding(
                Finding(
                    key="http.status",
                    value=status,
                    confidence=Confidence.HIGH,
                    evidence=[f"responded with HTTP {status} {data.get('reason') or ''}".strip()],
                )
            )
        if data.get("http_version"):
            result.add_finding(
                Finding(
                    key="http.version",
                    value=data["http_version"],
                    confidence=Confidence.MEDIUM,
                    evidence=[f"protocol: {data['http_version']}"],
                )
            )
        if data.get("content_type"):
            result.add_finding(
                Finding(
                    key="http.content_type",
                    value=data["content_type"],
                    confidence=Confidence.HIGH,
                    evidence=[f"Content-Type: {data['content_type']}"],
                )
            )
        enc = data.get("headers", {}).get("content-encoding")
        if enc:
            result.add_finding(
                Finding(
                    key="http.compression",
                    value=enc,
                    confidence=Confidence.HIGH,
                    evidence=[f"Content-Encoding: {enc}"],
                )
            )
        if data.get("content_length") is not None:
            result.add_finding(
                Finding(
                    key="http.size",
                    value=data["content_length"],
                    confidence=Confidence.HIGH,
                    evidence=[f"body size: {data['content_length']} bytes"],
                )
            )

    def _add_redirects(self, result: ScanResult, data: dict[str, Any]) -> None:
        chain = data.get("redirect_chain") or []
        final = data.get("final_url")
        if chain:
            result.add_finding(
                Finding(
                    key="http.redirect_chain",
                    value=chain,
                    confidence=Confidence.HIGH,
                    evidence=[f"redirect: {data.get('target')} -> {url}" for url in chain]
                    + [f"final destination: {final}"],
                )
            )
        elif data.get("redirected"):
            result.add_finding(
                Finding(
                    key="http.redirected",
                    value=final,
                    confidence=Confidence.HIGH,
                    evidence=[f"redirected to {final}"],
                )
            )

    def _add_cookies(self, result: ScanResult, data: dict[str, Any]) -> None:
        cookies = data.get("cookies") or []
        for cookie in cookies:
            result.add_finding(
                Finding(
                    key="http.cookie",
                    value=cookie.get("name"),
                    confidence=Confidence.HIGH,
                    evidence=[f"Set-Cookie: {cookie.get('attrs', '')[:200]}"],
                )
            )

    def _add_security_headers(self, result: ScanResult, data: dict[str, Any]) -> None:
        headers = data.get("headers", {})
        spec = load_signatures("security_headers")
        for entry in spec.get("headers", []):
            name = entry["name"]
            present = name.lower() in headers
            if present:
                result.add_finding(
                    Finding(
                        key=f"http.security.{entry['label'].lower().replace(' ', '_')}",
                        value="present",
                        confidence=Confidence.HIGH,
                        evidence=[f"{name}: {headers[name.lower()][:120]}"],
                    )
                )
            else:
                result.add_finding(
                    Finding(
                        key=f"http.security_missing.{entry['label'].lower().replace(' ', '_')}",
                        value="missing",
                        confidence=Confidence.LOW,
                        evidence=[f"{name} header not present (informational)"],
                    )
                )

    # -- DNA -------------------------------------------------------------

    def _add_dna(self, result: ScanResult, data: dict[str, Any]) -> None:
        headers = data.get("headers", {})
        dna_source = {
            "status_class": str(data.get("status", ""))[:1] + "xx" if data.get("status") else "",
            "content_type": (data.get("content_type") or "").split(";")[0].strip().lower(),
            "header_set": header_fingerprint(headers),
            "redirected": bool(data.get("redirect_chain")),
            "cookies": sorted(c.get("name", "") for c in data.get("cookies", [])),
            "encoding": headers.get("content-encoding", ""),
            "markers": {h: ("yes" if h in headers else "no") for h in _DNA_HEADERS},
        }
        blob = json.dumps(dna_source, sort_keys=True).encode("utf-8")
        fingerprint = hashlib.sha256(blob).hexdigest()
        result.add_finding(
            Finding(
                key="http.dna",
                value=fingerprint,
                confidence=Confidence.MEDIUM,
                evidence=[
                    "HTTP behaviour fingerprint (stable over header presence, content type, "
                    "status class, cookies, compression)",
                    f"DNA: {fingerprint}",
                ],
            )
        )
        result.artifacts["http_dna"] = fingerprint
