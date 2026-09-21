"""Subdomain analyzer.

Turns Certificate Transparency collector output into findings and a structured
subdomain list. Pure function: no network access.

Each discovered name is reported at MEDIUM confidence because CT data reflects
*historical* issuance and may include names that no longer resolve. The source
and certificate IDs are preserved as evidence.
"""

from __future__ import annotations

from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult


class SubdomainAnalyzer(BaseAnalyzer):
    """Derive subdomain findings from CT data."""

    name = "subdomains"
    consumes = ("ct",)

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        data = raw.get("ct")
        if not data:
            result.errors.append("no CT data collected")
            return result
        if data.get("_error"):
            # A CT outage (crt.sh is frequently overloaded) is an *availability*
            # condition, not a scan failure. Report it as an informational
            # finding so the overall scan stays OK.
            result.add_finding(
                Finding(
                    key="subdomains.unavailable",
                    value=str(data["_error"]),
                    confidence=Confidence.LOW,
                    evidence=[f"certificate transparency unavailable: {data['_error']}"],
                )
            )
            return result

        subdomains = data.get("subdomains", [])
        result.artifacts["subdomains"] = [s["name"] for s in subdomains]

        if not subdomains:
            result.add_finding(
                Finding(
                    key="subdomains.count",
                    value=0,
                    confidence=Confidence.LOW,
                    evidence=["no names found in public CT logs for this domain"],
                )
            )
            return result

        result.add_finding(
            Finding(
                key="subdomains.count",
                value=len(subdomains),
                confidence=Confidence.HIGH,
                evidence=[
                    f"{len(subdomains)} name(s) from Certificate Transparency",
                    f"source: {data.get('source', 'ct')}",
                ],
            )
        )

        for entry in subdomains:
            cert_ids = entry.get("cert_ids", [])
            result.add_finding(
                Finding(
                    key="subdomains.name",
                    value=entry["name"],
                    confidence=Confidence.MEDIUM,
                    evidence=[
                        f"seen in CT (crt.sh) under certificate id(s): "
                        f"{', '.join(str(c) for c in cert_ids[:5]) or 'n/a'}"
                    ],
                )
            )
        return result
