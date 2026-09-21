"""RDAP / IP analyzer.

Turns RDAP registration and network data into findings: registrar, creation/
expiry events, nameservers, RIR network, country and ASN. Pure function.

Note on terminology: RDAP gives registration *facts*, not ownership proof. We
report exactly what the registry publishes.
"""

from __future__ import annotations

from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult

# RDAP event actions we surface with friendly labels.
_EVENT_LABELS = {
    "registration": "registered",
    "expiration": "expires",
    "last changed": "last changed",
    "last update of RDAP database": "rdap updated",
}


class RdapAnalyzer(BaseAnalyzer):
    """Derive findings from RDAP registration and network data."""

    name = "rdap"
    consumes = ("rdap",)

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        data = raw.get("rdap")
        if not data:
            result.errors.append("no RDAP data collected")
            return result

        registration = data.get("registration")
        if registration and not registration.get("_error"):
            self._add_registration(result, registration)

        network = data.get("network")
        if network and not network.get("_error"):
            self._add_network(result, network)

        # RIR/registry endpoints are occasionally unreachable or lack a
        # bootstrap entry. Treat that as an availability note (informational)
        # rather than a scan failure, since RDAP is best-effort.
        for section in (registration, network):
            if section and section.get("_error"):
                result.add_finding(
                    Finding(
                        key="rdap.unavailable",
                        value=str(section["_error"]),
                        confidence=Confidence.LOW,
                        evidence=[f"RDAP unavailable: {section['_error']}"],
                    )
                )
        return result

    # -- registration ----------------------------------------------------

    def _add_registration(self, result: ScanResult, reg: dict[str, Any]) -> None:
        if reg.get("registrar"):
            result.add_finding(
                Finding(
                    key="rdap.registrar",
                    value=reg["registrar"],
                    confidence=Confidence.HIGH,
                    evidence=[f"registrar: {reg['registrar']}"],
                )
            )
        events = reg.get("events", {})
        for action, date in events.items():
            if not date:
                continue
            label = _EVENT_LABELS.get(action, action)
            result.add_finding(
                Finding(
                    key=f"rdap.event.{action}",
                    value=date,
                    confidence=Confidence.HIGH,
                    evidence=[f"{label}: {date}"],
                )
            )
        for ns in reg.get("nameservers", []):
            result.add_finding(
                Finding(
                    key="rdap.nameserver",
                    value=ns,
                    confidence=Confidence.HIGH,
                    evidence=[f"nameserver (RDAP): {ns}"],
                )
            )
        for status in reg.get("status", []):
            result.add_finding(
                Finding(
                    key="rdap.status",
                    value=status,
                    confidence=Confidence.MEDIUM,
                    evidence=[f"EPP status: {status}"],
                )
            )

    # -- network ---------------------------------------------------------

    def _add_network(self, result: ScanResult, net: dict[str, Any]) -> None:
        if net.get("asn"):
            result.add_finding(
                Finding(
                    key="net.asn",
                    value=net["asn"],
                    confidence=Confidence.MEDIUM,
                    evidence=[f"ASN (RDAP): {net['asn']}"],
                )
            )
        if net.get("name"):
            result.add_finding(
                Finding(
                    key="net.name",
                    value=net["name"],
                    confidence=Confidence.HIGH,
                    evidence=[f"network name: {net['name']}"],
                )
            )
        if net.get("country"):
            result.add_finding(
                Finding(
                    key="net.country",
                    value=net["country"],
                    confidence=Confidence.MEDIUM,
                    evidence=[f"country: {net['country']}"],
                )
            )
        if net.get("startAddress"):
            result.add_finding(
                Finding(
                    key="net.range",
                    value=f"{net.get('startAddress')} - {net.get('endAddress')}",
                    confidence=Confidence.HIGH,
                    evidence=[
                        f"network range {net.get('startAddress')} - {net.get('endAddress')}"
                    ],
                )
            )
