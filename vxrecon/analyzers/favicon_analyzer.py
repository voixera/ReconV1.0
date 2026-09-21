"""Favicon fingerprint analyzer (feature 4).

Turns fetched favicon bytes into a fingerprint finding with evidence integrity
(SHA-256, MD5, dimensions, format, perceptual hashes). The fingerprint can be
correlated with other artifacts later (feature 17).

We never claim two sites are owned by the same party based on a matching
favicon. A match is a **shared artifact indicator**.
"""

from __future__ import annotations

from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Evidence, Finding, ScanResult
from vxrecon.utils.image_fingerprint import fingerprint_image
from vxrecon.utils.timeutil import now_iso


class FaviconAnalyzer(BaseAnalyzer):
    """Fingerprint a fetched favicon or local image."""

    name = "favicon"
    consumes = ("favicon", "local_image")

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        source = raw.get("favicon") or raw.get("local_image")
        if not source:
            result.errors.append("no favicon/image collected")
            return result
        if source.get("_error"):
            result.errors.append(str(source["_error"]))
            return result

        icon = source.get("favicon") or source.get("image")
        if not icon or not icon.get("bytes"):
            result.add_finding(
                Finding(
                    key="favicon.present",
                    value=False,
                    confidence=Confidence.LOW,
                    evidence=[source.get("note", "no favicon/image found")],
                )
            )
            return result

        fp = fingerprint_image(icon["bytes"])
        evidence = Evidence(
            source_url=icon.get("source_url"),
            http_status=icon.get("status"),
            content_type=icon.get("content_type"),
            sha256=fp.sha256,
            bytes=fp.size,
            acquired_at=now_iso(),
        )

        result.add_finding(
            Finding(
                key="favicon.sha256",
                value=fp.sha256,
                confidence=Confidence.HIGH,
                evidence=[f"favicon SHA-256: {fp.sha256}", f"source: {icon.get('source_url')}"],
                evidence_ref=evidence,
            )
        )
        result.add_finding(
            Finding(
                key="favicon.md5",
                value=fp.md5,
                confidence=Confidence.HIGH,
                evidence=[f"favicon MD5: {fp.md5}"],
            )
        )
        if fp.width and fp.height:
            result.add_finding(
                Finding(
                    key="favicon.dimensions",
                    value=f"{fp.width}x{fp.height}",
                    confidence=Confidence.HIGH,
                    evidence=[f"image dimensions: {fp.width}x{fp.height} ({fp.format})"],
                )
            )
        if fp.ahash:
            result.add_finding(
                Finding(
                    key="favicon.ahash",
                    value=fp.ahash,
                    confidence=Confidence.MEDIUM,
                    evidence=["perceptual average hash (aHash) - similarity hint only"],
                )
            )
        if fp.dhash:
            result.add_finding(
                Finding(
                    key="favicon.dhash",
                    value=fp.dhash,
                    confidence=Confidence.MEDIUM,
                    evidence=["perceptual difference hash (dHash) - similarity hint only"],
                )
            )
        if fp.extra:
            result.artifacts["image_extra"] = fp.extra

        result.artifacts["favicon"] = fp.to_dict()
        return result
