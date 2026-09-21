"""Local file metadata analyzer (feature: metadata).

Extracts metadata from local files the user already possesses:

* images: EXIF (camera, timestamps, GPS), dimensions, format;
* generic: size, SHA-256/MD5, magic-byte type detection.

This is **offline by design**: it never fetches anything. It is meant for
digital-forensics workflows on artifacts the user has lawfully acquired.

EXIF is only available when Pillow is installed; without it we report file
level facts and clearly mark EXIF as unavailable rather than guessing.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vxrecon.analyzers.base import BaseAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.core.result import Confidence, Finding, ScanResult

try:  # optional
    from PIL import ExifTags, Image

    _HAS_PIL = True
except Exception:  # noqa: BLE001
    _HAS_PIL = False

# Magic bytes -> friendly type. Kept tiny and dependency-free.
_MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"RIFF", "RIFF container (WEBP/WAV/AVI)"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP container (docx/xlsx/zip)"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "PE/Windows executable"),
]

# GPS tag ids we surface when present.
_GPS_TAG = 34853


class MetadataAnalyzer(BaseAnalyzer):
    """Extract metadata and integrity hashes from a local file."""

    name = "metadata"
    requires_network = False

    def analyze(self, target: str, raw: dict[str, Any], ctx: RunContext) -> ScanResult:
        result = self._result(target)
        path = Path(target)
        if not path.exists() or not path.is_file():
            result.errors.append(f"file not found: {path}")
            return result
        try:
            data = path.read_bytes()
        except OSError as exc:
            result.errors.append(f"cannot read file: {exc}")
            return result

        self._add_file_facts(result, path, data)
        self._add_magic(result, data)
        if _HAS_PIL:
            self._add_image_metadata(result, data)
        else:
            result.add_finding(
                Finding(
                    key="metadata.exif_unavailable",
                    value=True,
                    confidence=Confidence.LOW,
                    evidence=["Pillow not installed; EXIF/image parsing skipped"],
                )
            )
        return result

    def _add_file_facts(self, result: ScanResult, path: Path, data: bytes) -> None:
        stat = path.stat()
        result.add_finding(
            Finding(
                key="metadata.size",
                value=stat.st_size,
                confidence=Confidence.HIGH,
                evidence=[f"file size: {stat.st_size} bytes"],
            )
        )
        result.add_finding(
            Finding(
                key="metadata.sha256",
                value=hashlib.sha256(data).hexdigest(),
                confidence=Confidence.HIGH,
                evidence=["SHA-256 of file contents"],
            )
        )
        result.add_finding(
            Finding(
                key="metadata.md5",
                value=hashlib.md5(data).hexdigest(),  # noqa: S324
                confidence=Confidence.HIGH,
                evidence=["MD5 of file contents (integrity/legacy matching)"],
            )
        )
        result.add_finding(
            Finding(
                key="metadata.modified",
                value=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                confidence=Confidence.HIGH,
                evidence=["filesystem modified time"],
            )
        )

    def _add_magic(self, result: ScanResult, data: bytes) -> None:
        for magic, label in _MAGIC:
            if data.startswith(magic):
                result.add_finding(
                    Finding(
                        key="metadata.type",
                        value=label,
                        confidence=Confidence.HIGH,
                        evidence=[f"magic bytes indicate: {label}"],
                    )
                )
                return

    def _add_image_metadata(self, result: ScanResult, data: bytes) -> None:
        import io

        try:
            with Image.open(io.BytesIO(data)) as img:
                result.add_finding(
                    Finding(
                        key="metadata.image",
                        value={"format": img.format, "size": f"{img.size[0]}x{img.size[1]}", "mode": img.mode},
                        confidence=Confidence.HIGH,
                        evidence=[f"image {img.format} {img.size[0]}x{img.size[1]} {img.mode}"],
                    )
                )
                exif = img.getexif()
                if not exif:
                    return
                for tag_id, value in exif.items():
                    name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if name == "GPSInfo":
                        gps = _decode_gps(value)
                        if gps:
                            result.add_finding(
                                Finding(
                                    key="metadata.gps",
                                    value=gps,
                                    confidence=Confidence.MEDIUM,
                                    evidence=[f"GPS metadata present: {gps}"],
                                )
                            )
                        continue
                    if isinstance(value, bytes):
                        continue
                    result.add_finding(
                        Finding(
                            key=f"metadata.exif.{name}",
                            value=str(value)[:200],
                            confidence=Confidence.MEDIUM,
                            evidence=[f"EXIF {name}: {str(value)[:120]}"],
                        )
                    )
        except Exception as exc:  # noqa: BLE001 - corrupt image
            result.errors.append(f"image parse failed: {exc}")


def _decode_gps(gps_info: dict) -> str | None:
    try:
        def to_deg(value, ref) -> float:
            d, m, s = value
            deg = float(d) + float(m) / 60 + float(s) / 3600
            if ref in ("S", "W"):
                deg = -deg
            return deg

        lat = to_deg(gps_info.get(2), gps_info.get(1))
        lon = to_deg(gps_info.get(4), gps_info.get(3))
        return f"{lat:.5f}, {lon:.5f}"
    except Exception:  # noqa: BLE001
        return None
