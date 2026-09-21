"""Tests for Phase 5: image fingerprinting and metadata analysis (offline)."""

from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

from vxrecon.analyzers.favicon_analyzer import FaviconAnalyzer
from vxrecon.analyzers.metadata_analyzer import MetadataAnalyzer
from vxrecon.core.context import RunContext
from vxrecon.utils.image_fingerprint import (
    fingerprint_image,
    hamming_distance,
    perceptual_similarity,
)


def _tiny_png() -> bytes:
    """Build a valid 1x1 PNG without external deps."""

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw = b"\x00\xff\x00\x00"  # one scanline, filter byte + RGB
    idat = zlib.compress(raw)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def test_fingerprint_image_crypto_hashes() -> None:
    data = _tiny_png()
    fp = fingerprint_image(data)
    assert fp.sha256 == hashlib.sha256(data).hexdigest()
    assert fp.md5 == hashlib.md5(data).hexdigest()
    assert fp.size == len(data)


def test_fingerprint_image_reads_dimensions() -> None:
    fp = fingerprint_image(_tiny_png())
    # Dimensions require Pillow; if absent, they are None (never guessed).
    if fp.format is not None:
        assert fp.width == 1 and fp.height == 1


def test_hamming_distance() -> None:
    assert hamming_distance("00", "00") == 0
    assert hamming_distance("00", "ff") == 8
    assert hamming_distance("0", "0000") is None


def test_perceptual_similarity_identical() -> None:
    assert perceptual_similarity("deadbeef", "deadbeef") == 1.0


def test_favicon_analyzer_emits_fingerprints() -> None:
    ctx = RunContext(quiet=True)
    raw = {
        "favicon": {
            "favicon": {
                "source_url": "https://example.com/favicon.ico",
                "status": 200,
                "content_type": "image/png",
                "bytes": _tiny_png(),
                "size": len(_tiny_png()),
            }
        }
    }
    result = FaviconAnalyzer(ctx).analyze("example.com", raw, ctx)
    keys = {f.key for f in result.findings}
    assert "favicon.sha256" in keys
    assert "favicon.md5" in keys
    # Evidence integrity is attached.
    sha = next(f for f in result.findings if f.key == "favicon.sha256")
    assert sha.evidence_ref is not None
    assert sha.evidence_ref.sha256


def test_favicon_analyzer_handles_missing() -> None:
    ctx = RunContext(quiet=True)
    result = FaviconAnalyzer(ctx).analyze("x", {"favicon": {"favicon": None}}, ctx)
    assert any(f.key == "favicon.present" for f in result.findings)


def test_metadata_analyzer_local_file(tmp_path: Path) -> None:
    path = tmp_path / "sample.png"
    path.write_bytes(_tiny_png())
    ctx = RunContext(quiet=True)
    result = MetadataAnalyzer(ctx).analyze(str(path), {}, ctx)
    keys = {f.key for f in result.findings}
    assert "metadata.size" in keys
    assert "metadata.sha256" in keys
    assert "metadata.type" in keys


def test_metadata_analyzer_detects_magic_pdf(tmp_path: Path) -> None:
    path = tmp_path / "doc.pdf"
    path.write_bytes(b"%PDF-1.7\n...")
    ctx = RunContext(quiet=True)
    result = MetadataAnalyzer(ctx).analyze(str(path), {}, ctx)
    type_finding = next(f for f in result.findings if f.key == "metadata.type")
    assert "PDF" in type_finding.value


def test_metadata_analyzer_missing_file(tmp_path: Path) -> None:
    ctx = RunContext(quiet=True)
    result = MetadataAnalyzer(ctx).analyze(str(tmp_path / "nope.bin"), {}, ctx)
    assert result.errors
