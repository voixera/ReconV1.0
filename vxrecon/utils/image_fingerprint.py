"""Image fingerprint utilities.

Computes cryptographic hashes (SHA-256, MD5) and, when Pillow is available,
image dimensions, MIME type and perceptual hashes (aHash/dHash). Perceptual
hashes let us *suspect* that two icons look alike; they never prove identity.

Everything degrades gracefully: without Pillow we still return the crypto
hashes and mark perceptual fields as unavailable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

try:  # optional
    from PIL import Image
    import io as _io

    _HAS_PIL = True
except Exception:  # noqa: BLE001
    _HAS_PIL = False


@dataclass
class ImageFingerprint:
    """Fingerprint data for an image artifact."""

    sha256: str
    md5: str
    size: int
    width: int | None = None
    height: int | None = None
    format: str | None = None
    mode: str | None = None
    ahash: str | None = None
    dhash: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "md5": self.md5,
            "size": self.size,
            "width": self.width,
            "height": self.height,
            "format": self.format,
            "mode": self.mode,
            "ahash": self.ahash,
            "dhash": self.dhash,
            "extra": self.extra,
        }


def fingerprint_image(data: bytes) -> ImageFingerprint:
    """Compute hashes and (if possible) perceptual hashes for image bytes."""

    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()  # noqa: S324 - fingerprint convention only
    fp = ImageFingerprint(sha256=sha256, md5=md5, size=len(data))

    if not _HAS_PIL:
        fp.extra["perceptual_hash"] = "unavailable (Pillow not installed)"
        return fp

    try:
        with Image.open(_io.BytesIO(data)) as img:
            fp.width, fp.height = img.size
            fp.format = img.format
            fp.mode = img.mode
            fp.ahash = _average_hash(img)
            fp.dhash = _difference_hash(img)
    except Exception as exc:  # noqa: BLE001 - corrupt/unsupported image
        fp.extra["decode_error"] = str(exc)
    return fp


def _average_hash(img: Any, size: int = 8) -> str:
    """Average hash (aHash): 64-bit hex of a downscaled grayscale image."""

    small = img.convert("L").resize((size, size))
    pixels = list(small.getdata())
    avg = sum(pixels) / len(pixels)
    bits = "".join("1" if p > avg else "0" for p in pixels)
    return f"{int(bits, 2):0{size * size // 4}x}"


def _difference_hash(img: Any, size: int = 8) -> str:
    """Difference hash (dHash): compares adjacent pixels."""

    small = img.convert("L").resize((size + 1, size))
    pixels = list(small.getdata())
    bits: list[str] = []
    for row in range(size):
        for col in range(size):
            left = pixels[row * (size + 1) + col]
            right = pixels[row * (size + 1) + col + 1]
            bits.append("1" if left > right else "0")
    return f"{int(''.join(bits), 2):0{size * size // 4}x}"


def hamming_distance(hash_a: str, hash_b: str) -> int | None:
    """Hamming distance between two hex perceptual hashes.

    Returns ``None`` if the hashes are incompatible lengths.
    """

    if len(hash_a) != len(hash_b):
        return None
    try:
        a = int(hash_a, 16)
        b = int(hash_b, 16)
    except ValueError:
        return None
    return bin(a ^ b).count("1")


def perceptual_similarity(hash_a: str, hash_b: str) -> float | None:
    """Similarity in [0, 1] derived from Hamming distance (a *hint*, not proof)."""

    distance = hamming_distance(hash_a, hash_b)
    if distance is None:
        return None
    bits = len(hash_a) * 4
    return 1.0 - (distance / bits)


def pil_available() -> bool:
    return _HAS_PIL
