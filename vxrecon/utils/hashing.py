"""Hashing helpers used for fingerprints and evidence integrity."""

from __future__ import annotations

import hashlib


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_bytes(data: bytes) -> str:
    # MD5 is used ONLY as a favicon-fingerprint convention (feature 4) and for
    # matching legacy datasets. It is never used for security decisions.
    return hashlib.md5(data).hexdigest()  # noqa: S324


def short(fingerprint: str, length: int = 16) -> str:
    """Return a shortened fingerprint for compact display."""

    return fingerprint[:length]
