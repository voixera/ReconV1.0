"""Signature loading helpers.

Signature files live in ``vxrecon/signatures/*.json`` and are loaded and cached
at import time. They are plain data: technology fingerprints, security header
expectations and small provider hint tables. Keeping them as JSON means the
community can extend detections without touching Python code.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_SIGNATURES_DIR = Path(__file__).parent


@lru_cache(maxsize=None)
def load_signatures(name: str) -> dict[str, Any]:
    """Load and cache a signature file by base name (no extension).

    Returns an empty dict if the file is missing or malformed, so callers can
    degrade gracefully rather than crash.
    """

    path = _SIGNATURES_DIR / f"{name}.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}


def technologies() -> list[dict[str, Any]]:
    return list(load_signatures("technologies").get("technologies", []))
