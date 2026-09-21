"""Tests for offline enforcement in the network gateway.

The most important guarantee in VXRecon: when ``--offline`` is set, the single
network gateway must refuse to make requests.
"""

from __future__ import annotations

import pytest

from vxrecon.core.context import RunContext
from vxrecon.core.errors import NetworkDisabledError
from vxrecon.utils.net import http_get


def test_offline_blocks_http_get() -> None:
    ctx = RunContext(offline=True, quiet=True)
    with pytest.raises(NetworkDisabledError):
        http_get("https://example.com", ctx)


def test_bad_scheme_rejected_without_network() -> None:
    ctx = RunContext(offline=False, quiet=True)
    result = http_get("ftp://example.com", ctx)
    assert result.ok is False
    assert "scheme" in (result.error or "").lower()
