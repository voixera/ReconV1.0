"""Tests for target validators (offline, pure)."""

from __future__ import annotations

import pytest

from vxrecon.utils.validators import (
    classify_target,
    host_from_target,
    is_domain,
    is_ip,
    is_url,
    normalize_url,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", True),
        ("sub.example.co.uk", True),
        ("xn--d1acufc.xn--p1ai", True),
        ("-bad.com", False),
        ("bad-.com", False),
        ("no_tld", False),
        ("", False),
        ("a" * 300 + ".com", False),
    ],
)
def test_is_domain(value: str, expected: bool) -> None:
    assert is_domain(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [("1.1.1.1", True), ("2606:4700::1111", True), ("999.1.1.1", False), ("example.com", False)],
)
def test_is_ip(value: str, expected: bool) -> None:
    assert is_ip(value) is expected


def test_is_url() -> None:
    assert is_url("https://example.com/path")
    assert is_url("http://example.com")
    assert not is_url("ftp://example.com")
    assert not is_url("example.com")


def test_normalize_url() -> None:
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("http://example.com") == "http://example.com"


def test_host_from_target() -> None:
    assert host_from_target("https://example.com/x") == "example.com"
    assert host_from_target("example.com") == "example.com"


@pytest.mark.parametrize(
    "value,kind",
    [
        ("https://example.com", "url"),
        ("example.com", "domain"),
        ("1.1.1.1", "ip"),
        ("user@example.com", "email"),
        ("!!!", "unknown"),
    ],
)
def test_classify_target(value: str, kind: str) -> None:
    assert classify_target(value) == kind
