"""HTTP header and cookie parsing helpers."""

from __future__ import annotations

from http.cookies import SimpleCookie


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return headers with lowercase keys (values preserved)."""

    out: dict[str, str] = {}
    for key, value in headers.items():
        out[key.lower()] = value
    return out


def parse_cookies(set_cookie_values: list[str]) -> list[dict[str, str]]:
    """Parse ``Set-Cookie`` header values into structured records.

    Returns a list of ``{"name", "value", "attrs"}``. Never raises.
    """

    cookies: list[dict[str, str]] = []
    for raw in set_cookie_values:
        try:
            jar = SimpleCookie()
            jar.load(raw)
            for name, morsel in jar.items():
                cookies.append(
                    {
                        "name": name,
                        "value": morsel.value,
                        "attrs": morsel.OutputString(),
                    }
                )
        except Exception:  # noqa: BLE001
            continue
    return cookies


def header_fingerprint(headers: dict[str, str]) -> str:
    """Return a stable, coarse fingerprint of response headers.

    Only the *presence and names* of headers are used (sorted), so the
    fingerprint is insensitive to volatile values like dates or tokens.
    """

    keys = sorted({k.lower() for k in headers})
    return "|".join(keys)
