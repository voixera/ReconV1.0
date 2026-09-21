"""The single network gateway.

Every outbound request in VXRecon goes through :func:`http_get`. This module:

* refuses to touch the network when ``ctx.offline`` is set,
* applies a mandatory timeout,
* sends an honest, identifiable User-Agent,
* respects the per-host rate limiter,
* never follows redirects into a different scheme without re-checking,
* returns a structured result instead of raising for expected failures.

No other module is permitted to open sockets directly. This is what makes
``--offline`` and the "no hidden network calls" guarantee enforceable.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from vxrecon.core.context import RunContext
from vxrecon.core.errors import NetworkDisabledError
from vxrecon.core.rate_limit import RateLimiter

# A shared limiter is fine for a single-process CLI run.
_LIMITER: RateLimiter | None = None
_LIMITER_RATE: float | None = None


@dataclass
class HttpResult:
    """Structured outcome of an HTTP GET."""

    url: str
    ok: bool = False
    status: int | None = None
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    final_url: str | None = None
    error: str | None = None
    elapsed_ms: int = 0
    content_type: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    http_version: str | None = None

    @property
    def text(self) -> str:
        """Best-effort decoded body (never raises on bad bytes)."""

        charset = "utf-8"
        if self.content_type and "charset=" in self.content_type:
            charset = self.content_type.split("charset=", 1)[1].split(";")[0].strip()
        try:
            return self.body.decode(charset, errors="replace")
        except (LookupError, TypeError):
            return self.body.decode("utf-8", errors="replace")

    def acquired_at(self) -> str:
        return datetime.now(timezone.utc).isoformat()


def _limiter_for(rate_rps: float) -> RateLimiter:
    global _LIMITER, _LIMITER_RATE
    if _LIMITER is None or _LIMITER_RATE != rate_rps:
        _LIMITER = RateLimiter(rate_rps=rate_rps)
        _LIMITER_RATE = rate_rps
    return _LIMITER


def _build_context(ctx: RunContext, insecure: bool = True) -> ssl.SSLContext:
    """Build an SSL context.

    ``insecure=True`` (default for reconnaissance) means we inspect certificates
    even when they are expired/self-signed, which is normal for passive recon
    and never weakens the *target*. We are reading public data only.
    """

    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context = ssl.create_default_context()
    return context


def http_get(
    url: str,
    ctx: RunContext,
    *,
    max_bytes: int = 2_000_000,
    headers: dict[str, str] | None = None,
    allow_redirects: bool = True,
    insecure: bool = True,
) -> HttpResult:
    """Perform a single rate-limited HTTP GET and return a :class:`HttpResult`.

    Raises
    ------
    NetworkDisabledError
        If ``ctx.offline`` is set. This is a *policy* violation, not a network
        failure, so it is intentionally loud.
    """

    if ctx.offline:
        raise NetworkDisabledError(
            f"refused network request to {url} (offline mode is enabled)"
        )
    if not url.lower().startswith(("http://", "https://")):
        return HttpResult(url=url, ok=False, error="unsupported URL scheme")

    host = urlparse(url).hostname or "default"
    _limiter_for(ctx.rate_rps).acquire(host)

    request_headers = {"User-Agent": ctx.user_agent, "Accept": "*/*"}
    if headers:
        request_headers.update(headers)

    request = urllib.request.Request(url, headers=request_headers, method="GET")
    import time

    start = time.perf_counter()
    result = HttpResult(url=url)

    # Always disable urllib's automatic redirects; we follow manually so we can
    # record the chain and rate-limit each hop.
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # noqa: D401
            return None

    https_handler = urllib.request.HTTPSHandler(context=_build_context(ctx, insecure))
    opener = urllib.request.build_opener(_NoRedirect(), https_handler)

    current = url
    seen = 0
    max_hops = 5
    while True:
        hop_request = urllib.request.Request(
            current, headers=request_headers, method="GET"
        )
        try:
            with opener.open(hop_request, timeout=ctx.timeout) as response:
                result.status = response.status
                result.reason = response.reason
                result.headers = {k: v for k, v in response.headers.items()}
                result.content_type = response.headers.get("Content-Type")
                result.body = response.read(max_bytes)
                result.final_url = response.geturl()
                result.ok = 200 <= response.status < 400
                result.http_version = _http_version(response)
                break
        except urllib.error.HTTPError as exc:
            # A 3xx that urllib surfaced as an HTTPError (redirect disallowed).
            location = exc.headers.get("Location") if exc.headers else None
            if (
                location
                and allow_redirects
                and 300 <= exc.code < 400
                and seen < max_hops
            ):
                seen += 1
                current = urllib.parse.urljoin(current, location)
                result.redirect_chain.append(current)
                host = urlparse(current).hostname or "default"
                _limiter_for(ctx.rate_rps).acquire(host)
                continue
            result.status = exc.code
            result.reason = exc.reason
            result.headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
            result.content_type = exc.headers.get("Content-Type") if exc.headers else None
            result.error = f"HTTP {exc.code}"
            result.ok = False
            break
        except urllib.error.URLError as exc:
            result.error = f"network error: {exc.reason}"
            break
        except (ssl.SSLError, ValueError) as exc:
            result.error = f"tls/url error: {exc}"
            break
        except Exception as exc:  # noqa: BLE001 - gateway must never propagate
            result.error = f"unexpected error: {exc}"
            break

    result.elapsed_ms = int((time.perf_counter() - start) * 1000)
    return result


def _http_version(response: Any) -> str | None:
    """Best-effort extraction of the HTTP protocol version from a response."""

    version = getattr(response, "version", None)
    if version == 10:
        return "HTTP/1.0"
    if version == 11:
        return "HTTP/1.1"
    if version == 20:
        return "HTTP/2"
    return None
