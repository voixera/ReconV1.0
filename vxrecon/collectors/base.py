"""Base class for collectors.

A collector performs I/O and returns *raw facts* as a plain dict. It must not
raise for expected operational failures (DNS miss, TLS error, HTTP 403); those
belong in the returned dict under an ``_error`` key, so the pipeline can keep
going and report the problem without aborting.

The only layer allowed to touch the network is the collector. Even here, all
HTTP must go through :func:`vxrecon.utils.net.http_get`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from vxrecon.core.context import RunContext


class BaseCollector(ABC):
    """Abstract base for all collectors."""

    #: Unique module name (matches the registry entry).
    name: str = "collector"
    #: Whether this collector requires network access.
    requires_network: bool = True
    #: Logical fact keys this collector emits (for diagnostics).
    provides: tuple[str, ...] = ()

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    @abstractmethod
    def collect(self, target: str) -> dict[str, Any]:
        """Collect raw facts for ``target``.

        Must not raise for expected failures. Return ``{"_error": "..."}`` or
        include an ``errors`` list instead.
        """

    def _error(self, message: str) -> dict[str, Any]:
        """Helper to build a structured error payload."""

        return {"_error": message, "target": None}
