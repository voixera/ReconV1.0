"""Exception taxonomy for VXRecon.

The core rule: *expected* operational failures (DNS miss, HTTP 403, TLS
handshake failure, timeout, malformed HTML) are NOT fatal. They are captured
and surfaced as structured errors so the pipeline can continue.

Only programming errors (ValueError, TypeError, ...) and truly unrecoverable
configuration problems should propagate to the top-level CLI handler.
"""

from __future__ import annotations


class VXReconError(Exception):
    """Base class for all VXRecon-specific errors."""


class ConfigError(VXReconError):
    """Raised for invalid configuration or conflicting CLI flags."""


class ValidationError(VXReconError):
    """Raised when a user supplied target/value is malformed."""


class NetworkDisabledError(VXReconError):
    """Raised when network access is attempted while ``--offline`` is set."""


class ModuleError(VXReconError):
    """A recoverable failure inside a collector/analyzer/correlator.

    Collectors should *generally* avoid raising this and instead return an
    ``_error`` key in their raw payload. It exists for cases where returning a
    value is impossible.
    """
