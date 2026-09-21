"""Structured logging with a UI-aware sink.

VXRecon never uses ``print`` for diagnostics. All output goes through either:

* the :class:`~vxrecon.ui.progress.UIReporter` (for human-facing progress), or
* this logger (for diagnostics / ``--verbose`` / ``--json``).

The logger is intentionally tiny: it wraps the stdlib ``logging`` module and
adds a ``silent`` level for ``--quiet`` and structured ``event()`` calls that
feed the investigation timeline.
"""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "vxrecon"

_LEVELS = {
    0: logging.WARNING,
    1: logging.INFO,
    2: logging.DEBUG,
}


def configure(quiet: bool = False, verbose: int = 0) -> logging.Logger:
    """Configure and return the shared VXRecon logger.

    ``quiet`` silences everything below WARNING. ``verbose`` raises the
    threshold: 0 -> WARNING, 1 -> INFO, 2+ -> DEBUG.
    """

    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()
    logger.propagate = False

    if quiet:
        level = logging.ERROR
    else:
        level = _LEVELS.get(min(verbose, 2), logging.DEBUG)
    logger.setLevel(level)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
    logger.addHandler(handler)
    return logger


def get_logger() -> logging.Logger:
    """Return the shared logger, configuring a sane default if needed."""

    logger = logging.getLogger(LOGGER_NAME)
    if not logger.handlers:
        return configure()
    return logger
