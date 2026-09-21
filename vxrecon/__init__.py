"""VXRecon - Advanced Passive OSINT & Digital Footprint Intelligence Framework.

Privacy-first, API-key free, passive by default. This package exposes the
public library surface used by the CLI and by third-party integrations.

The project is intentionally split into layers:

* ``core``        - orchestration, context, registry, pipeline, results.
* ``collectors``  - the ONLY layer permitted to perform network I/O.
* ``analyzers``   - pure functions that turn raw facts into evidence findings.
* ``correlators`` - pure functions that relate findings into graphs.
* ``database``    - local SQLite intelligence store.
* ``reporters``   - terminal / JSON / HTML rendering.
* ``ui``          - CLI parsing, banner, menu, progress, tables.
* ``utils``       - small, dependency-light helpers.
"""

from __future__ import annotations

__all__ = ["__version__", "__program__", "__url__"]

__program__ = "VXRecon"
__version__ = "1.0.0"
__url__ = "https://github.com/vxrecon/vxrecon"

# Default user agent used by every network request. It must always clearly
# identify the tool and provide a contact/documentation URL as required by
# common-sense responsible disclosure and RFC 7231 conventions.
DEFAULT_USER_AGENT = f"{__program__}/{__version__} (+{__url__})"
