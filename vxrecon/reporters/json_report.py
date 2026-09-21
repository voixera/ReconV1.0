"""JSON reporter and report file writing.

Produces the canonical machine-readable representation and persists
``report.json`` under the target's report directory (unless ``--no-save``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vxrecon.core.context import RunContext
from vxrecon.reporters.base import BaseReporter


class JsonReporter(BaseReporter):
    """Serialize a scan payload to canonical JSON."""

    name = "json"

    def render(self, data: dict[str, Any]) -> str:
        return json.dumps(data, indent=2, default=str, sort_keys=False)


def report_dir(ctx: RunContext, target: str) -> Path:
    """Return (and create) the report directory for a target."""

    safe = target.replace("/", "_").replace(":", "_")
    path = ctx.reports_dir / safe
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json_report(ctx: RunContext, target: str, data: dict[str, Any]) -> Path | None:
    """Write ``report.json`` for a target. Returns the path, or None if
    ``--no-save`` is set."""

    if ctx.no_save:
        return None
    directory = report_dir(ctx, target)
    out = directory / "report.json"
    out.write_text(
        json.dumps(data, indent=2, default=str), encoding="utf-8"
    )
    return out
