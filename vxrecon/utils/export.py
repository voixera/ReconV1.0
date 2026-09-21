"""Data export helpers: CSV and JSON serialization for database contents.

Kept dependency-free. CSV uses the stdlib ``csv`` module and always writes a
header row. Values are coerced to strings so mixed types never break export.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any


def to_csv(rows: list[dict[str, Any]], columns: list[str] | None = None) -> str:
    """Serialize a list of dicts to CSV text (with a header row)."""

    if not rows:
        return ""
    columns = columns or list(rows[0].keys())
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({c: _coerce(row.get(c)) for c in columns})
    return buffer.getvalue()


def to_json(data: Any, indent: int = 2) -> str:
    return json.dumps(data, indent=indent, default=str)


def write_export(
    out_dir: Path, basename: str, rows: list[dict[str, Any]], fmt: str = "json"
) -> Path:
    """Write ``rows`` to ``out_dir/basename.<fmt>`` and return the path."""

    out_dir.mkdir(parents=True, exist_ok=True)
    if fmt == "csv":
        path = out_dir / f"{basename}.csv"
        path.write_text(to_csv(rows), encoding="utf-8")
    else:
        path = out_dir / f"{basename}.json"
        path.write_text(to_json(rows), encoding="utf-8")
    return path


def _coerce(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    if value is None:
        return ""
    return str(value)
